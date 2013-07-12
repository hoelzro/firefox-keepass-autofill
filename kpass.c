/*
    libkpass, a library for reading and writing KeePass format files
    Copyright (C) 2009 Brian De Wolf

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define PACKAGE "kpass"

#include <stdlib.h>
#include <string.h>
#include <nettle/aes.h>
#include <nettle/sha.h>
#include <nettle/cbc.h>
#include <byteswap.h>
#include <time.h>

#include <libintl.h>
#define _(String) dgettext (PACKAGE, String)

#include "kpass.h"

/*
 *
 *
 * Internal structures that don't seem useful enough to expose 
 *
 *
 */

/* [DBHDR][GROUPINFO][GROUPINFO][GROUPINFO]...[ENTRYINFO][ENTRYINFO][ENTRYINFO]... */

/* Bytes for signature that are constant */
uint8_t kpass_signature[] = { 0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5 };
#define kpass_signature_len 8

/* kpass_group */

/* [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
 * [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...
 */

/* Required lengths for group types, indexed by type above. -1 indicates no limit. */
static int kpass_group_type_len[] = {
	-1,
	4,
	-1,
	5,
	5,
	5,
	5,
	4,
	2,
	4 };


/*
int kpass_group_fixed_len = 4 + 4 + 5 + 5 + 5 + 5 + 2 + 4;
*/
#define kpass_group_fixed_len 34

/* kpass_entry */

/* [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
 * [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...
 */

/* Required lengths for entry types, indexed by type above. -1 indicates no limit. */
static int kpass_entry_type_len[] = {
	-1,
	16,
	4,
	4,
	-1,
	-1,
	-1,
	-1,
	-1,
	5,
	5,
	5,
	5,
	-1,
	-1 };

/*
int kpass_entry_fixed_len = 16 + 4 + 4 + 5 + 5 + 5 + 5;
*/
#define kpass_entry_fixed_len 44

/*
 *
 *
 * Internal Function Prototypes
 *
 *
 */

/* kpass_prepare_key - Internal function for the extra steps of producing the
 * database key.  */
static void		kpass_prepare_key(const kpass_db *db, uint8_t *pw_hash);

/* decrypting helpers */
static kpass_retval	kpass_decrypt_data(kpass_db *db, const uint8_t *pw_hash, uint8_t * data, int * data_len);
static kpass_retval	kpass_load_decrypted_data(kpass_db *db, const uint8_t *data, const int data_len);

/* encrypting helpers */
static kpass_retval	kpass_encrypt_data(kpass_db *db, const uint8_t *pw_hash, uint8_t * data, int len, int pack_len);
static kpass_retval	kpass_pack_db(const kpass_db *db, uint8_t *buff, int len);
static void		kpass_write_header(const kpass_db *db, uint8_t * buf);
static int		kpass_db_packed_len(const kpass_db *db);
static int		kpass_group_packed_len(const kpass_group *group);
static int		kpass_entry_packed_len(const kpass_entry *entry);

/* internal bswap functions */
static uint32_t	kpass_htoll(uint32_t x);
static uint16_t	kpass_htols(uint16_t x);

/*
 *
 *
 * Functions
 *
 *
 */

char *kpass_strerror(kpass_retval retval) {
#if ENABLE_NLS
	static int init = 0;
	if(!init) {
		bindtextdomain (PACKAGE, LOCALEDIR);
		init = 1;
	}
#endif
	switch(retval) {
		case kpass_success:
			return _("The operation was successful.");
		case kpass_decrypt_data_fail:
			return _("Database corrupt or bad password given.");
		case kpass_load_decrypted_data_entry_fail:
			return _("Failed parsing corrupted entry.");
		case kpass_load_decrypted_data_group_fail:
			return _("Failed parsing corrupted group.");
		case kpass_init_db_short:
			return _("Given data too short to contain database.");
		case kpass_init_db_signature:
			return _("Signature doesn't match known value.");
		case kpass_pack_db_fail:
			return _("Packing database for encryption failed.");
		case kpass_unsupported_flag:
			return _("Database contains unsupported database flag.");
		default:
			return _("Unrecognized return value.");
	}
}

static kpass_retval kpass_decrypt_data(kpass_db *db, const uint8_t *pw_hash, uint8_t * data, int * data_len) {
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) aes_ctx;
	struct sha256_ctx sha256_ctx;
	uint8_t hash[32];

	if(db->flags != (kpass_flag_RIJNDAEL | kpass_flag_SHA2))
		return kpass_unsupported_flag;

	memcpy(hash, pw_hash, 32);
	kpass_prepare_key(db, hash);

	aes_set_decrypt_key(&aes_ctx.ctx, AES_KEY_SIZE, hash);
	CBC_SET_IV(&aes_ctx, db->encryption_init_vector);
	CBC_DECRYPT(&aes_ctx, aes_decrypt, *data_len, data, data);

	/* Really hokey PKCS7 padding */
	*data_len = *data_len - data[*data_len - 1];

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, *data_len, data);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, hash);

	if(memcmp(hash, db->contents_hash, 32))
		return kpass_decrypt_data_fail;

	return kpass_success;
}

kpass_retval kpass_decrypt_db(kpass_db *db, const uint8_t *pw_hash) {
	uint8_t *buf;
	int len = db->encrypted_data_len;
	kpass_retval retval = kpass_success;

	buf = malloc(len);
	memcpy(buf, db->encrypted_data, len);

	retval = kpass_decrypt_data(db, pw_hash, buf, &len);
	/* skip second operation if first failed */
	if(!retval)
		retval = kpass_load_decrypted_data(db, buf, len);

	memset(buf, 0, db->encrypted_data_len);
	free(buf);
	return retval;
}

void kpass_hash_pw(const char *pw, uint8_t *pw_hash) {
	struct sha256_ctx sha256_ctx;
	
	/* First, SHA256 the password.  This has been pulled out so it can be
	 * done separately so the calling program can hold onto the hash for
	 * encryption rather than the plain text which is gross!!! */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, strlen(pw), (uint8_t*) pw);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);
}

void kpass_hash_pw_keyfile(const char *pw, const uint8_t *data, const int len, uint8_t *pw_hash) {
	struct sha256_ctx sha256_ctx;
	uint8_t keyfile_hash[32], justpw_hash[32];

	/* Hash the password */
	kpass_hash_pw(pw, justpw_hash);

	/* Hash the file contents */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, len, data);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, keyfile_hash);

	/* Now hash password+file hash */
	sha256_update(&sha256_ctx, SHA256_DIGEST_SIZE, justpw_hash);
	sha256_update(&sha256_ctx, SHA256_DIGEST_SIZE, keyfile_hash);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);
}


static void kpass_prepare_key(const kpass_db *db, uint8_t *pw_hash) {
	struct sha256_ctx sha256_ctx;
	struct aes_ctx aes_ctx;
	int x;

	/* Now we hammer it with AES a specified ridiculous number of times */
	aes_set_encrypt_key(&aes_ctx, AES_KEY_SIZE, db->master_seed_extra);

	for(x = 0; x < db->key_rounds; x++) {
		aes_encrypt(&aes_ctx, SHA256_DIGEST_SIZE, pw_hash, pw_hash);
	}

	/* Now we SHA256 the result from the AES hammering */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);

	/* Now we SHA256 that result with the salt */
	sha256_update(&sha256_ctx, 16, db->master_seed);
	sha256_update(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, pw_hash);
}


static kpass_retval kpass_load_decrypted_data(kpass_db *db, const uint8_t *data, const int data_len) {
	int read_groups = 0, read_entries = 0, read = 0, type, size, x;
	kpass_retval retval = kpass_success;
	kpass_group *group = NULL;
	kpass_entry *entry = NULL;

	db->groups = malloc(sizeof(*group) * db->groups_len);
	memset(db->groups, 0, sizeof(*group) * db->groups_len);

	/* Let's fill in all of the groups... */

	while(read < data_len && read_groups < db->groups_len) {
		if(!group) {
			group = malloc(sizeof(kpass_group));
			memset(group, 0, sizeof(kpass_group));
		}

		type = kpass_htols(*(uint16_t*)(data + read));
		read += 2;
		size = kpass_htoll(*(uint32_t*)(data + read));
		read += 4;

		/* Make sure we don't overrun the buffer */
		if(read + size > data_len)
			goto kpass_load_decrypted_data_group_fail;
		/* check for valid type */
		if(type >= kpass_group_num_types && type != kpass_group_term)
			goto kpass_load_decrypted_data_group_fail;
		/* check for terminator having valid size */
		if(type == kpass_group_term && size != 0)
			goto kpass_load_decrypted_data_group_fail;
		/* check for all others having valid size */
		if(type != kpass_group_term && kpass_group_type_len[type] != -1 && kpass_group_type_len[type] != size)
			goto kpass_load_decrypted_data_group_fail;

		switch(type) {
			case kpass_group_comment: break;
			case kpass_group_id:	group->id = kpass_htoll(*(uint32_t*)(data + read));
						break;
			case kpass_group_name:  if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_group_fail;
						group->name = strdup((char*)data + read);
						break;
			case kpass_group_ctime: memcpy(group->ctime, data + read, 5);
						break;
			case kpass_group_mtime: memcpy(group->mtime, data + read, 5);
						break;
			case kpass_group_atime: memcpy(group->atime, data + read, 5);
						break;
			case kpass_group_etime: memcpy(group->etime, data + read, 5);
						break;
			case kpass_group_image_id: group->image_id = kpass_htoll(*(uint32_t*)(data + read));
						break;
			case kpass_group_level: group->level = kpass_htols(*(uint16_t*)(data + read));
						break;
			case kpass_group_flags: group->flags = kpass_htoll(*(uint32_t*)(data + read));
						break;
			case kpass_group_term:  db->groups[read_groups] = group;
						read_groups++;
						group = NULL;
						break;

			default: goto kpass_load_decrypted_data_group_fail;
		}
		read += size;
	}
	/* Make sure we exited because we had read all of the groups */
	if(read_groups != db->groups_len)
		goto kpass_load_decrypted_data_group_fail;

	/* Moving on to entries */

	db->entries = malloc(sizeof(*entry) * db->entries_len);
	memset(db->entries, 0, sizeof(*entry) * db->entries_len);

	while(read < data_len && read_entries < db->entries_len) {
		if(!entry) {
			entry = malloc(sizeof(kpass_entry));
			memset(entry, 0, sizeof(kpass_entry));
		}

		type = kpass_htols(*(uint16_t*)(data + read));
		read += 2;
		size = kpass_htoll(*(uint32_t*)(data + read));
		read += 4;

		/* Make sure we don't overrun the buffer */
		if(read + size > data_len)
			goto kpass_load_decrypted_data_entry_fail;
		/* check for valid type */
		if(type >= kpass_entry_num_types && type != kpass_entry_term)
			goto kpass_load_decrypted_data_entry_fail;
		/* check for terminator having valid size */
		if(type == kpass_entry_term && size != 0)
			goto kpass_load_decrypted_data_entry_fail;
		/* check for all others having valid size */
		if(type != kpass_entry_term && kpass_entry_type_len[type] != -1 && kpass_entry_type_len[type] != size)
			goto kpass_load_decrypted_data_entry_fail;

		switch(type) {
			case kpass_entry_comment: break;
			case kpass_entry_uuid: memcpy(entry->uuid, data + read, 16);
						break;
			case kpass_entry_group_id: entry->group_id = kpass_htoll(*(uint32_t*)(data + read));
						break;
			case kpass_entry_image_id: entry->image_id = kpass_htoll(*(uint32_t*)(data + read));
						break;
			case kpass_entry_title: if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->title = strdup((char*)data + read);
						break;
			case kpass_entry_url:   if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->url = strdup((char*)data + read);
						break;
			case kpass_entry_username: if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->username = strdup((char*)data + read);
						break;
			case kpass_entry_password: if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->password = strdup((char*)data + read);
						break;
			case kpass_entry_notes: if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->notes = strdup((char*)data + read);
						break;
			case kpass_entry_ctime: memcpy(entry->ctime, data + read, 5);
						break;
			case kpass_entry_mtime: memcpy(entry->mtime, data + read, 5);
						break;
			case kpass_entry_atime: memcpy(entry->atime, data + read, 5);
						break;
			case kpass_entry_etime: memcpy(entry->etime, data + read, 5);
						break;
			case kpass_entry_desc:  if(data[read + size - 1] != 0) goto kpass_load_decrypted_data_entry_fail;
						entry->desc = strdup((char*)data + read);
						break;
			case kpass_entry_data: if(size > 0) {
							entry->data = malloc(size);
							memcpy(entry->data, data + read, size);
						} else {
							entry->data = NULL;
						}
						entry->data_len = size;
						break;
			case kpass_entry_term:	db->entries[read_entries] = entry;
						read_entries++;
						entry = NULL;
						break;
						
			default: goto kpass_load_decrypted_data_entry_fail;
		}
		read += size;
	}

	if(read != data_len || read_entries != db->entries_len)
		goto kpass_load_decrypted_data_entry_fail;

	goto kpass_load_decrypted_data_success;

kpass_load_decrypted_data_entry_fail:
	if(retval == kpass_success) retval = kpass_load_decrypted_data_entry_fail;

	if(entry)
		kpass_free_entry(entry);

	for(x = 0; x < read_entries; x++)
		kpass_free_entry(db->entries[x]);

	free(db->entries);
	db->entries = NULL;

kpass_load_decrypted_data_group_fail:
	if(retval == kpass_success) retval = kpass_load_decrypted_data_group_fail;

	if(group)
		kpass_free_group(group);

	for(x = 0; x < read_groups; x++)
		kpass_free_group(db->groups[x]);

	free(db->groups);
	db->groups = NULL;

kpass_load_decrypted_data_success:
	return retval;
}

kpass_retval kpass_init_db(kpass_db *db, const uint8_t *data, const int len) {
	int x;

	if(len <= kpass_header_len) return kpass_init_db_short;

	/* init internal structures of kpass_db */
	db->groups = NULL;
	db->entries = NULL;
	db->encrypted_data = NULL;
	db->encrypted_data_len = 0;

	/* Check signature */
	for(x=0; x < kpass_signature_len; x++) {
		if(kpass_signature[x] != data[x]) {
			return kpass_init_db_signature;
		}
	}
	data += kpass_signature_len;

	/* read flags */
	db->flags = kpass_htoll(*(uint32_t*)data);
	if(db->flags >= kpass_flag_INVALID)
		return kpass_unsupported_flag;
	data += 4;

	/* grab version info */
	db->version = kpass_htoll(*(uint32_t*)data);
	data += 4;

	/* copy master_seed */
	memcpy(db->master_seed, data, 16);
	data += 16;

	/* copy encryption_init_vector */
	memcpy(db->encryption_init_vector, data, 16);
	data += 16;

	/* read groups_len  */
	db->groups_len = kpass_htoll(*(uint32_t*)data);
	data += 4;

	/* read entries_len  */
	db->entries_len = kpass_htoll(*(uint32_t*)data);
	data += 4;

	/* copy contents_hash */
	memcpy(db->contents_hash, data, 32);
	data += 32;

	/* copy master_seed_extra */
	memcpy(db->master_seed_extra, data, 32);
	data += 32;

	/* read key_rounds  */
	db->key_rounds = kpass_htoll(*(uint32_t*)data);
	data += 4;

	/* The rest of the data is the encrypted data */
	db->encrypted_data_len = len - kpass_header_len;
	db->encrypted_data = malloc(db->encrypted_data_len);
	memcpy(db->encrypted_data, data, db->encrypted_data_len);

	return kpass_success;
}

static void kpass_write_header(const kpass_db *db, uint8_t * buf) {

	memcpy(buf, kpass_signature, 8);
	buf += 8;

	*(uint32_t*)buf = kpass_htoll(db->flags);
	buf += 4;

	*(uint32_t*)buf = kpass_htoll(db->version);
	buf += 4;

	memcpy(buf, db->master_seed, 16);
	buf += 16;

	memcpy(buf, db->encryption_init_vector, 16);
	buf += 16;

	*(uint32_t*)buf = kpass_htoll(db->groups_len);
	buf += 4;

	*(uint32_t*)buf = kpass_htoll(db->entries_len);
	buf += 4;

	memcpy(buf, db->contents_hash, 32);
	buf += 32;

	memcpy(buf, db->master_seed_extra, 32);
	buf += 32;

	*(uint32_t*)buf = kpass_htoll(db->key_rounds);
	buf += 4;
}

static kpass_retval kpass_encrypt_data(kpass_db *db, const uint8_t *pw_hash, uint8_t * data, int len, int pack_len) {
	struct CBC_CTX(struct aes_ctx, AES_BLOCK_SIZE) aes_ctx;
	struct sha256_ctx sha256_ctx;
	uint8_t hash[32];
	int x;

	if(db->flags != (kpass_flag_RIJNDAEL | kpass_flag_SHA2))
		return kpass_unsupported_flag;
		
	/* Let's calculate the new contents_hash value */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, pack_len, data);
	sha256_digest(&sha256_ctx, SHA256_DIGEST_SIZE, hash);

	memcpy(db->contents_hash, hash, 32);

	/* Now make the key for the encryption */
	memcpy(hash, pw_hash, 32);
	kpass_prepare_key(db, hash);

	/* Do some hokey PKCS7 padding */
	for(x = pack_len; x < len; x++) {
		data[x] = len - pack_len;
	}

	/* Begin AES encryption of data */
	aes_set_encrypt_key(&aes_ctx.ctx, AES_KEY_SIZE, hash);
	CBC_SET_IV(&aes_ctx, db->encryption_init_vector);
	CBC_ENCRYPT(&aes_ctx, aes_encrypt, len, data, data);

	return kpass_success;
}

kpass_retval kpass_encrypt_db(kpass_db *db, const uint8_t *pw_hash, uint8_t * buf) {
	int sum, len;
	kpass_retval retval = kpass_success;

	/* get packed length */
	len = kpass_db_packed_len(db);

	/* round up to block size of 16 bytes */
	sum = (len + 16) & (-1 ^ 15);

	retval = kpass_pack_db(db, buf + kpass_header_len, len);
	if(retval)
		goto kpass_encrypt_db_end;

	retval = kpass_encrypt_data(db, pw_hash, buf + kpass_header_len, sum, len);
	if(retval)
		goto kpass_encrypt_db_end;

	/* write header afterward so it has updated hash */
	kpass_write_header(db, buf);

kpass_encrypt_db_end:
	return retval;
}

static kpass_retval kpass_pack_db(const kpass_db *db, uint8_t *buf, int len) {
	kpass_retval retval = kpass_success;
	int i, tmp, used = 0; /* 'used' is incremented and checked before
				copying to prevent overrunning buf */
	uint16_t type;
	kpass_group *g;
	kpass_entry *e;

	/* pack groups first */
	for(i = 0; i < db->groups_len; i++) {
		g = db->groups[i];
		/* start at field #1, 0 is for comments */
		for(type = 1; type < kpass_group_num_types; type++) {
			
			/* write header for all of fields */
			used += 2;
			if(used > len) goto kpass_pack_db_fail;
			*(uint16_t*)buf = kpass_htols(type);
			buf += 2;

			/* write the size if it can be determined */
			if(kpass_group_type_len[type] != -1) {
				used += 4 + kpass_group_type_len[type];
				if(used > len) goto kpass_pack_db_fail;
				*(uint32_t*)buf = kpass_htoll(kpass_group_type_len[type]);
				buf += 4;
			}

			switch(type) {
				case kpass_group_id:	*(uint32_t*)buf = kpass_htoll(g->id);
							break;

				case kpass_group_name:  tmp = strlen(g->name) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, g->name, tmp);
							buf += tmp;
							break;

				case kpass_group_ctime: memcpy(buf, g->ctime, 5);
							break;

				case kpass_group_mtime: memcpy(buf, g->mtime, 5);
							break;

				case kpass_group_atime: memcpy(buf, g->atime, 5);
							break;

				case kpass_group_etime: memcpy(buf, g->etime, 5);
							break;

				case kpass_group_image_id: *(uint32_t*)buf = kpass_htoll(g->image_id);
							break;

				case kpass_group_level: *(uint16_t*)buf = kpass_htoll(g->level);
							break;

				case kpass_group_flags: *(uint32_t*)buf = kpass_htoll(g->flags);
							break;
	
				/* I really hope this case never gets hit... */
				default: goto kpass_pack_db_fail;
			}

			/* increment buf if it was a fixed length */
			if(kpass_group_type_len[type] != -1) {
				buf += kpass_group_type_len[type];
			}
		}
		
		/* drop the terminator for this group */
		used += 6;
		if(used > len) goto kpass_pack_db_fail;
		*(uint16_t*)buf = kpass_htols(kpass_group_term);
		buf += 2;
		*(uint32_t*)buf = kpass_htoll(0);
		buf += 4;
	}


	/* pack the entries */
	for(i = 0; i < db->entries_len; i++) {
		e = db->entries[i];
		/* start at field #1, 0 is for comments */
		for(type = 1; type < kpass_entry_num_types; type++) {
			
			/* write header for all of fields */
			used += 2;
			if(used > len) goto kpass_pack_db_fail;
			*(uint16_t*)buf = kpass_htols(type);
			buf += 2;

			/* write the size if it can be determined */
			if(kpass_entry_type_len[type] != -1) {
				used += 4 + kpass_entry_type_len[type];
				if(used > len) goto kpass_pack_db_fail;
				*(uint32_t*)buf = kpass_htoll(kpass_entry_type_len[type]);
				buf += 4;
			}

			switch(type) {
				case kpass_entry_uuid: 	memcpy(buf, e->uuid, 16);
							break;

				case kpass_entry_group_id: *(uint32_t*)buf = kpass_htoll(e->group_id);
							break;

				case kpass_entry_image_id: *(uint32_t*)buf = kpass_htoll(e->image_id);
							break;

				case kpass_entry_title: tmp = strlen(e->title) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->title, tmp);
							buf += tmp;
							break;

				case kpass_entry_url:   tmp = strlen(e->url) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->url, tmp);
							buf += tmp;
							break;

				case kpass_entry_username: tmp = strlen(e->username) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->username, tmp);
							buf += tmp;
							break;

				case kpass_entry_password: tmp = strlen(e->password) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->password, tmp);
							buf += tmp;
							break;

				case kpass_entry_notes: tmp = strlen(e->notes) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->notes, tmp);
							buf += tmp;
							break;

				case kpass_entry_ctime: memcpy(buf, e->ctime, 5);
							break;

				case kpass_entry_mtime: memcpy(buf, e->mtime, 5);
							break;

				case kpass_entry_atime: memcpy(buf, e->atime, 5);
							break;

				case kpass_entry_etime: memcpy(buf, e->etime, 5);
							break;

				case kpass_entry_desc:  tmp = strlen(e->desc) + 1;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->desc, tmp);
							buf += tmp;
							break;

				case kpass_entry_data:  tmp = e->data_len;
							used += 4 + tmp;
							if(used > len) goto kpass_pack_db_fail;
							*(uint32_t*)buf = kpass_htoll(tmp);
							buf += 4;
							memcpy(buf, e->data, tmp);
							buf += tmp;
							break;

				/* I really hope this case never gets hit... */
				default: goto kpass_pack_db_fail;
			}

			/* increment buf if it was a fixed length */
			if(kpass_entry_type_len[type] != -1) {
				buf += kpass_entry_type_len[type];
			}
		}

		/* drop the terminator for this entry */
		used += 6;
		if(used > len) goto kpass_pack_db_fail;
		*(uint16_t*)buf = kpass_htols(kpass_entry_term);
		buf += 2;
		*(uint32_t*)buf = kpass_htoll(0);
		buf += 4;
	}

	goto kpass_pack_db_success;

kpass_pack_db_fail:
	if(retval == kpass_success) retval = kpass_pack_db_fail;

kpass_pack_db_success:
	return retval;
}
int kpass_db_encrypted_len(const kpass_db *db) {
	int sum = kpass_db_packed_len(db);
	
	/* round up to block size of 16 bytes */
	sum = (sum + 16) & (-1 ^ 15);

	return sum + kpass_header_len;
}

static int kpass_db_packed_len(const kpass_db *db) {
	int size = 0;
	int x;
	for(x = 0; x < db->groups_len; x++) {
		size += kpass_group_packed_len(db->groups[x]);
	}
	for(x = 0; x < db->entries_len; x++) {
		size += kpass_entry_packed_len(db->entries[x]);
	}
	return size;
}

static int kpass_group_packed_len(const kpass_group *g) {
	return kpass_group_fixed_len + strlen(g->name) + 1 +
	kpass_group_num_types * 6;
}

static int kpass_entry_packed_len(const kpass_entry *e) {
	return kpass_entry_fixed_len + strlen(e->title) + strlen(e->url)
	+ strlen(e->username) + strlen(e->password) + strlen(e->notes)
	+ strlen(e->desc) + 6 + e->data_len + kpass_entry_num_types * 6;
}

/* The time array is packed like this:
 *
 * time:   0          1            2           3            4
 *    76 543210   765432 10   76 54321 0   7654 3210   76 543210
 *      |               |       |     |        |         |      |
 *      +------year-----+-month-+-day-+--hour--+--minute-+second+ 
 */
void kpass_unpack_time(const uint8_t time[5], struct tm *tms) {
	tms->tm_sec  = time[4] & 0x3f;
	tms->tm_min  = ((time[3] & 0x0f) << 2) | (time[4] >> 6);
	tms->tm_hour = ((time[2] & 0x01) << 4) | (time[3] >> 4);
	tms->tm_mday = (time[2] >> 1) & 0x1f;
	tms->tm_mon  = ((time[1] & 0x03) << 2) | (time[2] >> 6);
	tms->tm_mon--; /* tm struct stores month zero indexed */

	/* This is happening in an int (more than 8 bits), so the bits
	 * shifted off the left are preserved. */
	tms->tm_year = (time[0] << 6) | (time[1] >> 2);
	tms->tm_year -= 1900; /* tm struct stores year as offset from 1900 */

	tms->tm_wday = 0;
	tms->tm_yday = 0;
	tms->tm_isdst = -1;
}

void kpass_pack_time(const struct tm *tms, uint8_t time[5]) {
	int year = tms->tm_year + 1900; /* tm struct stores year as offset from 1900 */
	int month = tms->tm_mon + 1;    /* tm struct stores month zero indexed */

	time[4] = (tms->tm_sec & 0x3f) | (tms->tm_min << 6);
	time[3] = ((tms->tm_min >> 2) & 0x0f) | (tms->tm_hour << 4);
	time[2] = ((tms->tm_hour >> 4) & 0x01) | ((tms->tm_mday & 0x1f) << 1) | (month << 6);
	time[1] = ((month >> 2) & 0x03) | (year << 2);
	time[0] = (year >> 6) & 0x3f;
}

void kpass_free_db(kpass_db *db) {
	kpass_free_groups(db);
	kpass_free_entries(db);

	free(db->encrypted_data);
}

void kpass_free_group(kpass_group *group) {
	if(!group) return;
	if(group->name) {
		memset(group->name, 0, strlen(group->name));
		free(group->name);
	}
	memset(group, 0, sizeof(kpass_group));
	free(group);
}

void kpass_free_groups(kpass_db *db) {
	int x;

	if(!db->groups) return;
	for(x = 0; x < db->groups_len; x++)
		kpass_free_group(db->groups[x]);
	free(db->groups);
	db->groups = NULL;
	db->groups_len = 0;
}

void kpass_free_entry(kpass_entry *entry) {
	if(!entry) return;
	if(entry->title) {
		memset(entry->title, 0, strlen(entry->title));
		free(entry->title);
	}
	if(entry->url) {
		memset(entry->url, 0, strlen(entry->url));
		free(entry->url);
	}
	if(entry->username) {
		memset(entry->username, 0, strlen(entry->username));
		free(entry->username);
	}
	if(entry->password) {
		memset(entry->password, 0, strlen(entry->password));
		free(entry->password);
	}
	if(entry->notes) {
		memset(entry->notes, 0, strlen(entry->notes));
		free(entry->notes);
	}
	if(entry->data) {
		memset(entry->data, 0, entry->data_len);
		free(entry->data);
	}
	if(entry->desc) {
		memset(entry->desc, 0, strlen(entry->desc));
		free(entry->desc);
	}

	memset(entry, 0, sizeof(kpass_entry));
	free(entry);
}

void kpass_free_entries(kpass_db *db) {
	int x;

	if(!db->entries) return;
	for(x = 0; x < db->entries_len; x++)
		kpass_free_entry(db->entries[x]);
	free(db->entries);
	db->entries = NULL;
	db->entries_len = 0;
}

static uint32_t kpass_htoll(uint32_t x) {
#if BYTE_ORDER == BIG_ENDIAN
	return bswap_32 (x);
#elif BYTE_ORDER == LITTLE_ENDIAN
	return x;
#else
# error "What kind of system is this?"
#endif
}

static uint16_t kpass_htols(uint16_t x) {
#if BYTE_ORDER == BIG_ENDIAN
	return bswap_16 (x);
#elif BYTE_ORDER == LITTLE_ENDIAN
	return x;
#else
# error "What kind of system is this?"
#endif
}
