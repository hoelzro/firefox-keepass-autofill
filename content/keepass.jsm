/*
 * This file is part of Firefox Keepass Autofill.
 *
 * Firefox Keepass Autofill is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Firefox Keepass Autofill is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Firefox Keepass Autofill.  If not, see <http://www.gnu.org/licenses/>.
 */

const Cc = Components.classes;
const Ci = Components.interfaces;

var Cifre = {};

Components.utils.import('chrome://keepassautofill/content/cifre-aes.jsm', Cifre);
Components.utils.import('chrome://keepassautofill/content/cifre-utils.jsm', Cifre);

var aes        = Cifre.AES;
var cifreUtils = Cifre.Utils;

const FLAG_SHA2    = 1;
const FLAG_AES     = 2;
const FLAG_ARC4    = 4;
const FLAG_TWOFISH = 8;

var charCodesToHex = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

function dumpHex(value) {
    // assume a string for now
    var result = '';
    if(typeof(value) == 'string') {
        for(var i = 0; i < value.length; i++) {
            result += charCodesToHex[value.charCodeAt(i) >> 4];
            result += charCodesToHex[value.charCodeAt(i) & 0xf];
        }
    } else {
        for(var i = 0; i < value.length; i++) {
            result += charCodesToHex[value[i] >> 4];
            result += charCodesToHex[value[i] & 0xf];
        }
    }
    dump(result + "\n");
}

function sha256(input) {
    var crypto = Cc['@mozilla.org/security/hash;1'].createInstance(Ci.nsICryptoHash);
    crypto.init(crypto.SHA256);
    if(typeof(input) === 'string') {
        input = cifreUtils.stringToArray(input);
    }
    crypto.update(input, input.length);

    return cifreUtils.stringToArray(crypto.finish(false));
}

function decodeUtf8(s) {
    var converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"]
                    .createInstance(Ci.nsIScriptableUnicodeConverter);
    converter.charset = 'UTF-8';

    return converter.ConvertToUnicode(s);
}

function LittleEndianInputStream(stream) {
    this.stream = stream;
}

LittleEndianInputStream.prototype = {
    read32: function() {
        var bytes = this.stream.readBytes(4);
        return (bytes.charCodeAt(3) << 24) |
               (bytes.charCodeAt(2) << 16) |
               (bytes.charCodeAt(1) << 8)  |
               bytes.charCodeAt(0);
    },

    readBytes: function(length) {
        return this.stream.readBytes(length);
    },

    available: function() {
        return this.stream.available();
    }
};

// XXX used a typed array?
function DecodedStream(stream, password, header) {
    this.stream = stream;

    var hashedPassword = sha256(password);
    var rounds         = header.keyEncRounds;
    var masterSeed     = cifreUtils.stringToArray(header.masterSeed2);
    var encrypt        = aes.ecb.encrypt;
    for(var i = 0; i < rounds; i++) {
        encrypt(hashedPassword, masterSeed);
    }
    hashedPassword = sha256(hashedPassword);
    var key        = new Array(48);
    var masterSeed = cifreUtils.stringToArray(header.masterSeed);
    for(var i = 0; i < 16; i++) {
        key[i] = masterSeed[i];
    }
    for(var i = 0; i < hashedPassword.length; i++) {
        key[i + 16] = hashedPassword[i];
    }

    this.key           = aes.keyExpansion(sha256(key));
    this.previousBlock = cifreUtils.stringToArray(header.encryptionIV);
    this.plaintext     = [];
}

DecodedStream.prototype = {
    // this streaming CBC logic was adapted from cifre's sources
    _readBlock: function() {
        // XXX avoid creating a new array
        var nextBlock = cifreUtils.stringToArray(this.stream.readBytes(16));
        var copy      = new Array(16);
        for(var i = 0; i < 16; i++) {
            copy[i] = nextBlock[i];
        }
        aes.decrypt(nextBlock, this.key);
        var previousBlock = this.previousBlock;
        for (var i = 0; i < 16; i++) {
            nextBlock[i] ^= previousBlock[i];
        }

        this.previousBlock = copy;

        // XXX avoid concat
        this.plaintext = this.plaintext.concat(nextBlock);
        if(this.stream.available() == 0) {
            var nCharsToChop = this.plaintext[this.plaintext.length - 1];
            this.plaintext   = this.plaintext.slice(0, -1 * nCharsToChop);
        }
    },

    _readRawBytes: function(length) {
        while(length > this.plaintext.length) {
            this._readBlock();
        }

        return this.plaintext.splice(0, length);
    },

    read16: function() {
        var bytes = this._readRawBytes(2);
        return (bytes[1] << 8) | bytes[0];
    },

    read32: function() {
        var bytes = this._readRawBytes(4);
        return (bytes[3] << 24) |
               (bytes[2] << 16) |
               (bytes[1] << 8)  |
               bytes[0];
    },

    readBytes: function(length) {
        var bytes = this._readRawBytes(length);
        // XXX there's got to be something more efficient...
        var result = '';
        for(var i = 0; i < length; i++) {
            result += String.fromCharCode(bytes[i]);
        }
        return result;
    },
};

function Keepass(filename, password) {
    this.filename = filename;
    this.password = password;
};

// Based on DbFormat.txt from libkpass
Keepass.prototype = {
    _readHeader: function(stream) {
        var header = {};

        var sig1 = stream.read32();
        var sig2 = stream.read32();
        //assert(0x9AA2D903 == sig1);
        //assert(0xB54BFB65 == sig2);
        header.flags        = stream.read32();
        header.version      = stream.read32();
        header.masterSeed   = stream.readBytes(16);
        header.encryptionIV = stream.readBytes(16);
        header.nGroups      = stream.read32();
        header.nEntries     = stream.read32();
        header.contentHash  = stream.readBytes(32);
        header.masterSeed2  = stream.readBytes(32);
        header.keyEncRounds = stream.read32();

        //assert(header.flags == (SHA2 | RIJNDAEL));

        return header;
    },

    _readGroups: function(stream, nGroups) {
        const KPASS_GROUP_COMMENT  = 0;
	const KPASS_GROUP_ID       = 1;
	const KPASS_GROUP_NAME     = 2;
	const KPASS_GROUP_CTIME    = 3;
	const KPASS_GROUP_MTIME    = 4;
	const KPASS_GROUP_ATIME    = 5;
	const KPASS_GROUP_ETIME    = 6;
	const KPASS_GROUP_IMAGE_ID = 7;
	const KPASS_GROUP_LEVEL    = 8;
	const KPASS_GROUP_FLAGS    = 9;
        const KPASS_GROUP_TERM     = 0xFFFF;

        var groupIdToName = {};

        // XXX check for malformed shit?
        // XXX assert sizes for certain types
        for(var i = 0; i < nGroups; i++) {
            var type = stream.read16();
            var size = stream.read32();

            var groupId;
            var groupName;

            while(type != KPASS_GROUP_TERM) {
                switch(type) {
                    case KPASS_GROUP_NAME:
                        groupName = decodeUtf8(stream.readBytes(size).slice(0, -1));
                        // XXX decode UTF-8
                        break;
                    case KPASS_GROUP_ID:
                        //assert(size == 4);
                        groupId = stream.read32();
                        break;
                    case KPASS_GROUP_FLAGS:
                    case KPASS_GROUP_COMMENT:
                    case KPASS_GROUP_CTIME:
                    case KPASS_GROUP_MTIME:
                    case KPASS_GROUP_ATIME:
                    case KPASS_GROUP_ETIME:
                    case KPASS_GROUP_IMAGE_ID:
                    case KPASS_GROUP_LEVEL:
                        // we don't care about these fields at the moment;
                        // throw them away
                        stream.readBytes(size);
                        break;
                    default:
                        // XXX FREAK OUT
                }

                type = stream.read16();
                size = stream.read32();
            }

            groupIdToName[groupId] = groupName;
        }

        return groupIdToName;
    },

    _readEntries: function(stream, nEntries, groupIdToName, callback) {
        const KPASS_ENTRY_COMMENT  = 0x0;
        const KPASS_ENTRY_UUID     = 0x1;
        const KPASS_ENTRY_GROUP_ID = 0x2;
        const KPASS_ENTRY_IMAGE_ID = 0x3;
        const KPASS_ENTRY_TITLE    = 0x4;
        const KPASS_ENTRY_URL      = 0x5;
        const KPASS_ENTRY_USERNAME = 0x6;
        const KPASS_ENTRY_PASSWORD = 0x7;
        const KPASS_ENTRY_NOTES    = 0x8;
        const KPASS_ENTRY_CTIME    = 0x9;
        const KPASS_ENTRY_MTIME    = 0xA;
        const KPASS_ENTRY_ATIME    = 0xB;
        const KPASS_ENTRY_ETIME    = 0xC;
        const KPASS_ENTRY_DESC     = 0xD;
        const KPASS_ENTRY_DATA     = 0xE;
        const KPASS_ENTRY_TERM     = 0xFFFF;

        for(var i = 0; i < nEntries; i++) {
            var type = stream.read16();
            var size = stream.read32();

            var entry = {};

            while(type != KPASS_ENTRY_TERM) {
                switch(type) {
                    case KPASS_ENTRY_GROUP_ID:
                        entry.group = groupIdToName[stream.read32()];
                        break;
                    case KPASS_ENTRY_TITLE:
                        entry.title = decodeUtf8(stream.readBytes(size).slice(0, -1));
                        break;
                    case KPASS_ENTRY_URL:
                        entry.url = decodeUtf8(stream.readBytes(size).slice(0, -1));
                        break;
                    case KPASS_ENTRY_USERNAME:
                        entry.username = decodeUtf8(stream.readBytes(size).slice(0, -1));
                        break;
                    case KPASS_ENTRY_PASSWORD:
                        entry.password = decodeUtf8(stream.readBytes(size).slice(0, -1));
                        break;
                    case KPASS_ENTRY_COMMENT:
                    case KPASS_ENTRY_UUID:
                    case KPASS_ENTRY_IMAGE_ID:
                    case KPASS_ENTRY_NOTES:
                    case KPASS_ENTRY_CTIME:
                    case KPASS_ENTRY_MTIME:
                    case KPASS_ENTRY_ATIME:
                    case KPASS_ENTRY_ETIME:
                    case KPASS_ENTRY_DESC:
                    case KPASS_ENTRY_DATA:
                        stream.readBytes(size);
                        break;
                    default:
                        // XXX FREAK OUT
                        stream.readBytes(size);
                        break;
                }

                type = stream.read16();
                size = stream.read32();
            }

            callback(entry);
        }
    },

    eachEntry: function(callback) {
        // XXX error handling?
        var file = Cc['@mozilla.org/file/local;1'].createInstance(Ci.nsILocalFile);
        file.initWithPath(this.filename);
        var inputStream = Cc['@mozilla.org/network/file-input-stream;1'].createInstance(Ci.nsIFileInputStream);
        inputStream.init(file, -1, -1, 4); // XXX magic numbers
        var rawInputStream = Cc['@mozilla.org/binaryinputstream;1'].createInstance(Ci.nsIBinaryInputStream);
        rawInputStream.setInputStream(inputStream);
        var lesStream = new LittleEndianInputStream(rawInputStream);

        var header        = this._readHeader(lesStream);
        var decodedStream = new DecodedStream(rawInputStream, this.password, header);
        var groupIdToName = this._readGroups(decodedStream, header.nGroups);
        this._readEntries(decodedStream, header.nEntries, groupIdToName, callback);
    },
};

var EXPORTED_SYMBOLS = ['Keepass'];
