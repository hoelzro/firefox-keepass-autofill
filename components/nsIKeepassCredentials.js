Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

function KeepassCredentials() {
}

KeepassCredentials.prototype = {
    classID: Components.ID('{0897d710-65ca-43fd-adfa-cb0b66555d2e}'),
    contractID: '@hoelz.ro/keepassautofill-credentials;1',
    classDescription: 'Keepass credentials',

    QueryInterface: XPCOMUtils.generateQI([Components.interfaces.nsIKeepassCredentials]),

    get username() {
        return this._username;
    },

    set username(value) {
        return this._username = value;
    },

    get password() {
        return this._password;
    },

    set password(value) {
        return this._password = value;
    },
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([KeepassCredentials]);
