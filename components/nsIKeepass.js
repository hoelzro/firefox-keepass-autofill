Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://keepassautofill/content/keepass.jsm");

function KeepassImpl() {
}

KeepassImpl.prototype = {
    classID: Components.ID('{99e105c6-6ad8-430b-9cc6-48b7bbb8b102}'),
    contractID: '@hoelz.ro/keepassautofill;1',
    classDescription: 'Keepass database',

    QueryInterface: XPCOMUtils.generateQI([Components.interfaces.nsIKeepass]),

    getCredentialsForLocation: function(url, count) {
        var creds = Components.classes['@hoelz.ro/keepassautofill-credentials;1'].createInstance(Components.interfaces.nsIKeepassCredentials);
        creds.username = 'hoelzro1';
        creds.password = 'abc1234';

        count.value = 1;
        return [ creds ];
    },
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([KeepassImpl]);
