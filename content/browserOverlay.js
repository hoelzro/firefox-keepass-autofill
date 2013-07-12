if('undefined' === typeof(KeepassAutofill)) {
    var KeepassAutofill = {};
}

KeepassAutofill.BrowserOverlay = {
    fillInForm: function() {
        var inputs = this.getFormInputs();

        if(inputs === null) {
            this.warnUser('Username/password fields not found!');
            return;
        }

        var usernameInput = inputs.username;
        var passwordInput = inputs.password;

        this.getCredentialsForLocation(window.content.document.location,
            function(creds) {
                if(creds === null) {
                    this.warnUser('No credentials found for this site =(');
                    return;
                }

                usernameInput.value = creds.username;
                passwordInput.value = creds.password;
        });
    },
    logDebug: function(msg) {
        var console = Components.classes['@mozilla.org/consoleservice;1'].
            getService(Components.interfaces.nsIConsoleService);
        console.logStringMessage(msg);
    },
    warnUser: function(msg) {
        window.alert(msg);
    },
    getFormInputs: function() {
        var forms = window.content.document.forms;

        var username;
        var password;
        var element;
        var i;

        for(i = 0;
            i < forms.length && ('undefined' === typeof(username) ||
                'undefined' === typeof(password));
            i++) {
                var elements = forms[i].elements;

                if('undefined' === typeof(username)) {
                    element = elements.namedItem('username');
                    if(element !== null) {
                        username = element;
                    }
                }
                if('undefined' === typeof(password)) {
                    element = elements.namedItem('password');
                    if(element !== null) {
                        password = element;
                    }
                }
        }

        if('undefined' !== typeof(username) &&
           'undefined' !== typeof(password)) {
            return {
                username: username,
                password: password,
            };
        } else {
            return null;
        }
    },
    getCredentialsForLocation: function(location, callback) {
        var keepass     = Components.classes['@hoelz.ro/keepassautofill;1'].createInstance(Components.interfaces.nsIKeepass);
        var count       = {};
        var credentials = keepass.getCredentialsForLocation(location, count, []);
        callback.call(this, credentials[0]);
    },
};
