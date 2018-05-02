var __cookie = require('./cookie.js');

module.exports = (function () {

    function tokenName(name) {
        name = name || this.currentToken;

        if (name) {
            return name;
        }

        if (this.impersonating.call(this)) {
            return this.options.tokenImpersonateName;
        }

        return this.options.accessTokenName;
    }

    function isWebStorageSupported() {
        try {
            if (!window.localStorage || !window.sessionStorage) {
                throw 'exception';
            }

            localStorage.setItem('storage_test', 1);
            localStorage.removeItem('storage_test');

            /**
             * Just to be sure
             */

            sessionStorage.setItem('storage_test', 1);
            sessionStorage.removeItem('storage_test');

            return true;
        } catch (e) {
            return false;
        }
    }

    function isCookieSupported() {
        return true;
    }

    function processToken(action, name, token) {
        var i, ii,
            args = [tokenName.call(this, name)];

        if (token) {
            args.push(token);
        }

        /**
         * I've converted the isLocalStorageSupported
         * function name to isWebStorageSupported so the name convers both storages
         */

        let _isWebStorageSupported = isWebStorageSupported();


        for (i = 0, ii = this.options.tokenStore.length; i < ii; i++) {
            /**
             * Added sessionStorage to set short-lived tokens when user don't
             * want to be remembered
             */

            if (this.options.tokenStore[i] === 'localStorage' && _isWebStorageSupported) {
                return localStorage[action + 'Item'](args[0], args[1]);
            }

            else if (this.options.tokenStore[i] === 'sessionStorage' && _isWebStorageSupported) {
                return sessionStorage[action + 'Item'](args[0], args[1]);
            }

            else if (this.options.tokenStore[i] === 'cookie' && isCookieSupported()) {
                return __cookie[action].apply(this, args);
            }
        }
    }

    return {
        get: function (name) {
            return processToken.call(this, 'get', name);
        },

        set: function (name, token) {
            return processToken.call(this, 'set', name, token);
        },

        remove: function (name) {
            return processToken.call(this, 'remove', name);
        },

        expiring: function () {
            return false;
        }
    }

})();