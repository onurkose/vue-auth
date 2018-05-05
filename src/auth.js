var __utils  = require('./lib/utils.js'),
    __token  = require('./lib/token.js'),
    __cookie = require('./lib/cookie.js')

module.exports = function () {

    // Private (used double underscore __).

    var __transitionPrev = null,
        __transitionThis = null,
        __transitionRedirectType = null;

    function __duckPunch(methodName, data) {
        var _this = this,
            success = data.success;

        data = __utils.extend(this.options[methodName + 'Data'], [data]);

        data.success = function (res) {
            data.success = success;

            _this.options[methodName + 'Process'].call(_this, res, data);
        };

        return this.options.http._http.call(this, data);
    }

    function __bindContext(methodName, data) {
        var _auth = this.$auth;

        return _auth.options[methodName + 'Perform'].call(_auth, _auth.options.router._bindData.call(_auth, data, this));
    }

    // Overrideable

    function _checkAuthenticated(cb) {
        if (this.watch.authenticated === null && __token.get.call(this)) {
            if ( ! __cookie.exists.call(this)) {
                this.options.logoutProcess.call(this, null, {});

                this.watch.loaded = true;

                return cb.call(this);
            }

            this.watch.authenticated = false;

            if (this.options.fetchData.enabled) {
                this.options.fetchPerform.call(this, {
                    success: cb,
                    error: cb,
                    enabled: true
                });
            }
            else {
                this.options.fetchProcess.call(this, {}, {});
                return cb.call(this);
            }
        } else {
            this.watch.loaded = true;
            return cb.call(this);
        }
    }

    function _routerBeforeEach(cb) {
        var _this = this;

        if (this.watch.authenticated && !__token.get.call(this)) {
            this.options.logoutProcess.call(this, null, {});
        }

        if (this.options.refreshData.enabled && !this.watch.loaded && __token.get.call(this)) {
            this.options.refreshData.data.refresh_token = __token.get.call(this, this.options.refreshTokenName)

            this.options.refreshPerform.call(this, {
                success: function () {
                    this.options.checkAuthenticated.call(_this, cb);
                }
            });
            return;
        }

        _checkAuthenticated.call(this, cb);
    }

    function _transitionEach(transition, routeAuth, cb) {
        var authRedirect = (routeAuth || '').redirect || this.options.authRedirect,
            forbiddenRedirect = (routeAuth || '').forbiddenRedirect || (routeAuth || '').redirect || this.options.forbiddenRedirect,
            notFoundRedirect = (routeAuth || '').redirect || this.options.notFoundRedirect;

        routeAuth = __utils.toArray((routeAuth || '').roles !== undefined ? routeAuth.roles : routeAuth);

        if (routeAuth && (routeAuth === true || routeAuth.constructor === Array || __utils.isObject(routeAuth))) {
            if ( ! this.check()) {
                __transitionRedirectType = 401;
                cb.call(this, authRedirect);
            }
            else if ((routeAuth.constructor === Array || __utils.isObject(routeAuth)) && ! __utils.compare(routeAuth, this.watch.data[this.options.rolesVar])) {
                __transitionRedirectType = 403;
                cb.call(this, forbiddenRedirect);
            }
            else {
                this.watch.redirect = __transitionRedirectType ? {type: __transitionRedirectType, from: __transitionPrev, to: __transitionThis} : null;
                __transitionRedirectType = null;

                return cb();
            }
        }
        else if (routeAuth === false && this.check()) {
            __transitionRedirectType = 404;
            cb.call(this, notFoundRedirect);
        }
        else {
            this.watch.redirect = __transitionRedirectType ? {type: __transitionRedirectType, from: __transitionPrev, to: __transitionThis} : null;
            __transitionRedirectType = null;

            return cb();
        }
    }

    function _requestIntercept(req) {
        var token,
            tokenName;

        if (req.ignoreVueAuth) {
            return req;
        }

        if (req.impersonating === false && this.impersonating()) {
            /**
             * defaultTokenName > accessTokenName
             */

            tokenName = this.options.accessTokenName;
        }

        token = __token.get.call(this, tokenName);

        if (token) {
            this.options.auth.request.call(this, req, token);
        }

        return req;
    }

    function _responseIntercept(res, req) {
        /**
         * token > tokens
         * We'll have more than one token from Laravel Passport
         */

        let tokens;

        if (req && req.ignoreVueAuth) {
            return;
        }

        _processInvalidToken.call(this, res, __transitionThis);

        /**
         * this.options.auth.response is already routed to laravel-passport-bearer.js
         * So, we should expect tokens are as object, includes access_token, refresh_token
         * and expires_in data. Check the driver file for more information.
         */

        tokens = this.options.auth.response.call(this, res);

        if (typeof tokens === 'object') {
            __token.set.call(this, this.options.accessTokenName, tokens.accessToken);
            __token.set.call(this, this.options.refreshTokenName, tokens.refreshToken);
            __token.set.call(this, this.options.tokenExpireDateKey, tokens.tokenExpireDate);
        }
    }

    function _parseUserData(data) {
        return data.data || {};
    }

    function _parseOauthState(data) {
        return JSON.parse(decodeURIComponent(data));
    }

    function _check(role) {
        if (this.watch.authenticated === true) {
            if (role) {
                return __utils.compare(role, this.watch.data[this.options.rolesVar]);
            }

            return true;
        }

        return false;
    }

    function _tokenExpired () {
        return ! __token.get.call(this);
    }

    function _cookieDomain () {
        return window.location.hostname;
    }

    function _getUrl () {
        var port = window.location.port

        return window.location.protocol + '//' + window.location.hostname + (port ? ':' + port : '')
    }

    function _getAuthMeta (transition) {
        var auth,
            authRoutes;

        if (transition.to) {
            auth = transition.to.auth;
        } else {
            authRoutes = transition.matched.filter(function (route) {
                return route.meta.hasOwnProperty('auth');
            });

            // matches the nested route, the last one in the list
            if (authRoutes.length) {
                auth = authRoutes[authRoutes.length - 1].meta.auth;
            }
        }

        return auth;
    }

    function _setTransitions (transition) {
        __transitionPrev = __transitionThis;
        __transitionThis = transition;
    }

    function _processInvalidToken(res, transition) {
        var i,
            auth,
            query = '',
            redirect = transition && transition.path;

        // Make sure we also attach any existing
        // query parameters on the path.
        if (redirect && transition.query) {
            for (i in transition.query) {
                if (transition.query[i]) {
                    query += '&' + i + '=' + transition.query[i];
                }
            }

            redirect += '?' + query.substring(1);
        }

        if (!this.options.http._invalidToken) {
            return;
        }

        if (!this.options.http._invalidToken.call(this, res)) {
            return;
        }

        if (transition) {
            auth = this.options.getAuthMeta(transition);
        }

        if (auth) {
            redirect = auth.redirect || this.options.authRedirect;
        }

        this.options.logoutProcess.call(this, res, {redirect: redirect});
    }

    function _fetchPerform(data) {
        var _this = this,
            error = data.error;

        data.error = function (res) {
            _this.watch.loaded = true;

            if (this.options.fetchData.error) { this.options.fetchData.error.call(this, res); }

            if (error) { error.call(_this, res); }
        };

        if (this.watch.authenticated !== true && !data.enabled) {
            _fetchProcess.call(this, {}, data);
        }
        else {
            return __duckPunch.call(this, 'fetch', data);
        }
    }

    function _fetchProcess(res, data) {
        this.watch.authenticated = true;
        this.watch.data = this.options.parseUserData.call(this, this.options.http._httpData.call(this, res));

        this.watch.loaded = true;

        if (this.options.fetchData.success) { this.options.fetchData.success.call(this, res); }

        if (data.success) { data.success.call(this, res); }
    }

    function _refreshPerform(data) {
        /**
         * This function is triggered by two locations:
         *   1] function _routerBeforeEach; to make sure before each route navigation
         *     if user logged in
         *   2} function Auth; to check user auth status periodically
         *
         * If you've enabled checkExpireDate, this guard will be depending on expireDate info.
         *
         * Either case, if you are using Laravel Passport, it'll check token expiration
         * date anyways on every request. So you should only worry about client side
         * sensitive routes that displays static information that might cause a security
         * breach.
         */

        if (this.options.refreshData.checkExpiration) {
            let tokenExpireDate = __token.get.call(this, this.options.tokenExpireDateKey)

            let diff = tokenExpireDate - Date.now();

            /**
             * expireDate is already passed or will do pass in one hour
             * 60′ x 60″ x 1000 ms
             */

            if (0 > diff || diff < 3600000) {
                return __duckPunch.call(this, 'refresh', data);
            } else {
                if (data.success) {
                    return data.success.call(this, {});
                }
            }
        }

        return __duckPunch.call(this, 'refresh', data);
    }

    function _refreshProcess(res, data) {
        if (data.success) { data.success.call(this, res); }
    }

    function _registerPerform(data) {
        return __duckPunch.call(this, 'register', data);
    }

    function _registerProcess(res, data) {
        if (data.autoLogin === true) {
            data = __utils.extend(data, [this.options.loginData, {redirect: data.redirect}]);

            this.options.loginPerform.call(this, data);
        }
        else {
            if (data.success) { data.success.call(this, res); }

            if (data.redirect) {
                this.options.router._routerGo.call(this, data.redirect);
            }
        }
    }

    function _loginPerform(data) {
        /**
         * Check function context for more info
         */

        _updateStoragePreference.call(this, { rememberMe: data.rememberMe })

        return __duckPunch.call(this, 'login', data);
    }

    function _loginProcess(res, data) {
        var _this = this;

        __cookie.remember.call(this, data.rememberMe);

        this.authenticated = null;

        this.options.fetchPerform.call(this, {
            enabled: data.fetchUser,
            success: function () {
                if (data.success) { data.success.call(this, res); }

                if (data.redirect && _this.options.check.call(_this)) {
                    _this.options.router._routerGo.call(_this, data.redirect);
                }
            }
        });
    }

    function _logoutPerform(data) {
        data = __utils.extend(this.options.logoutData, [data || {}]);

        if (data.makeRequest) {
            return __duckPunch.call(this, 'logout', data);
        }
        else {
            this.options.logoutProcess.call(this, null, data);
        }
    }

    function _logoutProcess(res, data) {
        __cookie.remove.call(this, 'rememberMe');

        __cookie.remove.call(this, this.options.tokenImpersonateName);
        __cookie.remove.call(this, this.options.accessTokenName);
        __cookie.remove.call(this, this.options.refreshTokenName);
        __cookie.remove.call(this, this.options.tokenExpireDateKey);

        __token.remove.call(this, this.options.tokenImpersonateName);
        __token.remove.call(this, this.options.accessTokenName);
        __token.remove.call(this, this.options.refreshTokenName);
        __token.remove.call(this, this.options.tokenExpireDateKey);

        this.watch.authenticated = false;
        this.watch.data = null;

        if (data.success) { data.success.call(this, res, data); }

        if (data.redirect) {
            this.options.router._routerGo.call(this, data.redirect);
        }
    }

    function _impersonatePerform(data) {
        var success,
            token = this.token.call(this); // (admin) token

        data = data || {};

        success = data.success;

        data.success = function (res) {

            // Reshuffle tokens here...
            __token.set.call(this, this.options.tokenImpersonateName, this.token.call(this));
            __token.set.call(this, this.options.accessTokenName, token);

            if (success) { success.call(this, res); }
        };

        return __duckPunch.call(this, 'impersonate', data);
    }

    function _impersonateProcess(res, data) {
        var _this = this;

        this.options.fetchPerform.call(this, {
            enabled: true,
            success: function () {
                if (data.success) { data.success.call(this, res); }

                if (data.redirect && _this.options.check.call(_this)) {
                    _this.options.router._routerGo.call(_this, data.redirect);
                }
            }
        });
    }

    function _unimpersonatePerform(data) {
        data = __utils.extend(this.options.unimpersonateData, [data || {}]);

        if (data.makeRequest) {
            return __duckPunch.call(this, 'unimpersonate', data);
        }
        else {
            this.options.unimpersonateProcess.call(this, null, data);
        }
    }

    function _unimpersonateProcess(res, data) {
        __token.remove.call(this, this.options.tokenImpersonateName);

        this.options.fetchPerform.call(this, {
            enabled: true,
            success: function () {
                if (data.success) { data.success.call(this, res, data); }

                if (data.redirect) {
                    this.options.router._routerGo.call(this, data.redirect);
                }
            }
        });
    }

    function _oauth2Perform(data) {
        var key,
            state = {},
            params = '';

        data = data || {};

        if (data.code === true) {
            data = __utils.extend(this.options[data.provider + 'Data'], [data]);

            try {
                if (data.query.state) {
                    state = this.options.parseOauthState(data.query.state);
                }
            }
            catch (e) {
                console.error('vue-auth:error There was an issue retrieving the state data.');
                state = {};
            }

            data.rememberMe = state.rememberMe === true;
            data.state = state;

            this.options.loginPerform.call(this, data);
        } else {
            data.params = __utils.extend(this.options[data.provider + 'Oauth2Data'].params, [data.params || {}]);
            data = __utils.extend(this.options[data.provider + 'Oauth2Data'], [data]);

            // Backwards compatibility.
            data.params.redirect_uri = data.redirect || data.params.redirect_uri;
            data.params.client_id = data.clientId || data.params.client_id;
            data.params.response_type = data.response_type || data.params.response_type || 'code';
            data.params.scope = data.scope || data.params.scope;
            data.params.state = data.state || data.params.state || {};

            if (typeof data.params.redirect_uri === 'function') {
                data.params.redirect_uri = data.params.redirect_uri.call(this);
            }

            data.params.state.rememberMe = data.rememberMe === true;
            data.params.state = encodeURIComponent(JSON.stringify(data.params.state));

            for (key in data.params) {
                params += '&' + key + '=' + data.params[key];
            }

            window.location = data.url + '?' + params;
        }
    }

    function _updateStoragePreference(data) {
        /**
         * Well, this part is little bit tricky.
         * This is where we check the rememberMe cookie is set true or false.
         * So we'll know if user wanted to be remembered or not. Then we can decide which
         * storage to use for the rest of the session.
         *
         * This function to be called by loginPerform and Auth functions
         */

        let checkCookie = true,
            rememberMe = false;

        if (data !== undefined) {
            if (data.rememberMe !== undefined) {
                rememberMe = data.rememberMe;

                checkCookie = false;
            }
        }

        if (checkCookie) {
            rememberMe = __cookie.get.call(this, 'rememberMe');
        }

        for (i = 0, ii = this.options.tokenStore.length; i < ii; i++) {
            if (['sessionStorage', 'localStorage'].indexOf(this.options.tokenStore[i]) !== -1) {
                this.options.tokenStore[i] = (rememberMe === true || rememberMe === 'true') ? 'localStorage' : 'sessionStorage';
            }
        }
    }

    var defaultOptions = {

        // Variables

        rolesVar:             'roles',
        tokenImpersonateName: 'impersonate_auth_token',
        accessTokenName:      'accessToken',
        refreshTokenName:     'refreshToken',
        tokenExpireDateKey:   'tokenExpireDate',
        tokenStore:           ['sessionStorage', 'cookie'],

        // Objects

        authRedirect:       {path: '/login'},
        forbiddenRedirect:  {path: '/403'},
        notFoundRedirect:   {path: '/404'},

        registerData:       {url: 'auth/register',      method: 'POST', redirect: 'auth//login'},

        /**
         * I've added grant_type vars to login and refresh functions.
         * Laravel Passport issues or refreshes tokens by this values.
         */

        loginData:          {url: 'oauth/token',        method: 'POST', redirect: 'dashboard', fetchUser: false, data: { grant_type: 'password' }},
        logoutData:         {url: 'auth/logout',        method: 'POST', redirect: 'auth/login', makeRequest: false},
        oauth1Data:         {url: 'auth/login',         method: 'POST'},
        fetchData:          {url: 'auth/user',          method: 'GET',  enabled: false},

        /**
         * Since we now have the expireDate datum for the accessToken
         * we don't really need to ask server the accessToken to be
         * refreshed each 30 minutes. If you're issuing very short lifed
         * tokens, it's better to disable checkExpiration to false so do
         * real token refresh operation periodically. Otherwise it'll only
         * be refreshed when the time very close to expireDate
         */

        refreshData:        {url: 'oauth/token',        method: 'POST', enabled: true, interval: 30, checkExpiration: true, data: { grant_type: 'refresh_token' }},
        impersonateData:    {url: 'auth/impersonate',   method: 'POST', redirect: '/'},
        unimpersonateData:  {url: 'auth/unimpersonate', method: 'POST', redirect: '/admin', makeRequest: false},

        facebookData:       {url: 'auth/facebook',      method: 'POST', redirect: '/'},
        googleData:         {url: 'auth/google',        method: 'POST', redirect: '/'},

        /**
         * We'll extend this passportData during package initialization
         */

        passportData:       {client_id: 0, client_secret: 'not so secret'},

        facebookOauth2Data: {
            url: 'https://www.facebook.com/v2.5/dialog/oauth',
            params: {
                client_id: '',
                redirect_uri: function () { return this.options.getUrl() + '/login/facebook'; },
                scope: 'email'
            }
        },
        googleOauth2Data: {
            url: 'https://accounts.google.com/o/oauth2/auth',
            params: {
                client_id: '',
                redirect_uri: function () { return this.options.getUrl() + '/login/google'; },
                scope: 'https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/plus.login https://www.googleapis.com/auth/plus.profile.emails.read'
            }
        },

        // Internal

        getUrl:             _getUrl,
        cookieDomain:       _cookieDomain,
        parseUserData:      _parseUserData,
        parseOauthState:    _parseOauthState,
        tokenExpired:       _tokenExpired,
        check:              _check,
        checkAuthenticated: _checkAuthenticated,
        getAuthMeta:        _getAuthMeta,
        setTransitions:     _setTransitions,

        readyCallback:      null,

        transitionEach:     _transitionEach,
        routerBeforeEach:   _routerBeforeEach,
        requestIntercept:   _requestIntercept,
        responseIntercept:  _responseIntercept,

        updateStoragePreference:  _updateStoragePreference,

        // Contextual

        registerPerform:    _registerPerform,
        registerProcess:    _registerProcess,

        loginPerform:       _loginPerform,
        loginProcess:       _loginProcess,

        logoutPerform:      _logoutPerform,
        logoutProcess:      _logoutProcess,

        fetchPerform:       _fetchPerform,
        fetchProcess:       _fetchProcess,

        refreshPerform:     _refreshPerform,
        refreshProcess:     _refreshProcess,

        impersonatePerform:  _impersonatePerform,
        impersonateProcess:  _impersonateProcess,

        unimpersonatePerform: _unimpersonatePerform,
        unimpersonateProcess: _unimpersonateProcess,

        oauth2Perform:      _oauth2Perform
    };

    function Auth(Vue, options) {
        var i, ii,
            msg,
            _this = this,
            drivers = ['auth', 'http', 'router'];

        this.currentToken = null;

        this.options = __utils.extend(defaultOptions, [options || {}]);
        this.options.Vue = Vue;

        this.watch = new this.options.Vue({
            data: function () {
                return {
                    data: null,
                    loaded: false,
                    redirect: null,
                    authenticated: null
                };
            },

            watch: {
                loaded: function (val) {
                    if (val === true && _this.options.readyCallback) {
                        _this.options.readyCallback();
                    }
                }
            }
        });

        /**
         * Extend refreshData and loginData with the Laravel Passport requirements
         * Maybe it's not the best solution by now (ES15 Object.assign)
         */

        this.options.refreshData.data = Object.assign(this.options.refreshData.data, this.options.passportData);
        this.options.loginData.data = Object.assign(this.options.loginData.data, this.options.passportData);

        // Check drivers.
        for (i = 0, ii = drivers.length; i < ii; i++) {
            if ( ! this.options[drivers[i]]) {
                console.error('Error (@websanova/vue-auth): "' + drivers[i] + '" driver must be set.');
                return;
            }

            if (this.options[drivers[i]]._init) {
                msg = this.options[drivers[i]]._init.call(this);

                if (msg) {
                    console.error('Error (@websanova/vue-auth): ' + msg);
                    return;
                }
            }
        }


        /**
         * Check function context for more info
         */

        _this.options.updateStoragePreference.call(this);


        // Set refresh interval.
        if (this.options.refreshData.interval && this.options.refreshData.interval > 0) {
            setInterval(function () {
                if (this.options.refreshData.enabled && !this.options.tokenExpired.call(this)) {
                    /**
                     * Attaching refreshToken to every refreshPerform action so our accessToken
                     * will never be expired
                     */

                    this.options.refreshData.data.refresh_token = __token.get.call(this, this.options.refreshTokenName);

                    this.options.refreshPerform.call(this);
                }
            }.bind(this), this.options.refreshData.interval * 1000 * 60); // In minutes.
        }

        // Init interceptors.
        this.options.router._beforeEach.call(this, this.options.routerBeforeEach, this.options.transitionEach);
        this.options.http._interceptor.call(this, this.options.requestIntercept, this.options.responseIntercept);
    }

    Auth.prototype.ready = function (cb) {
        if (cb !== undefined) {
            this.$auth.options.readyCallback = cb.bind(this);
        }

        return this.$auth.watch.loaded;
    };

    Auth.prototype.redirect = function () {
        return this.watch.redirect;
    };

    Auth.prototype.user = function (data) {
        if (data) {
            this.watch.data = data;
        }

        return this.watch.data || {};
    };

    Auth.prototype.check = function (role) {
        return this.options.check.call(this, role);
    };

    Auth.prototype.impersonating = function () {
        this.watch.data; // To fire watch

        return __token.get.call(this, this.options.tokenImpersonateName) ? true : false;
    };

    Auth.prototype.token = function (name, token) {
        if (token) {
            __token.set.call(this, name, token);
        }

        return __token.get.call(this, name);
    };

    Auth.prototype.fetch = function (data) {
        return __bindContext.call(this, 'fetch', data);
    };

    Auth.prototype.refresh = function (data) {
        return __bindContext.call(this, 'refresh', data);
    };

    Auth.prototype.register = function (data) {
        return __bindContext.call(this, 'register', data);
    };

    Auth.prototype.login = function (data) {
        return __bindContext.call(this, 'login', data);
    };

    Auth.prototype.logout = function (data) {
        return __bindContext.call(this, 'logout', data);
    };

    Auth.prototype.impersonate = function (data) {
        return __bindContext.call(this, 'impersonate', data);
    };

    Auth.prototype.unimpersonate = function (data) {
        return __bindContext.call(this, 'unimpersonate', data);
    };

    Auth.prototype.oauth2 = function (data) {
        return __bindContext.call(this, 'oauth2', data);
    }

    Auth.prototype.enableImpersonate = function () {
        if (this.impersonating()) {
            this.currentToken = null;
        }
    };

    Auth.prototype.disableImpersonate = function () {
        if (this.impersonating()) {
            this.currentToken = this.options.accessTokenName;
        }
    };

    return Auth;
};
