module.exports = {
    
    request: function (req, token) {
        this.options.http._setHeaders.call(this, req, {Authorization: 'Bearer ' + token});
    },
    
    response: function (res) {
        /**
         * TODO: Further investigation about the tokens must be implemented
         * Laravel responses expires_in in seconds. Because it is useless
         * unless you keep the timestamp of tokens response, we convert it into
         * expire date by converting to miliseconds first then adding to now timestamp
         */

        let accessToken = res.data.access_token,
            refreshToken = res.data.refresh_token,
            tokenExpireDate = res.data.expires_in + ( res.data.expires_in * 1000 ) + Date.now();

        /**
         * TODO: Again, do more checks for the tokens!
         */

        if (accessToken) {
            return {
                accessToken, refreshToken, tokenExpireDate
            };
        }
    }
};