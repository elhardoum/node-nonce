'use strict';

const crypto = require('crypto');

module.exports = {
    // ref response
    res: null,
    
    // ref request
    req: null,

    // default config
    DEFAULT_CONFIG: {
        cookie_path: '/',

        CSRF_ttl: 86400, // 1 day
        CSRF_token_name: 'CSRF',

        nonce_default_ttl: 1800, // 30 min
        nonce_hash_key_prefix: 'nn',
        nonce_hash_max_length: 20,

        hashing_algo: 'sha256',
    },

    // holds the settings
    options: {},

    // private variables
    _CSRF_token: null,
    _doing_verification: null,

    // custom config
    config: function(opt)
    {
        this.options = this.extendConfig( opt, this.DEFAULT_CONFIG )

        return this;
    },

    _checkConfig: function()
    {
        if ( ! this.options.secret ) {
            throw new Error( 'Nonce error: you must set a secret key (salt) for the hashes. e.g nonce.config({secret: xyz})' )
        }

        return this;
    },

    _checkReqRes: function()
    {
        if ( ! this.req || ! this.res ) {
            throw new Error( 'Nonce error: you must pass the request and response instances with `init` method. e.g nonce.init(req, res)' )
        }

        return this;
    },

    extendConfig: function(obj, def)
    {
        for ( let k in obj ) {
            def[ k ] = obj[ k ];
        }

        return def;
    },

    // init with response and request objects
    init: function(req, res)
    {
        this._checkConfig();

        this.req = req;
        this.res = res;

        return this;
    },

    create: function(action, ttl_seconds, config)
    {
        this._checkConfig();
        this._checkReqRes();

        const options = this.extendConfig(config||{}, this.options);

        const CSRF_TOKEN = this.getOrCreateCSRFToken(options);

        let hash = this.createHash(action + CSRF_TOKEN, options);

        hash = parseInt( options.nonce_hash_max_length ) > 0 ? hash.substr( 0, parseInt( options.nonce_hash_max_length ) ) : hash;

        if ( ! this._doing_verification ) {
            // save
            this.setCookie( options.nonce_hash_key_prefix + hash, 1, parseInt(ttl_seconds) || options.nonce_default_ttl, options.cookie_path );
        }

        return hash;
    },

    verify: function(hash, action, config)
    {
        this._doing_verification = true;
        let created_hash = this.create(action, config);
        this._doing_verification = null;

        return hash === created_hash;
    },

    createHash: function(string, options)
    {
        options = options || this.options;

        return crypto.createHmac(options.hashing_algo, options.secret)
           .update(string + options.secret)
           .digest('hex');
    },

    getOrCreateCSRFToken: function(options)
    {
        options = options || this.options;

        if ( ! this._CSRF_token ) {
            if ( ! this.getCookie( options.CSRF_token_name ) ) {
                const hash = this.createHash(Math.random().toString(36).substring(2, 15)
                    + Math.random().toString(36).substring(2, 15)
                    + options.secret);

                this.setCookie( options.CSRF_token_name, hash, options.CSRF_ttl, options.cookie_path );

                this._CSRF_token = hash;
            } else {
                this._CSRF_token = this.getCookie( options.CSRF_token_name );
            }
        }

        return this._CSRF_token;
    },

    setCookie: function(name, value, expire_seconds, path) {
        let expires = '';

        if ( expire_seconds ) {
            let date = new Date;
            date.setSeconds(date.getSeconds() + expire_seconds);
            expires = '; expires=' + date.toUTCString();
        }

        let cookies = this.res.getHeader('set-cookie') || [];
        cookies = 'object' == typeof cookies ? cookies : [ cookies ];
        cookies.push( name + '=' + value + expires + ';' + ' path=' + (path||'/') + ';' );

        this.res.setHeader('Set-Cookie', cookies);
    },

    getCookie: function(name) {
        let nameEQ = name + '=';
        let ca = (this.req.headers.cookie||'').split(';');
        for(let i=0;i < ca.length;i++) {
            let c = ca[i];
            while (c.charAt(0)==' ') c = c.substring(1,c.length);
            if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
        }
        return null;
    }
}