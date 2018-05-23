var assert = require('assert')
  , mocha = require('mocha')

const nonce = require('./../index.js').config({
    secret: 'eiwer9weriorl2342i323i4e'
});

const fakeCookies = {
    // cookie jar
    all: {},

    // get a cookie
    get: function(name)
    {
        return this.all[ name ]
    },

    // set a cookie
    set: function(name, value, expires_seconds)
    {
        this.all[ name ] = value;

        if ( expires_seconds ) {
            setTimeout(() => delete this.all[ name ], parseFloat(expires_seconds) * 1000)
        }
    }
}

describe('node-nonce', () => {
    it('tests config', () =>
    {
        assert( 'eiwer9weriorl2342i323i4e' === nonce.options.secret )
    })

    it('tests fake cookies', (done) =>
    {
        // first set a cookie
        fakeCookies.set( 'test', 11, 0.1 )

        // then assert it was set
        assert( 11 == fakeCookies.get( 'test' ) )

        // now wait for it to expire and asset expiry success
        setTimeout(() => {
            assert( ! fakeCookies.get( 'test' ) )
            done()
        }, 100)
    })

    it('tests the hashes', () =>
    {
        let pre_hash = nonce.createHash( 'test' );

        // assert hash unique per salt
        assert( pre_hash !== nonce.config({secret: 'xyz'}).createHash('test') )

        // restore our salt
        nonce.config({secret: 'eiwer9weriorl2342i323i4e'})

        // one last test wouldn't hurt
        assert( pre_hash === nonce.createHash( 'test' ) )
    })

    /**
      * Overriding the default hash store functionality since
      * we're not testing with an HTTP server
      */
    nonce.setCookie = (name, value, expire_seconds) => fakeCookies.set(name, value, expire_seconds)
    nonce.getCookie = (name) => fakeCookies.get( name )
    nonce._checkReqRes = () => nonce

    it('tests the nonce creation', () =>
    {
        let hash = nonce.create('test', 1, {
            csrf_ttl: 1,
            nonce_hash_max_length: 10
        })

        // first assert a hash is returned
        assert( hash )

        // assert the hash length
        assert( hash.length === 10 )
    })

    it('tests the nonce verification', () =>
    {
        let hash = nonce.create('login-nonce', 1, {
            csrf_ttl: 1, // override the default CSRF expiration seconds
            nonce_hash_max_length: 10
        })

        // assert verification against the same action
        assert( nonce.verify( hash, 'login-nonce' ) )

        // assert error with a different action
        assert( ! nonce.verify( hash, 'logout-nonce' ) )

        // get the CSRF token
        const CSRF_token = nonce.getOrCreateCSRFToken()
        
        // assert maintaining a CSRF token for the expiration interval (1 second in our testing config)
        assert( CSRF_token == nonce.getOrCreateCSRFToken() )
    })
});