# Node.js Nonce

Authenticate your web forms and endpoints easily and tokenize your actions to prevent CSRF.

```bash
npm install node-nonce --save
```

```javascript
const nonce = require('node-nonce').config({
    secret: 'eiwer9weriorl2342i323i4e'
});

// init
nonce.init( req, res ); // request and response (HTTP)

// create a nonce
const nonce_token = nonce.create( 'some-action' );

// verify a nonce
nonce.verify( nonce_token, 'some-action' );
```

*I am still working on this.*
