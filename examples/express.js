const express = require('express')
const app = express()
const bodyParser = require('body-parser')

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true})) 

const nonce = require('./../index.js').config({
    secret: 'eiwer9weriorl2342i323i4e',
    cookie_path: '/'
});

app.get('/', function (req, res) {
  const nonce_token = nonce.init(req, res).create('test-nonce', 120);

  res.send('<form method="post">'
    + '<input type="text" name="first_name" placeholder="First name" />'
    + '<button type="submit">Submit</button>'
    + '<input type="hidden" name="nonce" value="' + nonce_token + '" />'
    + '</form>')
})

app.post('/', function (req, res) {
  if ( ! req.body.nonce || ! nonce.init(req, res).verify( req.body.nonce, 'test-nonce' ) ) {
    return res.send( 'Whyyy!!!', 403 );
  }

  res.send('Hello, ' + req.body.first_name + '!') // !! escape HTML on prod
})

app.listen(3000, () => console.log('Example app listening on port 3000!'))