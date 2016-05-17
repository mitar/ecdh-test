var Promise = require('promise-polyfill');
var WebCrypto = require('node-webcrypto-ossl').default;

var crypto = new WebCrypto();

var PRIVATE_KEY = 0;
var PUBLIC_KEY = 1;

function generateKey() {
  return crypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-256'
  }, true, ['deriveKey', 'deriveBits']).then(function (keyPair) {
    return Promise.all([
      crypto.subtle.exportKey('pkcs8', keyPair.privateKey),
      crypto.subtle.exportKey('spki', keyPair.publicKey)
    ]);
  }).then(function (exportedKeys) {
    return Promise.all([
      crypto.subtle.importKey('pkcs8', exportedKeys[PRIVATE_KEY], {
        name: 'ECDH',
        namedCurve: 'P-256'
      }, false, ['deriveKey', 'deriveBits']),
      crypto.subtle.importKey('spki', exportedKeys[PUBLIC_KEY], {
        name: 'ECDH',
        namedCurve: 'P-256'
      }, false, [])
    ]);
  });
}

function publicKey() {
  var content = new Buffer('3059301306072a8648ce3d020106082a8648ce3d030107034200047a9f5058422c18043bcb3df3ea56b513a533cfe4c2c3fa489a8606bff6a6677d9a9eb0505fcc8011a329013f96b3646a438ea4e55343a0d3b8fdf60c954c36e5', 'hex');

  return crypto.subtle.importKey('spki', content, {
    name: 'ECDH',
    namedCurve: 'P-256'
  }, false, [])
}

Promise.all([publicKey(), generateKey()]).then(function (keys) {
  var keyPairA = keys[0];
  var keyPairB = keys[1];

  return crypto.subtle.deriveBits({
    name: 'ECDH',
    namedCurve: 'P-256',
    public: keyPairA
  }, keyPairB[PRIVATE_KEY], 256);
}).then(function (bits) {
  return crypto.subtle.digest({
    name: 'SHA-256'
  }, bits);
}).then(function (hashedBits) {
  console.log("hashedBits", new Buffer(hashedBits).toString('hex'));
}).catch(function (error) {
  console.log("error", error);
});
