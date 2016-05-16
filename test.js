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

Promise.all([generateKey(), generateKey()]).then(function (keys) {
  var keyPairA = keys[0];
  var keyPairB = keys[1];
  
  return crypto.subtle.deriveBits({
    name: 'ECDH',
    namedCurve: 'P-256',
    public: keyPairA[PUBLIC_KEY]
  }, keyPairB[PRIVATE_KEY], 256);
}).then(function (bits) {
  return crypto.subtle.digest({
    name: 'SHA-256'
  }, bits);
}).then(function (hashedBits) {
  console.log("hashedBits", new Buffer(hashedBits).toString('hex'));
});
