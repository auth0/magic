const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');
const { Transform } = require('stream');

const extcrypto = require('./extcrypto');


// Constants

const HASHBYTES = { sha256: 32, sha384: 48, sha512: 64 };
const AESKEYS   = [ 128, 192, 256 ];



/************************
 * Variant Constructors *
 ************************/



/***
 * rsasign
 *
 * rsa constructor
 *
 * @function
 * @api private
 *
 * @param {String} padding
 * @param {String} digest
 * @returns {Function}
 */
function rsasign(digest, padding) {

  if (Object.keys(HASHBYTES).indexOf(digest) === -1) { throw new Error('Unknown hashing algorithm'); }

  let algorithm;
  switch (padding) {
    case 'pss':
      algorithm = crypto.constants.RSA_PKCS1_PSS_PADDING;
      break;
    case 'v1_5':
      algorithm = crypto.constants.RSA_PKCS1_PADDING;
      break;
    default:
      throw new Error('Unknown padding method');
  }

  /***
   * keying
   *
   * get an rsa key
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} provided
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  function keying(provided) {
    return new Promise((resolve, reject) => {
      if (provided) { return resolve(provided); }

      extcrypto.keygen((err, sk) => {
        if (err) { return reject(err); }
        return resolve(sk);
      });
    });
  }

  /***
   * `lambda`
   *
   * sign a payload
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} sk
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, sk, cb) => {
    if (typeof sk === 'function') {
      cb = sk;
      sk = null;
    }
    const done = ret(cb);

    let payload;
    [ payload ] = iparse(message);

    return keying(sk).then((isk) => {
      if (!isk) { return done(new Error('Unable to generate key')); }

      // for pss tests, should crypto api change in the future to allow specifying salt
      //let salt;
      //if (typeof isk === 'object' && padding === crypto.constants.RSA_PKCS1_PSS_PADDING) {
      //  salt = isk.salt;
      //  isk = isk.sk;
      //}

      let signature;
      try {
        const alg  = ('rsa-' + digest).toUpperCase();
        const sign = crypto.createSign(alg);
        sign.update(message);
        sign.end();

        signature = sign.sign({ key: isk, padding: algorithm });
      } catch(ex) {
        return done(new Error('Crypto error: ' + ex));
      }

      return done(null, convert({
        alg:       'rsa' + padding + '-' + digest,
        sk:        isk,
        payload:   payload,
        signature: signature
      }));
    }).catch((err) => { return done(err); });
  }
}


/***
 * rsaverify
 *
 * rsa constructor
 *
 * @function
 * @api private
 *
 * @param {String} padding
 * @param {String} digest
 * @returns {Function}
 */
function rsaverify(digest, padding) {

  if (Object.keys(HASHBYTES).indexOf(digest) === -1) { throw new Error('Unknown hashing algorithm'); }

  let algorithm;
  switch (padding) {
    case 'pss':
      algorithm = crypto.constants.RSA_PKCS1_PSS_PADDING;
      break;
    case 'v1_5':
      algorithm = crypto.constants.RSA_PKCS1_PADDING;
      break;
    default:
      throw new Error('Unknown padding method');
  }

  /***
   * keying
   *
   * get an rsa public key, if necessary from private key
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} key
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  function keying(key) {
    return new Promise((resolve, reject) => {
      if (key.startsWith('-----BEGIN PUBLIC KEY-----'))     { return resolve(key); }
      if (key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) { return resolve(key); }

      if (!key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) { return reject(new Error('Invalid key formatting')); }

      extcrypto.extract(key, (err, pkey) => {
        if (err) { return reject(err); }
        return resolve(pkey);
      });
    });
  }

  /***
   * `lambda`
   *
   * verify a signature
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} pk
   * @param {String|Buffer} signature
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, pk, signature, cb) => {
    if (typeof pk === 'function') {
      cb = pk;
      pk = null;
    }
    const done = ret(cb);

    if (!pk) { return done(new Error('Cannot verify without a key')); }

    let payload, received, ipk;
    [ payload ]  = iparse(message);
    [ received ] = cparse(signature);

    return keying(pk).then((ipk) => {
      if (!ipk) { return done(new Error('Unable to load key')); }

      let verified;
      try {
        const alg    = ('rsa-' + digest).toUpperCase();
        const verify = crypto.createVerify(alg);
        verify.update(message);
        verify.end();

        verified = verify.verify({ key: ipk, padding: algorithm }, received);
      } catch(ex) {
        return done(new Error('Crypto error: ' + ex));
      }

      if (!verified) { return done(new Error('Invalid signature')); }

      return done();
    }).catch((err) => { return done(err); });
  }
}


/***
 * mac
 *
 * mac constructor
 *
 * @function
 * @api private
 *
 * @param {String} algorithm
 * @returns {Function}
 */
function mac(algorithm) {

  if (Object.keys(HASHBYTES).indexOf(algorithm) === -1) { throw new Error('Unknown hashing algorithm'); }

  /***
   * `lambda`
   *
   * mac a payload
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} sk
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, sk, cb) => {
    if (typeof sk === 'function') {
      cb  = sk;
      sk = null;
    }
    const done = ret(cb);

    // https://tools.ietf.org/html/rfc2104#section-3
    if (!sk) { sk = crypto.randomBytes(HASHBYTES[algorithm]); }

    let payload, isk;
    [ payload ] = iparse(message);
    [ sk ]      = cparse(sk);

    isk = sk;

    let mac;
    try {
      mac = crypto.createHmac(algorithm, isk).update(message).digest();
    } catch(ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert({
      alg:     'hmac' + algorithm,
      sk:      sk,
      payload: payload,
      mac:     mac
    }));
  }
}


/***
 * vmac
 *
 * mac verifier constructor
 *
 * @function
 * @api private
 *
 * @param {String} algorithm
 * @returns {Function}
 */
function vmac(algorithm) {

  if (Object.keys(HASHBYTES).indexOf(algorithm) === -1) { throw new Error('Unknown hashing algorithm'); }

  /***
   * `lambda`
   *
   * verify a mac
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} sk
   * @param {String|Buffer} mac
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, sk, tag, cb) => {
    const done = ret(cb);

    if (!sk) { return done(new Error('Cannot verify without a key')); }

    let payload, received, isk;
    [ payload ]      = iparse(message);
    [ sk, received ] = cparse(sk, tag);

    isk = sk;

    let mac, verified;
    try {
      mac      = crypto.createHmac(algorithm, isk).update(message).digest();
      verified = cnstcomp(mac, received);
    } catch(ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    if (!verified) { return done(new Error('Invalid mac')); }

    return done();
  }
}


/***
 * cbc
 *
 * aes-cbc-hmac encryption constructor
 *
 * @function
 * @api private
 * @param {String} digest
 * @param {String} keysize
 * @returns {Function}
 */
function cbc(digest, keysize) {

  if (Object.keys(HASHBYTES).indexOf(digest) === -1) { throw new Error('Unknown hashing algorithm'); }
  if (AESKEYS.indexOf(keysize) === -1) { throw new Error('Invalid key size'); }

  /***
   * `lambda`
   *
   * encrypt-then-authenticate a plaintext
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} ek
   * @param {String|Buffer} ak
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, ek, ak, cb) => {
    if (typeof ek === 'function') {
      cb   = ek;
      ek = null;
      ak = null;
    }
    const done = ret(cb);

    if (!!ek ^ !!ak) { return done(new Error('Requires both or neither of encryption and authentication keys')); }

    // Undocumented functionality to allow specifying iv for tests.
    let iv;
    if (ek && typeof ek === 'object' && !(ek instanceof Buffer)) {
      iv = ek.iv;
      ek = ek.key;
    }

    let payload, iek, iak;
    [ payload ]    = iparse(message);
    [ ek, ak, iv ] = cparse(ek, ak, iv);

    if (!ek) {
      ek = crypto.randomBytes(keysize / 8);
      ak = crypto.randomBytes(HASHBYTES[digest]);
    }

    iek = ek;
    iak = ak;

    let ciphertext, mac;
    try {
      iv = iv || crypto.randomBytes(16);

      const cipher = crypto.createCipheriv('aes-' + keysize + '-cbc', iek, iv);
      const hmac   = crypto.createHmac(digest, iak);

      ciphertext = Buffer.concat([ cipher.update(payload), cipher.final() ]);

      hmac.update(Buffer.concat([ iv, ciphertext ]));
      mac = hmac.digest();
    } catch (ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert({
      alg:        'aes' + keysize + 'cbc-hmac' + digest,
      sek:        ek,
      sak:        ak,
      payload:    payload,
      iv:         iv,
      ciphertext: ciphertext,
      mac:        mac
    }));
  }
}


/***
 * dcbc
 *
 * aes-cbc-hmac decryption constructor
 *
 * @function
 * @api private
 * @param {String} digest
 * @param {String} keysize
 * @returns {Function}
 */
function dcbc(digest, keysize) {

  if (Object.keys(HASHBYTES).indexOf(digest) === -1) { throw new Error('Unknown hashing algorithm'); }
  if (AESKEYS.indexOf(keysize) === -1) { throw new Error('Invalid key size'); }

  /***
   * `lambda`
   *
   * verify-then-decrypt a ciphertext
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} ek
   * @param {String|Buffer} ak
   * @param {String|Buffer} iv
   * @param {String|Buffer} ciphertext
   * @param {String|Buffer} mac
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (ek, ak, iv, ciphertext, mac, cb) => {
    const done = ret(cb);

    if (!ek || !ak) { return done(new Error('Cannot decrypt without encryption and authentication keys')); }

    let iek, iak;
    [ ek, ak, iv, ciphertext, mac ] = cparse(ek, ak, iv, ciphertext, mac);

    iek = ek;
    iak = ak;

    let plaintext;
    try {
      const cipher = crypto.createDecipheriv('aes-' + keysize + '-cbc', iek, iv);
      const hmac   = crypto.createHmac(digest, iak);

      hmac.update(Buffer.concat([ iv, ciphertext ]));
      const received = hmac.digest();

      if (!cnstcomp(received, mac)) { return done(new Error('Invalid mac')); }

      plaintext = Buffer.concat([ cipher.update(ciphertext), cipher.final() ]);
    } catch (ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert(plaintext));
  }
}


/***
 * gcm
 *
 * aes-gcm encryption constructor
 *
 * @function
 * @api private
 * @param {String} keysize
 * @returns {Function}
 */
function gcm(keysize) {

  if (AESKEYS.indexOf(keysize) === -1) { throw new Error('Invalid key size'); }

  /***
   * `lambda`
   *
   * aead encrypt a plaintext
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {String|Buffer} sk
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, sk, cb) => {
    if (typeof sk === 'function') {
      cb = sk;
      sk = null;
    }
    const done = ret(cb);

    // Undocumented functionality to allow specifying iv for tests.
    let iv;
    if (sk && typeof sk === 'object' && !(sk instanceof Buffer)) {
      iv = sk.iv;
      sk = sk.key;
    }

    let payload, isk;
    [ payload ] = iparse(message);
    [ sk, iv ]  = cparse(sk, iv);

    if (!sk) { sk = crypto.randomBytes(keysize / 8); }

    isk = sk;

    let ciphertext, tag;
    try {
      iv = iv || crypto.randomBytes(12);

      const cipher = crypto.createCipheriv('aes-' + keysize + '-gcm', sk, iv);
      ciphertext   = Buffer.concat([ cipher.update(payload), cipher.final() ]);
      tag          = cipher.getAuthTag();
    } catch (ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert({
      alg:        'aes' + keysize + 'gcm',
      sk:         sk,
      payload:    payload,
      iv:         iv,
      ciphertext: ciphertext,
      tag:        tag
    }));
  }
}


/***
 * dgcm
 *
 * aes-gcm decryption constructor
 *
 * @function
 * @api private
 * @param {String} keysize
 * @returns {Function}
 */
function dgcm(keysize) {

  if (AESKEYS.indexOf(keysize) === -1) { throw new Error('Invalid key size'); }

  /***
   * `lambda`
   *
   * aead decrypt a ciphertext
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} sk
   * @param {String|Buffer} iv
   * @param {String|Buffer} ciphertext
   * @param {String|Buffer} tag
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (sk, iv, ciphertext, tag, cb) => {
    const done = ret(cb);

    if (!sk) { return done(new Error('Cannot decrypt without a key')); }

    let isk;
    [ sk, iv, ciphertext, tag ] = cparse(sk, iv, ciphertext, tag);

    isk = sk;

    let plaintext;
    try {
      const cipher = crypto.createDecipheriv('aes-' + keysize + '-gcm', isk, iv);
      cipher.setAuthTag(tag);

      plaintext = Buffer.concat([ cipher.update(ciphertext), cipher.final() ]);
    } catch (ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert(plaintext));
  }
}


/***
 * hash
 *
 * hash constructor
 *
 * @function
 * @api private
 *
 * @param {String} algorithm
 * @returns {Function}
 */
function hash(algorithm) {

  if (Object.keys(HASHBYTES).indexOf(algorithm) === -1) { throw new Error('Unknown hashing algorithm'); }

  /***
   * `lambda`
   *
   * hash a payload
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} message
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, cb) => {
    const done = ret(cb);

    let payload;
    [ payload ] = iparse(message);

    let hash;
    try {
      hash = crypto.createHash(algorithm).update(message).digest();
    } catch(ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert({
      alg:     algorithm,
      payload: payload,
      hash:    hash
    }));
  }
}



/************
 * Core API *
 ************/



exports = module.exports  = new Object();
module.exports.auth       = new Object();
module.exports.verify     = new Object();
module.exports.encrypt    = new Object();
module.exports.decrypt    = new Object();
module.exports.password   = new Object();
module.exports.util       = new Object();
module.exports.pwdEncrypt = new Object();
module.exports.pwdDecrypt = new Object();


/***
 * auth.sign
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.auth.sign = (m, s, cb) => { return sodium.ready.then(() => { return sign(m, s, cb); } ) }
function sign(message, sk, cb) {
  if (typeof sk === 'function') {
    cb = sk;
    sk = null;
  }
  const done = ret(cb);

  let payload, isk;
  [ payload ] = iparse(message);
  [ sk ]      = cparse(sk);

  switch (sk && Buffer.byteLength(sk)) {
    case sodium.crypto_sign_SECRETKEYBYTES:
      isk = sk;
      break;
    case sodium.crypto_sign_SEEDBYTES:
      isk = sodium.crypto_sign_seed_keypair(sk).privateKey;
      break;
    default:
      isk = sodium.crypto_sign_keypair().privateKey;
      sk  = sodium.crypto_sign_ed25519_sk_to_seed(isk);
  }

  let signature;
  try {
    signature = sodium.crypto_sign_detached(payload, isk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert({
    alg:       'ed25519',
    sk:        sk,
    payload:   payload,
    signature: signature
  }));
}


/***
 * verify.sign
 *
 * verify a signature
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {String|Buffer} signature
 * @param {Boolean}       issk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.verify.sign = (m, p, s, i, cb) => { return sodium.ready.then(() => { return vsign(m, p, s, i, cb); } ) }
function vsign(message, pk, signature, ispk, cb) {
  if (typeof ispk === 'function') {
    cb   = ispk;
    ispk = false;
  }
  const done = ret(cb);

  if (!pk) { return done(new Error('Cannot verify without a key')); }

  let payload, received, ipk;
  [ payload ]      = iparse(message);
  [ pk, received ] = cparse(pk, signature);

  ipk = (ispk) ? pk : sodium.crypto_sign_seed_keypair(pk).publicKey;

  let verified;
  try {
    verified = sodium.crypto_sign_verify_detached(received, payload, ipk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  if (!verified) { return done(new Error('Invalid signature')); }

  return done();
}


/***
 * auth.mac
 *
 * mac a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.auth.mac = mac('sha384');


/***
 * verify.mac
 *
 * verify a mac
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.verify.mac = vmac('sha384');


/***
 * encrypt.pki
 *
 * symmetric authenticated encryption of a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {String|Buffer} pk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.encrypt.pki = (m, s, p, cb) => { return sodium.ready.then(() => { return async(m, s, p, cb); } ) };
function async(message, sk, pk, cb) {
  if (typeof sk === 'function') {
    cb = sk;
    sk = null;
    pk = null;
  }
  const done = ret(cb);

  if (!!sk ^ !!pk) { return done(new Error('Requires both or neither of private and public keys')); }

  // Undocumented functionality to allow specifying nonce for tests.
  let nonce;
  if (sk && typeof sk === 'object' && !(sk instanceof Buffer)) {
    nonce = sk.nonce;
    sk    = sk.key;
  }

  let payload, isk, ipk;
  [ payload ]       = iparse(message);
  [ sk, pk, nonce ] = cparse(sk, pk, nonce);

  if (!sk) {
    const keys = sodium.crypto_box_keypair();
    sk = keys.privateKey;
    pk = keys.publicKey;
  }

  isk = sk;
  ipk = pk;

  let ciphertext;
  try {
    nonce      = nonce || sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    ciphertext = sodium.crypto_box_easy(payload, nonce, ipk, isk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert({
    alg:        'x25519-xsalsa20poly1305',
    sk:         sk,
    pk:         pk,
    payload:    payload,
    nonce:      nonce,
    ciphertext: ciphertext
  }));
}


/***
 * decrypt.pki
 *
 * asymmetric authenticated decryption of a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} sk
 * @param {String|Buffer} pk
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} nonce
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.decrypt.pki = (s, p, c, n, cb) => { return sodium.ready.then(() => { return dasync(s, p, c, n, cb); } ) };
function dasync(sk, pk, ciphertext, nonce, cb) {
  const done = ret(cb);

  if (!sk || !pk) { return done(new Error('Cannot decrypt without both private and public keys')); }

  let isk, ipk;
  [ ciphertext, nonce, sk, pk ] = cparse(ciphertext, nonce, sk, pk);

  isk = sk;
  ipk = pk;

  let plaintext;
  try {
    plaintext = sodium.crypto_box_open_easy(ciphertext, nonce, ipk, isk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert(plaintext));
}


/***
 * encrypt.aead
 *
 * symmetric authenticated encryption of a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.encrypt.aead = (m, s, cb) => { return sodium.ready.then(() => { return sync(m, s, cb); } ) };
function sync(message, sk, cb) {
  if (typeof sk === 'function') {
    cb = sk;
    sk = null;
  }
  const done = ret(cb);

  // Undocumented functionality to allow specifying nonce for tests.
  let nonce;
  if (sk && typeof sk === 'object' && !(sk instanceof Buffer)) {
    nonce = sk.nonce;
    sk    = sk.key;
  }

  let payload, isk;
  [ payload ]   = iparse(message);
  [ sk, nonce ] = cparse(sk, nonce);

  if (!sk) { sk = sodium.crypto_secretbox_keygen(); }

  isk = sk;

  let ciphertext;
  try {
    nonce      = nonce || sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    ciphertext = sodium.crypto_secretbox_easy(payload, nonce, isk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert({
    alg:        'xsalsa20poly1305',
    sk:         sk,
    payload:    payload,
    nonce:      nonce,
    ciphertext: ciphertext
  }));
}


/***
 * decrypt.aead
 *
 * symmetric authenticated decryption of a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} sk
 * @param {String|Buffer} pk
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} nonce
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.decrypt.aead = (s, c, n, cb) => {
  return sodium.ready.then(() => {
    if (!s) {
      const done = ret(cb);
      return done(new Error('Cannot decrypt without a key'));
    }
    return dsync(s, c, n, cb);
  } )
};

function dsync(sk, ciphertext, nonce, cb) {
  const done = ret(cb);

  let isk;
  [ ciphertext, nonce, sk ] = cparse(ciphertext, nonce, sk);

  isk = sk;

  let plaintext;
  try {
    plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, isk);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert(plaintext));
}

module.exports.pwdDecrypt.aead = (p, c, n, cb) => {
  return sodium.ready.then(() => {
    if (typeof p === 'function') {
      cb = p;
      p = null;
    }
    const done = ret(cb);

    if (!p) { return done(new Error('Cannot decrypt without a password')); }

    let s;
    [ c ] = cparse(c);
    salt = c.slice(0, sodium.crypto_pwhash_SALTBYTES);
    try {
      s = sodium.crypto_pwhash(
        KEY_SIZE,
        p,
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT
      );
    } catch(ex) {
      return done(new Error('Libsodium error: ' +  ex))
    }
    c = c.slice(sodium.crypto_pwhash_SALTBYTES);
    return dsync(s, c, n, cb);
  })
};

module.exports.pwdEncrypt.aead = (m, p, cb) => {
  return sodium.ready.then(() => {
    if (typeof p === 'function') {
      cb = p;
      p = null;
    }
    const done = ret(cb);

    if (!p) { return done(new Error('Cannot encrypt without a password')); }
    let sk;
    const salt = crypto.randomBytes(sodium.crypto_pwhash_SALTBYTES)

    try {
      sk = sodium.crypto_pwhash(
        KEY_SIZE,
        p,
        salt,
        sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
        sodium.crypto_pwhash_ALG_DEFAULT
      );
    } catch(ex) {
      return done(new Error('Libsodium error: ' +  ex))
    }

    return sync(m, Buffer.from(sk), (err, aead) => {
      const done = ret(cb);
      if (err) {
        return err;
      }
      aead.ciphertext = Buffer.concat([salt, aead.ciphertext])
      return done(null, aead);
    })
  });
};

/***
 * password.hash
 *
 * hash a password
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} password
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.password.hash = (p, cb) => { return sodium.ready.then(() => { return pw(p, cb); } ) };
function pw(password, cb) {
  const done = ret(cb);

  if (!password) { return done(new Error('Empty password')); }

  let hash;
  try {
    // generates the salt itself
    hash = sodium.crypto_pwhash_str(password, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert({
    alg:  'argon2id',
    hash: hash
  }));
}


/***
 * verify.password
 *
 * verify a password
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} password
 * @param {String} hash
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.verify.password = (p, h, cb) => { return sodium.ready.then(() => { return pwverify(p, h, cb); } ) };
function pwverify(password, hash, cb) {
  const done = ret(cb);

  if (!password) { return done(new Error('Empty password')); }
  if (!hash) { return done(new Error('Cannot verify without stored hash')); }

  let verified;
  try {
    verified = sodium.crypto_pwhash_str_verify(hash, password);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  if (!verified) { return done(new Error('Invalid password')); }

  return done();
}


/***
 * util.hash
 *
 * hash a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.util.hash = hash('sha384');


/***
 * util.rand
 *
 * get random bytes
 *
 * @function
 * @api public
 *
 * @param {Number} length
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.util.rand = rand;
function rand(len, cb) {
  const done = ret(cb);

  if (len <= 0) { return done(new Error('Invalid length')); }

  let bytes;
  try {
    bytes = crypto.randomBytes(len);
  } catch(ex) {
    return done(new Error('Crypto error: ' + ex));
  }

  return done(null, bytes);
}


/***
 * util.uid
 *
 * get a base64url encoded uid
 *
 * @function
 * @api public
 *
 * @param {Number} sec
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.util.uid = (sec, cb) => { return sodium.ready.then(() => { return uid(sec, cb); } ) };
function uid(sec, cb) {
  if (typeof sec === 'function') {
    cb  = sec;
    sec = null;
  }
  const done = ret(cb);

  sec = sec || 32;

  return rand(sec).then((bytes) => {
    return done(null, sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING));
  }).catch((err) => { return done(err); })
}

/**
 * Provides timing safe comparisons of two strings to prevent
 * timing based attacks. Returns true if the strings are the
 * same and false if not.
 * @function
 * @api public
 * 
 * @param {string} input - The first string to check
 * @param {string} ref - The reference string to check against
 * @returns {Boolean} - true if they match, false otherwise
 */
module.exports.util.timingSafeCompare = (input, ref) => {
  inputIsString = typeof input === 'string' || input instanceof String;
  refIsString = typeof ref === 'string' || ref instanceof String;
  if (!inputIsString || !refIsString) throw new TypeError('Inputs must be Strings');
  
  let inputLength = Buffer.byteLength(input);
  let refLength = Buffer.byteLength(ref);

  /* 
  Allocate two buffers, making the input buffer the length. 
  Continue the comparison of the two buffers 
  with the length evaluation failing at the end to not give
  away the length of the reference string.  
  */
  let inputBuffer = Buffer.alloc(inputLength);
  inputBuffer.write(input);
  let refBuffer = Buffer.alloc(inputLength);

  /* 
  Write the reference string, to the size of the inputString.
  This could lead to false positives, when substrings are 
  involved but we'll catch those with a length check at the end. 
  */  
  refBuffer.write(ref);
  // check buffers and their lengths
  return cnstcomp(inputBuffer, refBuffer) && inputLength === refLength;
};


/*
 * rsaKeypairGen
 *
 * Get an RSA private/public keypair
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */

module.exports.util.rsaKeypairGen = (cb) => {
  const done  = ret(cb)

  if (crypto.generateKeyPair) { // node >= 10
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair('rsa', {
        modulusLength: 2048,
        publicExponent: 65537,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        }
      }, (err, publicKey, privateKey) => {
        return resolve(done(null, {privateKey, publicKey}));
      });
    })
  } else {
    return new Promise((resolve, reject) => {
      extcrypto.keygen((err, privateKey) => {
        if (err) { return reject(done(new Error(err.message))); }

        extcrypto.extractSPKI(privateKey, (err, publicKey) => {
          if (err) { return reject(done(new Error(err.message))); }
          return resolve(done(null, {privateKey, publicKey}));
        });
      });
    })
  }
};

/*****************
 *    Streams    *
 *****************/
/* The libsodium library expects to decrypt the stream in the same chunks it
 * encrypted it. I've set the stream chunk size in 4KB, so that libsodium
 * encrypts/decrypts stream chunks of 4KB each time except from the last one. The
 * 4KB chunk is ok for most scenarios (e.g. encrypting/decrypting files) but not
 * ideal for real time stream manipulation. Adding support for that would require
 * to store the length of each received chunk in the encrypted stream. This means
 * additional implementation work and thus is omitted for now.
 */
const STREAM_CHUNK_SIZE = exports.STREAM_CHUNK_SIZE = 4096;

/* The first byte of the encrypted stream will always indicate the version of the
 * EncryptStream. For now it's set to 1. This will allow us to modify the data we
 * store in the EncryptStream in the future and mark the change with a new
 * version.
 */
const STREAM_VERSION = 1;
const PWD_STREAM_VERSION = 1;
const KEY_SIZE = 32;

/* A lot of the initialisation in the stream implementations is deferred to run
 * during the transform phase because we need to be in an async context in
 * order to be able to use sodiium.ready.
 */


// AbstractEncryptStream format:  STREAM_VERSION | libsodium header | encrypted data

class AbstractEncryptStream extends Transform {
  constructor() {
    super();
    this.init = false;
    this.dataOffset = 0;
    this.data = Buffer.alloc(STREAM_CHUNK_SIZE);
  }

  _transform(data, encoding, callback) {
    sodium.ready.then(() => {
      if (!this.init) {
        const res = sodium.crypto_secretstream_xchacha20poly1305_init_push(this.key);
        this.state = res.state;
        this.push(Buffer.from([STREAM_VERSION]));
        this.push(res.header);
        this.init = true;
      }

      while (this.dataOffset + data.length >= STREAM_CHUNK_SIZE) {
        let dataCopied  = data.copy(this.data, this.dataOffset);

        data = data.slice(dataCopied);
        this.dataOffset = 0

        try {
          let c = sodium.crypto_secretstream_xchacha20poly1305_push(
            this.state,
            this.data,
            null,
            sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
          );
          this.push(c);
        } catch(ex) {
          return callback(new Error('Libsodium error: ' + ex));
        };
      }

      this.dataOffset += data.copy(this.data, this.dataOffset);
      return callback(null, null);
    });
  }

  _flush(callback) {
    sodium.ready.then(() => {
      try {
        let c = sodium.crypto_secretstream_xchacha20poly1305_push(
          this.state,
          this.data.slice(0, this.dataOffset),
          null,
          sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        )
        return callback(null, c);
      } catch(ex) {
        return callback(new Error('Libsodium error: ' + ex));
      }
    });
  }
}

class AbstractDecryptStream extends Transform {
  constructor() {
    super();
    this.init = false;
    this.dataOffset = 0;
    this.headerOffset = 0;
    this.header = null;
  }

  _transform(data, encoding, callback) {
    sodium.ready.then(() => {
      if (!this.init) {
        if (!this.header) {
          this.header = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + 1);
        }
        const bytesCopied = data.copy(this.header, this.headerOffset);
        this.headerOffset += bytesCopied;

        if (this.headerOffset < sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
          return callback(null, null);
        }
        if (this.header[0] !== STREAM_VERSION) {
          return callback(new Error('Unsupported version'))
        }
        this.state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(this.header.slice(1), this.key);
        this.init = true;

        this.chunkSize = STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
        this.data = Buffer.alloc(this.chunkSize);
        data = data.slice(bytesCopied);
      }

      while (this.dataOffset + data.length > this.chunkSize) {
        const dataCopied = data.copy(this.data, this.dataOffset)

        data = data.slice(dataCopied);
        this.dataOffset = 0;

        try {
          const res = sodium.crypto_secretstream_xchacha20poly1305_pull(this.state, this.data);
          if (!res) {
            return callback(new Error('Corrupted chunk'))
          }
          this.push(res.message);
        } catch(ex) {
          return callback(new Error('Libsodium error: ' + ex));
        }
      }

      this.dataOffset += data.copy(this.data, this.dataOffset);
      return callback(null, null);
    });
  }

  _flush(callback) {
    sodium.ready.then(() => {
      if (this.dataOffset) {
        try {
          const res = sodium.crypto_secretstream_xchacha20poly1305_pull(
            this.state,
            this.data.slice(0, this.dataOffset)
          )
          if (!res) {
            return callback(new Error('Corrupted chunk'))
          }
          // avoid truncation attacks
          if (res.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            return callback(new Error('Premature stream close'));
          }
          return callback(null, res.message);
        } catch(ex) {
          return callback(new Error('Libsodium error: ' + ex));
        }
      };
      return callback(null, null);
    });
  }
}


/***
 * EncryptStream
 *
 * symmetric authenticated encryption of a stream
 *
 * @api public
 *
 * @param {String|Buffer} key
 * @returns {Stream}
 */

// EncryptStream format:  AbstractEncryptStream

class EncryptStream extends AbstractEncryptStream {
  constructor(key) {
    super();
    if (key) {
      [key] = cparse(key);
      this.key = new Uint8Array(key);
    } else {
      key = crypto.randomBytes(KEY_SIZE);
      this.key = new Uint8Array(key);
    }
  }


}

module.exports.EncryptStream = EncryptStream;

/***
 * DecryptStream
 *
 * symmetric authenticated decryption of a stream
 *
 * @api public
 *
 * @param {String|Buffer} key
 * @returns {Stream}
 */
class DecryptStream extends AbstractDecryptStream {
  constructor(key) {
    super();
    if (!key) {
      throw new Error('Missing key for DecryptStream')
    }
    [key] = cparse(key);
    this.key = new Uint8Array(key);
  }
}
module.exports.DecryptStream = DecryptStream;

// PwdEncryptStream format:  PWD_STREAM_VERSION | salt | AbstractEncryptStream

module.exports.PwdEncryptStream = class PwdEncryptStream extends AbstractEncryptStream {
  constructor(pwd) {
    super();
    if (!pwd) {
      return new Error('Missing password for PwdEncryptStream');
    }
    this.pwd = pwd;
    this.key = null;
  }

  _transform(data, encoding, callback) {
    sodium.ready.then(() => {
      if (!this.key) {
        let key;
        const salt = crypto.randomBytes(sodium.crypto_pwhash_SALTBYTES)
        try {
          this.key = sodium.crypto_pwhash(
            KEY_SIZE,
            this.pwd,
            salt,
            sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_ALG_DEFAULT
          );
        } catch(ex) {
          return callback(new Error('Libsodium error: ' +  ex))
        }
        this.push(Buffer.from([PWD_STREAM_VERSION]));
        this.push(salt);
      }
      super._transform(data, encoding, callback);
    });
  };
};

module.exports.PwdDecryptStream = class PwdDecryptStream extends AbstractDecryptStream {
  constructor(pwd) {
    super();
    this.initPwd = false;
    this.pwdHeaderOffset = 0;
    this.pwdHeader = null;

    if (!pwd) {
      throw new Error('Missing password for PwdDecryptStream')
    }
    this.pwd = pwd;
    this.key = null;
  }

  _transform(data, encoding, callback) {
    sodium.ready.then(() => {
      if (!this.initPwd) {
        // Get salt from stream to re-generate key
        if (!this.pwdHeader) {
          this.pwdHeader = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES + 1);
        }

        if (!this.key) {
          const saltBytesCopied = data.copy(this.pwdHeader, this.pwdHeaderOffset);
          this.pwdHeaderOffset += saltBytesCopied;

          if (this.pwdHeaderOffset < sodium.crypto_pwhash_SALTBYTES) {
            return callback(null, null);
          }
          if (this.pwdHeader[0] !== PWD_STREAM_VERSION) {
            return callback(new Error('Unsupported PwdEncryptionStream version'));
          }

          this.key = sodium.crypto_pwhash(
            KEY_SIZE,
            this.pwd,
            this.pwdHeader.slice(1),
            sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_ALG_DEFAULT
          );
          this.initPwd = true;
          data = data.slice(saltBytesCopied);
        }
      }
      super._transform(data, encoding, callback);
    });
  }
}

/*****************
 * Alternate API *
 *****************/



module.exports.alt          = new Object();
module.exports.alt.auth     = new Object();
module.exports.alt.verify   = new Object();
module.exports.alt.encrypt  = new Object();
module.exports.alt.decrypt  = new Object();
module.exports.alt.password = new Object();
module.exports.alt.util     = new Object();


/***
 * alt.auth.RSASSA_PSS_SHA256
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PSS_SHA256 = rsasign('sha256', 'pss');


/***
 * alt.verify.RSASSA_PSS_SHA256
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PSS_SHA256 = rsaverify('sha256', 'pss');


/***
 * alt.auth.RSASSA_PSS_SHA384
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PSS_SHA384 = rsasign('sha384', 'pss');


/***
 * alt.verify.RSASSA_PSS_SHA384
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PSS_SHA384 = rsaverify('sha384', 'pss');


/***
 * alt.auth.RSASSA_PSS_SHA512
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PSS_SHA512 = rsasign('sha512', 'pss');


/***
 * alt.verify.RSASSA_PSS_SHA512
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PSS_SHA512 = rsaverify('sha512', 'pss');


/***
 * alt.auth.RSASSA_PKCS1V1_5_SHA256
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PKCS1V1_5_SHA256 = rsasign('sha256', 'v1_5');


/***
 * alt.verify.RSASSA_PKCS1V1_5_SHA256
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PKCS1V1_5_SHA256 = rsaverify('sha256', 'v1_5');


/***
 * alt.auth.RSASSA_PKCS1V1_5_SHA384
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PKCS1V1_5_SHA384 = rsasign('sha384', 'v1_5');


/***
 * alt.verify.RSASSA_PKCS1V1_5_SHA384
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PKCS1V1_5_SHA384 = rsaverify('sha384', 'v1_5');


/***
 * alt.auth.RSASSA_PKCS1V1_5_SHA512
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.RSASSA_PKCS1V1_5_SHA512 = rsasign('sha512', 'v1_5');


/***
 * alt.verify.RSASSA_PKCS1V1_5_SHA512
 *
 * verify a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} pk
 * @param {String|Buffer} signature
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.RSASSA_PKCS1V1_5_SHA512 = rsaverify('sha512', 'v1_5');


/***
 * alt.auth.HMAC_SHA256
 *
 * mac a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.HMAC_SHA256 = mac('sha256');


/***
 * alt.verify.HMAC_SHA256
 *
 * verify a mac
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.HMAC_SHA256 = vmac('sha256');


/***
 * alt.auth.HMAC_SHA512
 *
 * mac a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.HMAC_SHA512 = mac('sha512');


/***
 * alt.verify.HMAC_SHA512
 *
 * verify a mac
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.HMAC_SHA512 = vmac('sha512');


/***
 * alt.encrypt.AES_128_CBC_HMAC_SHA256
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_128_CBC_HMAC_SHA256 = cbc('sha256', 128);


/***
 * alt.decrypt.AES_128_CBC_HMAC_SHA256
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_128_CBC_HMAC_SHA256 = dcbc('sha256', 128);


/***
 * alt.encrypt.AES_128_CBC_HMAC_SHA384
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_128_CBC_HMAC_SHA384 = cbc('sha384', 128);


/***
 * alt.decrypt.AES_128_CBC_HMAC_SHA384
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_128_CBC_HMAC_SHA384 = dcbc('sha384', 128);


/***
 * alt.encrypt.AES_128_CBC_HMAC_SHA512
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_128_CBC_HMAC_SHA512 = cbc('sha512', 128);


/***
 * alt.decrypt.AES_128_CBC_HMAC_SHA512
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_128_CBC_HMAC_SHA512 = dcbc('sha512', 128);


/***
 * alt.encrypt.AES_192_CBC_HMAC_SHA256
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_192_CBC_HMAC_SHA256 = cbc('sha256', 192);


/***
 * alt.decrypt.AES_192_CBC_HMAC_SHA256
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_192_CBC_HMAC_SHA256 = dcbc('sha256', 192);


/***
 * alt.encrypt.AES_192_CBC_HMAC_SHA384
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_192_CBC_HMAC_SHA384 = cbc('sha384', 192);


/***
 * alt.decrypt.AES_192_CBC_HMAC_SHA384
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_192_CBC_HMAC_SHA384 = dcbc('sha384', 192);


/***
 * alt.encrypt.AES_192_CBC_HMAC_SHA512
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_192_CBC_HMAC_SHA512 = cbc('sha512', 192);


/***
 * alt.decrypt.AES_192_CBC_HMAC_SHA512
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_192_CBC_HMAC_SHA512 = dcbc('sha512', 192);


/***
 * alt.encrypt.AES_256_CBC_HMAC_SHA256
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_256_CBC_HMAC_SHA256 = cbc('sha256', 256);


/***
 * alt.decrypt.AES_256_CBC_HMAC_SHA256
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_256_CBC_HMAC_SHA256 = dcbc('sha256', 256);


/***
 * alt.encrypt.AES_256_CBC_HMAC_SHA384
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_256_CBC_HMAC_SHA384 = cbc('sha384', 256);


/***
 * alt.decrypt.AES_256_CBC_HMAC_SHA384
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_256_CBC_HMAC_SHA384 = dcbc('sha384', 256);


/***
 * alt.encrypt.AES_256_CBC_HMAC_SHA512
 *
 * encrypt-then-authenticate a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_256_CBC_HMAC_SHA512 = cbc('sha512', 256);


/***
 * alt.decrypt.AES_256_CBC_HMAC_SHA512
 *
 * verify-then-decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} ek
 * @param {String|Buffer} ak
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_256_CBC_HMAC_SHA512 = dcbc('sha512', 256);


/***
 * alt.encrypt.AES_128_GCM
 *
 * aead encrypt a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_128_GCM = gcm(128);


/***
 * alt.decrypt.AES_128_GCM
 *
 * aead decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} sk
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_128_GCM = dgcm(128);


/***
 * alt.encrypt.AES_192_GCM
 *
 * aead encrypt a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_192_GCM = gcm(192);


/***
 * alt.decrypt.AES_192_GCM
 *
 * aead decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} sk
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_192_GCM = dgcm(192);


/***
 * alt.encrypt.AES_256_GCM
 *
 * aead encrypt a plaintext
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} sk
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.encrypt.AES_256_GCM = gcm(256);


/***
 * alt.decrypt.AES_256_GCM
 *
 * aead decrypt a ciphertext
 *
 * @function
 * @api pubic
 *
 * @param {String|Buffer} sk
 * @param {String|Buffer} iv
 * @param {String|Buffer} ciphertext
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.decrypt.AES_256_GCM = dgcm(256);


/***
 * alt.password.bcrypt
 *
 * hash a password
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} password
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.password.bcrypt = hbcrypt;
function hbcrypt(password, cb) {
  const done = ret(cb);

  if (!password) { return done(new Error('Empty password')); }

  return bcrypt.hash(password, 10)
    .then((hash) => {
      return done(null, convert({
        alg:  'bcrypt',
        hash: hash
      }));
    }).catch((ex) => {
      return done(new Error('Bcrypt error: ' + ex));
    });
}


/***
 * alt.verify.bcrypt
 *
 * verify a password
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} password
 * @param {String} hash
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.bcrypt = vbcrypt;
function vbcrypt(password, hash, cb) {
  const done = ret(cb);

  if (!password) { return done(new Error('Empty password')); }
  if (!hash) { return done(new Error('Cannot verify without stored hash')); }

  return bcrypt.compare(password, hash)
    .then((verified) => {
      if (!verified) { return done(new Error('Invalid password')); }
      return done();
    }).catch((ex) => {
      return done(new Error('Bcrypt error: ' + ex));
    });
}


/***
 * alt.util.sha256
 *
 * hash a payload
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} message
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.util.sha256 = hash('sha256');


/***
 * alt.util.sha512
 *
 * hash a payload
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} message
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.util.sha512 = hash('sha512');



/*************
 * Utilities *
 *************/



/***
 * cnstcomp
 *
 * constant time comparsion
 *
 * @function
 * @api private
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */
function cnstcomp(a, b) {
  if (!(a instanceof Buffer && b instanceof Buffer)) { throw new TypeError('Inputs must be buffers'); }

  // use builtin if available
  if ('timingSafeEqual' in crypto) { return crypto.timingSafeEqual(a, b); }

  // fallback on sodium
  return sodium.compare(a, b) === 0;
}



/***
 * iparse
 *
 * parse input strings as utf-8 into buffers
 *
 * @function
 * @api private
 *
 * @returns {Buffer}
 */
function iparse() {
  return [ ...arguments ].map((inp) => {
    if (!inp) { return Buffer.from(''); }
    return (inp instanceof Buffer) ? inp : Buffer.from(inp, 'utf-8');
  });
}


/***
 * cparse
 *
 * parse keying and other cryptographic material into buffers
 *
 * @function
 * @api private
 *
 * @returns {Buffer}
 */
function cparse() {
  return [ ...arguments ].map((inp) => {
    if (!inp) { return; }
    return (inp instanceof Buffer) ? inp : Buffer.from(inp, 'hex');
  });
}


/***
 * convert
 *
 * convert Uint8Array used by sodium into nodejs buffers
 *
 * @function
 * @api private
 *
 * @param {Uint8Array|Object} out
 * @returns {Object}
 */
function convert(out) {
  if (out instanceof Uint8Array) { return Buffer.from(out); }

  Object.keys(out).forEach((k) => { if (out[k] instanceof Uint8Array) out[k] = Buffer.from(out[k]); });
  return out;
}


/***
 * ret
 *
 * callback wrapping
 *
 * @function
 * @api private
 *
 * @param {Function} callback
 * @returns {Function}
 */
function ret(callback) {
  const promisify = !(callback && typeof callback === 'function');

  /***
   * `lambda`
   *
   * execute callback if available, else promise
   *
   * @function
   * @api private
   */
  return function() {
    const args = [ ...arguments ];
    if (!promisify) { return callback.apply(this, args); }

    return new Promise((resolve, reject) => {
      const err = args.shift();
      if (err) { return reject(err); }

      return resolve.apply(this, args);
    });
  }
}
