const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');

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



exports = module.exports = new Object();
module.exports.auth      = new Object();
module.exports.verify    = new Object();
module.exports.encrypt   = new Object();
module.exports.decrypt   = new Object();
module.exports.password  = new Object();
module.exports.util      = new Object();


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
 * encrypt.async
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
module.exports.encrypt.async = (m, s, p, cb) => { return sodium.ready.then(() => { return async(m, s, p, cb); } ) };
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
 * decrypt.async
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
module.exports.decrypt.async = (s, p, c, n, cb) => { return sodium.ready.then(() => { return dasync(s, p, c, n, cb); } ) };
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
 * encrypt.sync
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
module.exports.encrypt.sync = (m, s, cb) => { return sodium.ready.then(() => { return sync(m, s, cb); } ) };
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
 * decrypt.sync
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
module.exports.decrypt.sync = (s, c, n, cb) => { return sodium.ready.then(() => { return dsync(s, c, n, cb); } ) };;
function dsync(sk, ciphertext, nonce, cb) {
  const done = ret(cb);

  if (!sk) { return done(new Error('Cannot decrypt without a key')); }

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
module.exports.util.uid = uid;
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
