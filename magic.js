const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');


// Constants

const HASHBYTES = { sha256: 32, sha384: 48, sha512: 64 };



/************************
 * Variant Constructors *
 ************************/



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
   * @param {String|Buffer} key
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, key, cb) => {
    if (typeof key === 'function') {
      cb  = key;
      key = null;
    }
    const done = ret(cb);

    // https://tools.ietf.org/html/rfc2104#section-3
    if (!key) { key = crypto.randomBytes(HASHBYTES[algorithm]); }

    let payload, ikey;
    [ payload ] = iparse(message);
    [ key ]     = cparse(key);

    ikey = key;

    let mac;
    try {
      mac = crypto.createHmac(algorithm, ikey).update(message).digest();
    } catch(ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, convert({
      alg:     'hmac' + algorithm,
      sk:      key,
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
   * @param {String|Buffer} key
   * @param {String|Buffer} mac
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  return (message, key, tag, cb) => {
    const done = ret(cb);

    if (!key) { return done(new Error('Cannot verify without a key')); }

    let payload, ikey;
    [ payload ]       = iparse(message);
    [ key, received ] = cparse(key, tag);

    ikey = key;

    let mac, verified;
    try {
      mac      = crypto.createHmac(algorithm, ikey).update(message).digest();
      verified = cnstcomp(mac, received);
    } catch(ex) {
      return done(new Error('Crypto error: ' + ex));
    }

    return done(null, verified);
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
 * @param {String|Buffer} key
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.auth.sign = sign;
function sign(message, key, cb) {
  if (typeof key === 'function') {
    cb  = key;
    key = null;
  }
  const done = ret(cb);

  let payload, ikey;
  [ payload ] = iparse(message);
  [ key ]     = cparse(key);

  switch (key && Buffer.byteLength(key)) {
    case sodium.crypto_sign_SECRETKEYBYTES:
      ikey = key;
      break;
    case sodium.crypto_sign_SEEDBYTES:
      ikey = sodium.crypto_sign_seed_keypair(key).privateKey;
      break;
    default:
      ikey = sodium.crypto_sign_keypair().privateKey;
      key  = sodium.crypto_sign_ed25519_sk_to_seed(ikey);
  }

  let signature;
  try {
    signature = sodium.crypto_sign_detached(payload, ikey);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, convert({
    alg:       'ed25519',
    sk:        key,
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
 * @param {String|Buffer} key
 * @param {String|Buffer} signature
 * @param {Boolean}       iskey
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.verify.sign = vsign;
function vsign(message, key, signature, iskey, cb) {
  if (typeof iskey === 'function') {
    cb    = iskey;
    iskey = false;
  }
  const done = ret(cb);

  if (!key) { return done(new Error('Cannot verify without a key')); }

  let payload, ikey;
  [ payload ]       = iparse(message);
  [ key, received ] = cparse(key, signature);

  ikey = (iskey) ? key : sodium.crypto_sign_seed_keypair(key).publicKey;

  let verified;
  try {
    verified = sodium.crypto_sign_verify_detached(received, payload, ikey);
  } catch(ex) {
    return done(new Error('Libsodium error: ' + ex));
  }

  return done(null, verified);
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
 * @param {String|Buffer} key
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
 * @param {String|Buffer} key
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.verify.mac = vmac('sha384');


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
 * util.pwhash
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
module.exports.util.pwhash = pwhash;
function pwhash(password, cb) {
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
 * util.pwverify
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
module.exports.util.pwverify = pwverify;
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

  return done(null, verified);
}


/***
 * util.rand
 *
 * get random bytes
 *
 * @function
 * @api public
 *
 * @param {Number} length
 * @param {String} hash
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



/*****************
 * Alternate API *
 *****************/



module.exports.alt         = new Object();
module.exports.alt.auth    = new Object();
module.exports.alt.verify  = new Object();
module.exports.alt.encrypt = new Object();
module.exports.alt.decrypt = new Object();
module.exports.alt.util    = new Object();


/***
 * alt.auth.hmacsha256
 *
 * mac a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} key
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.hmacsha256 = mac('sha256');


/***
 * alt.verify.hmacsha256
 *
 * verify a mac
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} key
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.hmacsha256 = vmac('sha256');


/***
 * alt.auth.hmacsha512
 *
 * mac a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} key
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.auth.hmacsha512 = mac('sha512');


/***
 * alt.verify.hmacsha512
 *
 * verify a mac
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} message
 * @param {String|Buffer} key
 * @param {String|Buffer} mac
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.alt.verify.hmacsha512 = vmac('sha512');


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
 * @param {Object} out
 * @returns {Object}
 */
function convert(out) {
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
