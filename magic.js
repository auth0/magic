const crypto = require('crypto');
const sodium = require('libsodium-wrappers');


exports = module.exports = new Object();


/***
 * sign
 *
 * sign a payload
 *
 * @function
 * @api public
 *
 * @param {String|Buffer|Object} message
 * @param {String|Buffer} key
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
module.exports.sign = sign;
function sign(message, key, cb) {
  prep(message, cb, (err, done, payload) => {
    if (err) { return done(err); }

    key = kparse(key);
    switch (Buffer.byteLength(key)) {
      case sodium.crypto_sign_SECRETKEYBYTES:
        key = key;
      case sodium.crypto_sign_SEEDBYTES:
        key = sodium.crypto_sign_seed_keypair(key).privateKey;
      default:
        key = sodium.crypto_sign_keypair().privateKey;
    }

    try {
      const signature = sodium.crypto_sign(payload, key);
    } catch(ex) {
      return done(new Error('Libsodium error: ' + ex));
    }

    return done(null, {
      sk:        key,
      payload:   payload,
      signature: signature
    });
  });
}



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
 * prep
 *
 * preparations for cryptographic operations
 *
 * @function
 * @api private
 *
 * @param {String|Buffer|Object} message
 * @param {Function} _cb
 * @param {Function} cb
 *
 * @returns {Callback}
 */
function prep(message, _cb, cb) {
  const done = ret(_cb);

  try {
    return cb(null, done, parse(message));
  } catch(ex) {
    return cb(ex, done);
  }
}


/***
 * parse
 *
 * parse strings as utf-8 into buffer
 *
 * @function
 * @api private
 *
 * @param {String|Buffer|Object} inp
 * @returns {Buffer}
 */
function parse(inp) {
  if (!inp) { return Buffer.from(''); }
  if (typeof inp === 'object') { return Buffer.from(JSON.stringify(inp), 'utf-8'); }

  return (inp instanceof Buffer) ? inp : Buffer.from(inp, 'utf-8');
}


/***
 * kparse
 *
 * parse key material into buffer
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} key
 * @returns {Buffer}
 */
function kparse(inp) {
  if (!inp) { return; }

  return (inp instanceof Buffer) ? inp : Buffer.from(inp, 'hex');
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
