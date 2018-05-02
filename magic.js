const crypto  = require('crypto');
const sodium = require('libsodium-wrappers-sumo');


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
  if (typeof key === 'function') {
    cb  = key;
    key = null;
  }

  prep(message, cb, (err, done, payload) => {
    if (err) { return done(err); }

    let ikey;
    key = kparse(key);

    switch (Buffer.byteLength(key)) {
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
    return cb(null, done, iparse(message));
  } catch(ex) {
    return cb(ex, done);
  }
}


/***
 * iparse
 *
 * parse input strings as utf-8 into buffer
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} inp
 * @returns {Buffer}
 */
function iparse(inp) {
  if (!inp) { return Buffer.from(''); }
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
 * convert
 *
 * convert Uint8Array used by sodium into Nodejs buffers
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
