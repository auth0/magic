# magic

A lightweight wrapper around the `crypto` interface to OpenSSL and the `libsodium` library to provide a standard cryptography API for internal use, consistent with [best current practices](https://auth0team.atlassian.net/wiki/spaces/AUTHSEC/pages/30998532/Cryptography) of the product security team.

All public functions support both callbacks and promises (and therefore async/await), allowing easy integration into any preexisting codebase. All constructions requiring secret keys will generate them as necessary if they are not supplied, and return them for future use.

### core api

The core api implements the recommended algorithms for each cryptographic operation. When in doubt, use them.

##### magic.auth.sign | magic.verify.sign

Implements `ed25519` signatures using `libsodium.js`. Efficient and without some of the concerns inherent in `ECDSA`, `ed25519` has been accepted and standardized by the [IETF](https://tools.ietf.org/html/rfc8032). By default, the api expects to be given a secret key as a seed, from which the actual keypair is derived (allowing easier, more concise storage). However, it may be used directly with a keypair, requiring only a boolean flag for the `verify` call.

```js
// seed generation

// callback
magic.auth.sign(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:       'ed25519',
  //   sk:        <Buffer af b4 b8 a8 2f 59 cb  ... >,
  //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
  //   signature: <Buffer e5 b7 ce 0e 92 71 0c  ... > }
});

// promise
magic.auth.sign(message)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
    // { alg:       'ed25519',
    //   sk:        <Buffer af b4 b8 a8 2f 59 cb  ... >,
    //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
    //   signature: <Buffer e5 b7 ce 0e 92 71 0c  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied seed
const seed = '0d05d0...';

// callback
magic.auth.sign(message, seed, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:       'ed25519',
  //   sk:        <Buffer 0d 05 d0 99 d3 2d 00  ... >,
  //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
  //   signature: <Buffer 54 4a d1 ab a9 c7 19  ... > }
});

// promise
magic.auth.sign(message, seed)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
    // { alg:       'ed25519',
    //   sk:        <Buffer 0d 05 d0 99 d3 2d 00  ... >,
    //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
    //   signature: <Buffer 54 4a d1 ab a9 c7 19  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied key
const sk = 'bf288a...';

// callback
magic.auth.sign(message, sk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:       'ed25519',
  //   sk:        <Buffer bf 28 8a 58 28 36 37  ... >,
  //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
  //   signature: <Buffer b9 ca 8e 69 12 34 35  ... > }
});

// promise
magic.auth.sign(message, sk)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
   // { alg:       'ed25519',
   //   sk:        <Buffer bf 28 8a 58 28 36 37  ... >,
   //   payload:   <Buffer 41 20 73 63 72 65 61  ... >,
   //   signature: <Buffer b9 ca 8e 69 12 34 35  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

Verification has a very similar interface, requiring only the additional flag if the public key is presented directly, and returning a boolean as to whether the signature verifies.

```js
// supplied seed
const seed      = '0d05d0...';
const signature = '544ad1...';

// callback
magic.verify.sign(message, seed, signature, (err, verified) => {
  if (err) { return cb(err); }
  console.log(verified);
  // true
});

// promise
magic.verify.sign(message, seed, signature)
  .then((verified) => {
    if (err) { return cb(err); }
    console.log(verified);
    // true
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied key
const pk        = 'bf288a...';
const signature = 'b9ca8e...';

// callback
magic.verify.sign(message, pk, signature, true, (err, verified) => {
  if (err) { return cb(err); }
  console.log(verified);
  // true
});

// promise
magic.verify.sign(message, pk, signature, true)
  .then((verified) => {
    if (err) { return cb(err); }
    console.log(verified);
   // true
  })
  .catch((err) => {
    return reject(err);
  });
});
```

##### magic.auth.mac | magic.verify.mac

Implements `HMAC-SHA384` using OpenSSL through `crypto`. The `HMAC` algorithm is the most common message authentication code construction, standardized by the [IETF](https://tools.ietf.org/html/rfc2104) and [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf). The choice of `SHA384` is due to its widespread availability and to provide a consistent hash function throughout `magic`, as `SHA256` may be susceptible to length extension attacks in certain situations. Both `HMAC-SHA256` and `HMAC-SHA512` are available in the alternative api.

```js
// key generation

// callback
magic.auth.mac(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:     'hmacsha384',
  //   sk:      <Buffer 97 9b 18 78 50 6f bf  ... >,
  //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
  //   mac:     <Buffer 2d 15 ab 58 08 9a d7  ... > }
});

// promise
magic.auth.mac(message)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
    // { alg:     'hmacsha384',
    //   sk:      <Buffer 97 9b 18 78 50 6f bf  ... >,
    //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
    //   mac:     <Buffer 2d 15 ab 58 08 9a d7  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied key
const key = '49d013...';

// callback
magic.auth.mac(message, key, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:     'hmacsha384',
  //   sk:      <Buffer 49 d0 13 6e 72 15 f4  ... >,
  //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
  //   mac:     <Buffer f1 9d c0 5a ae 8a f1  ... > }
});

// promise
magic.auth.mac(message, key)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
    // { alg:     'hmacsha384',
    //   sk:      <Buffer 49 d0 13 6e 72 15 f4  ... >,
    //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
    //   mac:     <Buffer f1 9d c0 5a ae 8a f1  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

Once again verification has a similar interface, and returns a boolean denoting whether verification has succeeded.

```js
// supplied key
const key = '49d013...';
const mac = 'f19dc0...';

// callback
magic.verify.mac(message, key, mac, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // true
});

// promise
magic.verify.mac(message, key, mac)
  .then((output) => {
    if (err) { return cb(err); }
    console.log(output);
    // true
  })
  .catch((err) => {
    return reject(err);
  });
});
```

### alt api

The alt api implements alternative algorithms for each cryptographic operation. They should only be used over the core api when required by an external specification or interoperability concerns.

##### magic.alt.auth.hmacsha256 | magic.alt.verify.hmacsha256

Implements `HMAC-SHA256` using OpenSSL through `crypto`. An alterative to `magic.auth.mac`.

##### magic.alt.auth.hmacsha512 | magic.alt.verify.hmacsha512

Implements `HMAC-SHA512` using OpenSSL through `crypto`. An alterative to `magic.auth.mac`.
