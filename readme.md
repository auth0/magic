# magic

A lightweight wrapper around the `crypto` interface to OpenSSL and the `libsodium` library to provide a standard cryptography API for internal use, consistent with best current practices recommended by the product security team at Auth0. Named not for what it is intended to do, but for [what it is intended to prevent](https://en.wikipedia.org/wiki/Magic_(cryptography)).

All public functions support both callbacks and promises (and therefore async/await), allowing easy integration into any preexisting codebase. All constructions requiring secret keys will generate them as necessary if they are not supplied, and return them for future use.

### core api

The core api implements the recommended algorithms for each cryptographic operation. When in doubt, use them.

#### magic.auth.sign | magic.verify.sign

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

Verification has a very similar interface, requiring only the additional flag if the public key is presented directly, and returning without error if the signature is valid.

```js
// supplied seed
const seed      = '0d05d0...';
const signature = '544ad1...';

// callback
magic.verify.sign(message, seed, signature, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.verify.sign(message, seed, signature)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied key
const pk        = 'bf288a...';
const signature = 'b9ca8e...';

// callback
magic.verify.sign(message, pk, signature, true, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.verify.sign(message, pk, signature, true)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.auth.mac | magic.verify.mac

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

Once again verification has a similar interface, and returns without error if the mac is valid.

```js
// supplied key
const key = '49d013...';
const mac = 'f19dc0...';

// callback
magic.verify.mac(message, key, mac, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.verify.mac(message, key, mac)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.encrypt.async | magic.decrypt.async

Implements `x25519` static Diffie-Hellman key exchange, and employs the resultant shared secret for `xsalsa20poly1305` authenticated encryption using `libsodium.js`. This allows for an efficient, simple symmetric authenticated encryption scheme to be used in an asymmetric setting. A very closely related symmetric authenticated encryption scheme (using ChaCha20-Poly1305) has been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). As a static Diffie-Hellman exchange, the API is slightly different than most asymmetric encryption schemes - for encryption both the recipient public key and sender private key are required, whereas for decryption the recipient private key and sender public key are required. Usually, only the keys of the recipient are required for encryption, though `x25519-xsalsa20poly1305` has the benefit of being an authenticated scheme as well.

```js
// key generation

// callback
magic.encrypt.async(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'x25519-xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   pk:         <Buffer d2 b2 e2 05 7a 2a ab ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.async(message)
  .then((output) => {
    console.log(output);
    // { alg:        'x25519-xsalsa20poly1305',
    //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
    //   pk:         <Buffer d2 b2 e2 05 7a 2a ab ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
    //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
  }).catch((err) => {
    return reject(err);
  });
});

// supplied key
const sk = 'd7d5dd...';
const pk = 'd2b2e2...';

// callback
magic.encrypt.async(message, sk, pk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'x25519-xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   pk:         <Buffer d2 b2 e2 05 7a 2a ab ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.async(message, sk, pk)
  .then((output) => {
    console.log(output);
    // { alg:        'x25519-xsalsa20poly1305',
    //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
    //   pk:         <Buffer d2 b2 e2 05 7a 2a ab ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
    //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
  }).catch((err) => {
    return reject(err);
  });
});
```

Decryption then returns the plaintext directly, without the metadata.

```js
const sk = 'e5e5c6...';
const pk = 'fea66a...';

// callback
magic.decrypt.async(sk, pk, ciphertext, nonce, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.decrypt.async(sk, pk, ciphertext, nonce)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.encrypt.sync | magic.decrypt.sync

Implements `xsalsa20poly1305` authenticated encryption using `libsodium.js`. A very closely related symmetric authenticated encryption scheme (using ChaCha20-Poly1305) has been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). The scheme is fast, simple, and as an AEAD construction provides each of confidentiality, authentication, and integrity on the message.

```js
// key generation

// callback
magic.encrypt.sync(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.sync(message)
  .then((output) => {
    console.log(output);
    // { alg:        'xsalsa20poly1305',
    //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
    //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
  }).catch((err) => {
    return reject(err);
  });
});

// supplied key
const sk = 'd7d5dd...';

// callback
magic.encrypt.sync(message, sk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.sync(message, sk)
  .then((output) => {
    console.log(output);
    // { alg:        'xsalsa20poly1305',
    //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
    //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
  }).catch((err) => {
    return reject(err);
  });
});
```

Decryption then returns the plaintext directly, without the metadata.

```js
const sk = 'e5e5c6...';

// callback
magic.decrypt.sync(sk, ciphertext, nonce, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.decrypt.sync(sk, ciphertext, nonce)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.util.hash

Implements `SHA2-384` (henceforth just `SHA384`) using OpenSSL through `crypto`. Unlike `SHA256` and `SHA512` - which are available through the alternative api - `SHA384` is resistant to length extension attacks, a capability which may be relevant in some circumstances. The `SHA2` family is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), and the most commonly used fast, cryptographically secure hash function.

```js
// callback
magic.util.hash(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:     'sha384',
  //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
  //   hash:    <Buffer 15 0b f9 4d e3 2b 5a  ... > }
});

// promise
magic.util.hash(message)
  .then((output) => {
    console.log(output);
    // { alg:     'sha384',
    //   payload: <Buffer 41 20 73 63 72 65 61  ... >,
    //   hash:    <Buffer 15 0b f9 4d e3 2b 5a  ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.password.hash | magic.verify.password

Implements `argon2id` password hashing using `libsodium.js`. The winner of the [Password Hashing Competition](https://password-hashing.net/) and now the [OWASP recommendation](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), `argon2id` is robust against both memory tradeoff and side-channel attacks. The output of the `argon2id` function is encoded with a prefix and other metadata, and so `output.hash` is encoded as a string, not a raw binary buffer as is normal for the rest of the `magic` api. Nor is the raw password itself returned.

```js
const pw = 'ascream...';

// callback
magic.password.hash(password, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:  'argon2id',
  //   hash: '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM' }
});

// promise
magic.password.hash(password)
  .then((output) => {
    console.log(output);
    // { alg:  'argon2id',
    //   hash: '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM' }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

Due to the metadata in the hash output, it must be provided in the same encoded format for verification.

```js
const pw   = 'ascream...';
const hash = '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM';

// callback
magic.verify.password(password, hash, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.verify.password(password, hash)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.util.rand

Employs OpenSSL through `crypto` to return the requested number of random bytes, generated in a cryptographically secure manner.

```js
// callback
magic.util.rand(length, (err, bytes) => {
  if (err) { return done(err); }
  console.log(bytes);
  // <Buffer d3 12 78 83 3a f3 32 ... >
});

// promise
magic.util.rand(length)
  .then((bytes) => {
    console.log(bytes);
    // <Buffer d3 12 78 83 3a f3 32 ... >
  })
  .catch((err) => {
    return reject(err);
});
```

#### magic.util.uid

Employs OpenSSL through `crypto` to return a base64url encoded uid. The input is not the length of the returned uid, but rather a security parameter taken as the unencoded byte length of the identifer. The returned string will be roughly a third longer than it. The default security parameter (if one is not provided) is 32 bytes, returning a uid of 43 chars.

```js
// default security parameter

// callback
magic.util.uid((err, uid) => {
  if (err) { return done(err); }
  console.log(uid);
  // 74iUE8utrO4vuR9MvdeEAZ2eVAMFch02P81uN-tlvIk
});

// promise
magic.util.uid()
  .then((uid) => {
    console.log(uid);
    // 74iUE8utrO4vuR9MvdeEAZ2eVAMFch02P81uN-tlvIk
  })
  .catch((err) => {
    return reject(err);
});

// provided security parameter length

// callback
magic.util.uid(24, (err, uid) => {
  if (err) { return done(err); }
  console.log(uid);
  // Md7Al-OnKydNF-ZsE5WBdgGVCcVIEcGu
});

// promise
magic.util.uid(24)
  .then((uid) => {
    console.log(uid);
    // Md7Al-OnKydNF-ZsE5WBdgGVCcVIEcGu
  })
  .catch((err) => {
    return reject(err);
});
```

### alt api

The alt api implements alternative algorithms for each cryptographic operation. They should only be used over the core api when required by an external specification or interoperability concerns.

#### magic.alt.auth.RSASSA\_PSS\_SHA{256,384,512} | magic.alt.verify.RSASSA\_PSS\_SHA{256,384,512}

Implements `RSA PKCS#1 v2.1` over `SHA2`, better known as `RSAPSS-SHA`. Available with each of the `SHA256`, `SHA384`, or `SHA512` variants of `SHA2`. The protocol is standardized by the [IETF](https://tools.ietf.org/html/rfc3447). The `PSS` acronym stands for probablistic signature scheme, a construction which is theoretically more robust than the older `RSA PKCS#1 v1.5` protocol also available in the alternative api. When possible, this is the preferred RSA variant, although the `ed25519` signature scheme in the core api is preferred above any use of RSA at all. For key generation, the key (private only) is returned in PEM encoding.

```js
// key generation

// callback
magic.alt.auth.RSASSA_PSS_SHA256(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:       'rsapss-sha256',
  //   sk:        '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----',
  //   payload:   <Buffer 41 20 73 63 72 65 61 ... >,
  //   signature: <Buffer 86 a8 d2 d7 67 01 8a ... > }
});

// promise
magic.alt.auth.RSASSA_PSS_SHA256(message)
  .then((output) => {
    console.log(output);
    // { alg:       'rsapss-sha256',
    //   sk:        '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----',
    //   payload:   <Buffer 41 20 73 63 72 65 61 ... >,
    //   signature: <Buffer 86 a8 d2 d7 67 01 8a ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied key
const sk = '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----';

// callback
magic.alt.auth.RSASSA_PSS_SHA256(message, sk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:       'rsapss-sha256',
  //   sk:        '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----',
  //   payload:   <Buffer 41 20 73 63 72 65 61 ... >,
  //   signature: <Buffer 86 a8 d2 d7 67 01 8a ... > }
});

// promise
magic.alt.auth.RSASSA_PSS_SHA256(message, sk)
  .then((output) => {
    console.log(output);
    // { alg:       'rsapss-sha256',
    //   sk:        '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----',
    //   payload:   <Buffer 41 20 73 63 72 65 61 ... >,
    //   signature: <Buffer 86 a8 d2 d7 67 01 8a ... > }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

Verification can be done by supplying either a private key (from which the public key will be extracted) or the public key itself.

```js
// supplied private key
const sk = '-----BEGIN RSA PRIVATE KEY-----\nMIIEp ... NZ3Yw==\n-----END RSA PRIVATE KEY-----';

// callback
magic.alt.verify.RSASSA_PSS_SHA256(message, sk, signature, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.alt.verify.RSASSA_PSS_SHA256(message, sk)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});

// supplied public key
const pk = '-----BEGIN RSA PUBLIC KEY-----\nMIIBI ... DAQAB\n-----END RSA PUBLIC KEY-----';

// callback
magic.alt.verify.RSASSA_PSS_SHA256(message, pk, signature, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.alt.verify.RSASSA_PSS_SHA256(message, pk)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.alt.auth.RSASSA\_PKCS1V1\_5\_SHA{256,384,512} | magic.alt.verify.RSASSA_PKCS1V1\_5\_SHA{256,384,512}

Implements `RSA PKCS#1 v1.5` over `SHA2`, standardized by the [IETF](https://tools.ietf.org/html/rfc2313). Available with each of the `SHA256`, `SHA384`, or `SHA512` variants of `SHA2`. An alternative to `magic.alt.verify.RSASSA_PSS_SHA{256,384,512}`.

#### magic.alt.auth.HMAC\_SHA{256,512} | magic.alt.verify.HMAC\_SHA{256,512}

Implements `HMAC-SHA2` using OpenSSL through `crypto`. Available with each of the `SHA256`, `SHA384` (as `magic.auth.mac`), or `SHA512` variants of `SHA2`. An alterative to `magic.auth.mac`.

#### magic.alt.encrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512} | magic.alt.decrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512}

Implements `AES{128,192,256}CBC-SHA2` using OpenSSL through `crypto`. Available with a large number of variants; any key size of `AES` - `AES128`, `AES192`, or `AES256`, and any digest size of `SHA2` - `SHA256`, `SHA384`, or `SHA512`. The protocol is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) and provides authenticated eencryption using the industry standard symmetric encryption and authentication schemes, in an encrypt-than-authenticate construction.

```js
// key generation

// callback
magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'aes128cbc-hmacsha256',
  //   sek:        <Buffer 61 d6 4b 6a 70 84 a0 ... >,
  //   sak:        <Buffer 03 ce db e3 d2 d4 17 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   iv:         <Buffer d4 84 14 29 ae a4 11 ... >,
  //   ciphertext: <Buffer 75 f8 cf 94 07 81 46 ... >,
  //   mac:        <Buffer a4 40 4b 6c 1b 7f d8 ... > }
});

// promise
magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message)
  .then((output) => {
    console.log(output);
    // { alg:        'aes128cbc-hmacsha256',
    //   sek:        <Buffer 61 d6 4b 6a 70 84 a0 ... >,
    //   sak:        <Buffer 03 ce db e3 d2 d4 17 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   iv:         <Buffer d4 84 14 29 ae a4 11 ... >,
    //   ciphertext: <Buffer 75 f8 cf 94 07 81 46 ... >,
    //   mac:        <Buffer a4 40 4b 6c 1b 7f d8 ... > }
  }).catch((err) => {
    return reject(err);
  });
});

// supplied key
const sek = '61d64b...';
const sak = '03cedb...';

// callback
magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, sek, sak, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'aes128cbc-hmacsha256',
  //   sek:        <Buffer 61 d6 4b 6a 70 84 a0 ... >,
  //   sak:        <Buffer 03 ce db e3 d2 d4 17 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   iv:         <Buffer d4 84 14 29 ae a4 11 ... >,
  //   ciphertext: <Buffer 75 f8 cf 94 07 81 46 ... >,
  //   mac:        <Buffer a4 40 4b 6c 1b 7f d8 ... > }
});

// promise
magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, sek, sak)
  .then((output) => {
    console.log(output);
    // { alg:        'aes128cbc-hmacsha256',
    //   sek:        <Buffer 61 d6 4b 6a 70 84 a0 ... >,
    //   sak:        <Buffer 03 ce db e3 d2 d4 17 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   iv:         <Buffer d4 84 14 29 ae a4 11 ... >,
    //   ciphertext: <Buffer 75 f8 cf 94 07 81 46 ... >,
    //   mac:        <Buffer a4 40 4b 6c 1b 7f d8 ... > }
  }).catch((err) => {
    return reject(err);
  });
});
```

Decryption then returns the plaintext directly, without the metadata.

```js
const sek = '61d64b...';
const sak = '03cedb...';

// callback
magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(sek, sak, iv, ciphertext, mac, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(sek, sak, iv, ciphertext, mac)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.alt.encrypt.AES\_{128,192,256}\_GCM | magic.alt.decrypt.AES\_{128,192,256}\_GCM

Implements `AES{128,192,256}GCM` using OpenSSL through `crypto`. AES-GCM is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) and provides authenticated encryption using the industry standard symmetric encryption scheme with an authenticated block cipher mode, a clean and simple construction.

```js
// key generation

// callback
magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'aes128gcm',
  //   sk:         <Buffer 6c 5e 93 6c a4 b8 43 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   iv:         <Buffer 8e 81 31 91 d2 a3 2c ... >,
  //   ciphertext: <Buffer 0a 37 d4 86 69 1e c9 ... >,
  //   tag:        <Buffer 72 69 d6 25 18 92 9d ... > }
});

// promise
magic.alt.encrypt.AES_128_GCM(message)
  .then((output) => {
    console.log(output);
    // { alg:        'aes128gcm',
    //   sk:         <Buffer 6c 5e 93 6c a4 b8 43 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   iv:         <Buffer 8e 81 31 91 d2 a3 2c ... >,
    //   ciphertext: <Buffer 0a 37 d4 86 69 1e c9 ... >,
    //   tag:        <Buffer 72 69 d6 25 18 92 9d ... > }
  }).catch((err) => {
    return reject(err);
  });
});

// supplied key
const sk = '6c5e93...';

// callback
magic.alt.encrypt.AES_128_GCM(message, sk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'aes128gcm',
  //   sk:         <Buffer 6c 5e 93 6c a4 b8 43 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   iv:         <Buffer 8e 81 31 91 d2 a3 2c ... >,
  //   ciphertext: <Buffer 0a 37 d4 86 69 1e c9 ... >,
  //   tag:        <Buffer 72 69 d6 25 18 92 9d ... > }
});

// promise
magic.alt.encrypt.AES_128_GCM(message, sk)
  .then((output) => {
    console.log(output);
    // { alg:        'aes128gcm',
    //   sk:         <Buffer 6c 5e 93 6c a4 b8 43 ... >,
    //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
    //   iv:         <Buffer 8e 81 31 91 d2 a3 2c ... >,
    //   ciphertext: <Buffer 0a 37 d4 86 69 1e c9 ... >,
    //   tag:        <Buffer 72 69 d6 25 18 92 9d ... > }
  }).catch((err) => {
    return reject(err);
  });
});
```

Decryption then returns the plaintext directly, without the metadata.

```js
const sk = '6c5e93...';

// callback
magic.alt.decrypt.AES_128_GCM(sk, iv, ciphertext, tag, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.alt.decrypt.AES_128_GCM(sk, iv, ciphertext, tag)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.alt.password.bcrypt | magic.alt.verify.bcrypt

Implements `bcrypt` using [node.bcrypt.js](https://github.com/kelektiv/node.bcrypt.js/), wrapping the OpenBSD implementation of the algorithm. An alterative to `magic.util.pwhash`. The security parameter (rounds) is set to 13, to bring the computational time in line with that of `magic.util.pwhash` on a development machine - they may not scale equivalently, but it provides a sensible default.

#### magic.alt.util.sha{256,512}

Implements `SHA2` using OpenSSL through `crypto`. Each of the `SHA256`, `SHA384` (as `magic.util.hash`), and `SHA512` digest length variatns are available. An alterative to `magic.util.hash`.

### Notes

&ndash; As a recommendation, `magic` should always be used with [node.js buffers](https://nodejs.org/api/buffer.html) for all (non-boolean) inputs, with the exception of passwords. Due to the variety of tasks to which it may be put, the library attempts to be as unopinionated about encoding as it is opinionated about algorithms. There is minimal decoding functionality, which will attempt to break down any plaintext input as `utf-8` and any cryptographic input (keys, ciphertexts, macs, signatures, etc.) as `hex`. If as a consumer of this library you decide to depend on this builtin decoder it is recommended that you extensively test it to make sure your inputs are being parsed appropriately. When in doubt, it is always safer to parse them yourself and pass in binary data.
