# magic

A lightweight wrapper around the `crypto` interface to OpenSSL and the `libsodium` library to provide a standard cryptography API for internal use, consistent with [best current practices](https://auth0team.atlassian.net/wiki/spaces/AUTHSEC/pages/30998532/Cryptography) of the product security team.

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
    console.log(verified);
    // true
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
    console.log(output);
    // true
  })
  .catch((err) => {
    return reject(err);
  });
});
```

#### magic.encrypt.async | magic.decrypt.async

Implements `x25519` static Diffie-Hellman key exchange, and employs the resultant shared secret for `xsalsa20poly1305` authenticated encryption using `libsodium.js`. This allows for an efficient, simple symmetric authenticated encryption scheme to be used in an asymmetric setting. A very closely related symmetric authenticated encryption scheme (using ChaCha20-Poly1305) has been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). As a static Diffie-Hellman exchange, the API is slightly different than most asymmetric encryption schemes - for encryption both the recipient public key and sender private key are required, whereas for decryption the recipient private key and sender public key are required. Usually, only the keys are the recipient are required for encryption, though `x25519-xsalsa20-poly1305` has the benefit of being an authenticated scheme as well.

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

#### magic.util.pwhash | magic.util.pwverify

Implements `argon2id` password hashing using `libsodium.js`. The winner of the [Password Hashing Competition](https://password-hashing.net/) and now the [OWASP recommendation](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), `argon2id` is robust against both memory tradeoff and side-channel attacks. The output of the `argon2id` function is encoded with a prefix and other metadata, and so `output.hash` is encoded as a string, not a raw binary buffer as is normal for the rest of the `magic` api. Nor is the raw password itself returned.

```js
const pw = 'ascream...';

// callback
magic.util.pwhash(password, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:  'argon2id',
  //   hash: '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM' }
});

// promise
magic.util.pwhash(password)
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
magic.util.pwverify(password, hash, (err, verified) => {
  if (err) { return cb(err); }
  console.log(verified);
  // true
});

// promise
magic.util.pwverify(password, hash)
  .then((verified) => {
    console.log(verified);
    // true
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

#### magic.alt.auth.hmacsha256 | magic.alt.verify.hmacsha256

Implements `HMAC-SHA256` using OpenSSL through `crypto`. An alterative to `magic.auth.mac`.

#### magic.alt.auth.hmacsha512 | magic.alt.verify.hmacsha512

Implements `HMAC-SHA512` using OpenSSL through `crypto`. An alterative to `magic.auth.mac`.

#### magic.alt.encrypt.aes128cbc_hmacsha256 | magic.alt.decrypt.aes128cbc_hmacsha256

Implements `AES128CBC-SHA256` using OpenSSL through `crypto`. AES-CBC is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) and provides authenticated eencryption using the industry standard symmetric encryption and authentication schemes, in an encrypt-than-authenticate construction.

```js
// key generation

// callback
magic.alt.encrypt.aes128cbc_hmacsha256(message, (err, output) => {
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
magic.alt.encrypt.aes128cbc_hmacsha256(message)
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
magic.alt.encrypt.aes128cbc_hmacsha256(message, sek, sak, (err, output) => {
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
magic.alt.encrypt.aes128cbc_hmacsha256(message, sek, sak)
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
magic.alt.decrypt.aes128cbc_hmacsha256(sek, sak, iv, ciphertext, mac, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.alt.decrypt.aes128cbc_hmacsha256(sek, sak, iv, ciphertext, mac)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.alt.encrypt.aes128cbc_hmacsha384 | magic.alt.decrypt.aes128cbc_hmacsha384

Implements `AES128CBC-SHA384` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes128cbc_hmacsha512 | magic.alt.decrypt.aes128cbc_hmacsha512

Implements `AES128CBC-SHA512` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes192cbc_hmacsha256 | magic.alt.decrypt.aes192cbc_hmacsha256

Implements `AES192CBC-SHA256` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes192cbc_hmacsha384 | magic.alt.decrypt.aes192cbc_hmacsha384

Implements `AES192CBC-SHA384` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes192cbc_hmacsha512 | magic.alt.decrypt.aes192cbc_hmacsha512

Implements `AES192CBC-SHA512` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes256cbc_hmacsha256 | magic.alt.decrypt.aes256cbc_hmacsha256

Implements `AES256CBC-SHA256` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes256cbc_hmacsha384 | magic.alt.decrypt.aes256cbc_hmacsha384

Implements `AES256CBC-SHA384` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes256cbc_hmacsha512 | magic.alt.decrypt.aes256cbc_hmacsha512

Implements `AES256CBC-SHA512` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128cbc_hmacsha256`.

#### magic.alt.encrypt.aes128gcm | magic.alt.decrypt.aes128gcm

Implements `AES128GCM` using OpenSSL through `crypto`. AES-GCM is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) and provides authenticated encryption using the industry standard symmetric encryption scheme with an authenticated block cipher mode, a clean and simple construction.

```js
// key generation

// callback
magic.alt.encrypt.aes128gcm(message, (err, output) => {
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
magic.alt.encrypt.aes128gcm(message)
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
magic.alt.encrypt.aes128gcm(message, sk, (err, output) => {
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
magic.alt.encrypt.aes128gcm(message, sk)
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
magic.alt.decrypt.aes128gcm(sk, iv, ciphertext, tag, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.alt.decrypt.aes128gcm(sk, iv, ciphertext, tag)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

#### magic.alt.encrypt.aes192gcm | magic.alt.decrypt.aes192gcm

Implements `AES192GCM` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128gcm`.

#### magic.alt.encrypt.aes256gcm | magic.alt.decrypt.aes256gcm

Implements `AES256GCM` using OpenSSL through `crypto`. An alternative to `magic.alt.encrypt.aes128gcm`.

#### magic.alt.util.sha256

Implements `SHA256` using OpenSSL through `crypto`. An alterative to `magic.util.hash`.

#### magic.alt.util.sha512

Implements `SHA512` using OpenSSL through `crypto`. An alterative to `magic.util.hash`.
