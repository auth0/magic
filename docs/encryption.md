# Encryption

magic supports the following encryption functions in its core API:
* [magic.encrypt.pki | magic.decrypt.pki](#magicencryptpki--magicdecryptpki): Assymetric encryption with PKI
* [magic.encrypt.aead | magic.decrypt.aead](#magicencryptaead--magicdecryptaead): Symmetric encryption using a key
* [magic.pwdEncrypt.aead | magic.pwdDecrypt.aead](#magicpwdencryptaead--magicpwddecryptaead): Symmetric encryption using a password
* [magic.EncryptStream | magic.DecryptStream](##magicencryptstream--magicdecryptstream): Symmetric encryption for streams using a key
* [magic.PwdEncryptStream | magic.PwdDecryptStream](#magicpwdencryptstream--magicpwddecryptstream): Symmetric encryption for streams using a password

The alt API also supports the following functions:
* [magic.alt.encrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512} | magic.alt.decrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512}](magicaltencryptaes_128192256_cbc_hmac_sha256384512--magicaltdecryptaes_128192256_cbc_hmac_sha256384512): Implements AES encryption with different key lengths and SHA2 algorithms

Remember that the alt API should only be used over the core API when required by an external specification or interoperability concerns.


## Core API

### magic.encrypt.pki | magic.decrypt.pki

Implements `x25519` static Diffie-Hellman key exchange, and employs the resultant shared secret for `xsalsa20poly1305` authenticated encryption using `libsodium.js`. This allows for an efficient, simple symmetric authenticated encryption scheme to be used in an asymmetric setting. A very closely related symmetric authenticated encryption scheme (using ChaCha20-Poly1305) has been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). As a static Diffie-Hellman exchange, the API is slightly different than most asymmetric encryption schemes - for encryption both the recipient public key and sender private key are required, whereas for decryption the recipient private key and sender public key are required. Usually, only the keys of the recipient are required for encryption, though `x25519-xsalsa20poly1305` has the benefit of being an authenticated scheme as well.

```js
// key generation

// callback
magic.encrypt.pki(message, (err, output) => {
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
magic.encrypt.pki(message)
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
magic.encrypt.pki(message, sk, pk, (err, output) => {
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
magic.encrypt.pki(message, sk, pk)
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
magic.decrypt.pki(sk, pk, ciphertext, nonce, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.decrypt.pki(sk, pk, ciphertext, nonce)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

### magic.encrypt.aead | magic.decrypt.aead

Implements `xsalsa20poly1305` authenticated encryption using `libsodium.js`. A very closely related symmetric authenticated encryption scheme (using ChaCha20-Poly1305) has been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). The scheme is fast, simple, and as an AEAD construction provides each of confidentiality, authentication, and integrity on the message.

```js
// key generation

// callback
magic.encrypt.aead(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.aead(message)
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
magic.encrypt.aead(message, sk, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.encrypt.aead(message, sk)
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
magic.decrypt.aead(sk, ciphertext, nonce, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.decrypt.aead(sk, ciphertext, nonce)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```

### magic.pwdEncrypt.aead | magic.pwdDecrypt.aead
Implements the same cryptographic protocols as magic.encrypt.aead/magic.decrypt.aead. The only difference is that pwdEncrypt.aead/pwdDecrypt.aead derive a key from a given password instead of requiring the key as an input. Only use these functions when encryption derived from a password is required. Otherwise, magic.encrypt.aead/magic.decrypt.aead is a more secure choice.

```js
// password
const pwd = 'randomPassword';

// callback
magic.pwdEncrypt.aead(message, pwd, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:        'xsalsa20poly1305',
  //   sk:         <Buffer d7 d5 dd 2c 2a eb f1 ... >,
  //   payload:    <Buffer 41 20 73 63 72 65 61 ... >,
  //   nonce:      <Buffer b3 4f 59 af 96 e4 4c ... >,
  //   ciphertext: <Buffer 3c 3d 0e 8b c6 34 83 ... > }
});

// promise
magic.pwdEncrypt.aead(message, pwd)
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
// password
const pwd = 'randomPassword';

// callback
magic.pwdDecrypt.aead(pwd, ciphertext, nonce, (err, plaintext) => {
  if (err) { return cb(err); }
  console.log(plaintext);
  // <Buffer 41 20 73 63 72 65 61 ... >
});

// promise
magic.pwdDecrypt.aead(pwd, ciphertext, nonce)
  .then((plaintext) => {
    console.log(plaintext);
    // <Buffer 41 20 73 63 72 65 61 ... >
  }).catch((err) => {
    return reject(err);
  });
});
```


### magic.EncryptStream | magic.DecryptStream

Implements `xchacha20poly1305` authenticated encryption using `libsodium.js`. The ChaCha20-Poly1305 symmetric authenticated encryption scheme been standardized by the [IETF](https://tools.ietf.org/html/rfc7539). The scheme is fast, simple, and as an AEAD construction provides confidentiality, authentication, and integrity on the message.

```js
  // key generation

  const readStream = fs.createReadStream('./plaintext.txt');
  const writeStream = fs.createWriteStream('./ciphertext.txt');
  const encryptStream = new magic.EncryptStream()
  readStream
    .pipe(encryptStream)
    .pipe(writeStream)
    .on('finish', function() {
      console.log('encrypted file written')
    })
```
The generated key is found in `encryptStream.key`.


```js
  let key = 'a0c4..' // supplied key; 32-bytes hex encoded string or 32-bytes Buffer

  const readStream = fs.createReadStream('./plaintext.txt');
  const writeStream = fs.createWriteStream('./ciphertext.txt');
  const encryptStream = new magic.EncryptStream(key)
  readStream
    .pipe(encryptStream)
    .pipe(writeStream)
    .on('finish', function() {
      console.log('encrypted file written')
    })
```

For decryption, the `encryptStream.key` should be passed to `magic.DecryptStream`.

```js
  const decryptStream = new magic.DecryptStream(encryptStream.key)
  readStream
    .pipe(decryptStream)
    .pipe(writeStream)
    .on('finish', function() {
      console.log('decrypted file written')
    })
```

### magic.PwdEncryptStream | magic.PwdDecryptStream

Implements the same cryptographic protocols as magic.EncryptStream/magic.DecryptStream. The only difference is that PwdEncryptStream and PwdDecryptStream derive a key from a given password instead of requiring the key as an input. Only use these functions when encryption derived from a password is required. Otherwise, magic.EncryptStream/magic.DecryptStream is a more secure choice.

```js
  // key generation

  const readStream = fs.createReadStream('./plaintext.txt');
  const writeStream = fs.createWriteStream('./ciphertext.txt');
  const encryptStream = new magic.PwdEncryptStream('a password')
  readStream
    .pipe(encryptStream)
    .pipe(writeStream)
    .on('finish', function() {
      console.log('encrypted file written')
    })
```


```js
  const decryptStream = new magic.PwdDecryptStream('a password')
  readStream
    .pipe(decryptStream)
    .pipe(writeStream)
    .on('finish', function() {
      console.log('decrypted file written')
    })
```


## alt api

### magic.alt.encrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512} | magic.alt.decrypt.AES\_{128,192,256}\_CBC\_HMAC\_SHA{256,384,512}

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

  ### magic.alt.encrypt.AES\_{128,192,256}\_GCM | magic.alt.decrypt.AES\_{128,192,256}\_GCM

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
