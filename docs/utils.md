# Utility functions

magic supports the following utility functions in its core API:
* [magic.util.hash](#magicutilhash): Implements `SHA2-384`
* [magic.util.rsaKeypairGen](#magicutilrsakeypairgen): Generates an RSA public/private key pair
* [magic.util.timingSafeCompare](#magicutiltimingsafecompare): Implements a timing safe comparison between two strings
* [magic.util.rand](#magicutilrand): Returns the requested number of random bytes
* [magic.util.uid](#magicutiluid): Returns a base64url encoded UID

The alt API also supports the following functions:
* [magic.alt.util.sha{256,512}](#magicaltutilsha256512): Implements `SHA2-256` or `SHA2-512`

Remember that the alt API should only be used over the core API when required by an external specification or interoperability concerns.

## Core API

### magic.util.hash

Implements `SHA2-384` (henceforth just `SHA384`) using OpenSSL through `crypto`.

Unlike `SHA256` and `SHA512` - which are available through the alternative API - `SHA384` is resistant to length extension attacks, a capability which may be relevant in some circumstances. The `SHA2` family is standardized by [NIST](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), and the most commonly used fast, cryptographically secure hash function.

```js
// callback
magic.util.hash(message, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  /*
   * {
   *   alg:     'sha384',
   *   payload: <Buffer 41 20 73 63 72 65 61  ... >,
   *   hash:    <Buffer 15 0b f9 4d e3 2b 5a  ... >
   * }
   */
});

// promise
magic.util.hash(message)
  .then((output) => {
    console.log(output);
    /*
     * {
     *   alg:     'sha384',
     *   payload: <Buffer 41 20 73 63 72 65 61  ... >,
     *   hash:    <Buffer 15 0b f9 4d e3 2b 5a  ... >
     * }
     */
  })
  .catch((err) => {
    return reject(err);
  });
});
```

### magic.util.rsaKeypairGen

Generates an RSA public/private key pair. The public key is encoded using a SubjectPublicKeyInfo(SPKI) structure.

For node 10+, it uses the built-in `generateKeyPair` from `crypto` library. For older node versions, it generates the keypair using OpenSSL directly.

```js
// callback
magic.util.rsaKeypairGen((err, keypair) => {
  if (err) { return cb(err); }
  console.log(keypair)
  /*
   * {
   *   privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBi...6gA=\n-----END RSA PRIVATE KEY-----\n',
   *   publicKey: '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQE...ApIDAQAB\n-----END RSA PUBLIC KEY-----\n'
   *  }
   */
});

// promise
magic.util.rsaKeypairGen()
.then((keypair) => {
  console.log(keypair)
  /*
   * {
   *   privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBi...6gA=\n-----END RSA PRIVATE KEY-----\n',
   *   publicKey: '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQE...ApIDAQAB\n-----END RSA PUBLIC KEY-----\n'
   *  }
   */
})
.catch((err) => {
  return reject(err);
});
```

### magic.util.timingSafeCompare

Implements a timing safe comparison between two strings. The comparison is completed using string length checks and the timing safe buffer comparison in the `crypto` module (falling back to `libsodium` if `crypto` is not available).

*Recommended use: Best used when comparing sensitive information that is transmitted in clear text but is not practical to store, and encrypt or hash. An example would be to check whether an input string matches an environment variable. When in doubt, use encryption and hashing functions.*

```js
var stringsAreTheSame = magic.util.timingSafeCompare(inputString, referenceString);
```

### magic.util.rand

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

### magic.util.uid

Employs OpenSSL through `crypto` to return a base64url encoded uid.

The input is not the length of the returned uid, but rather a security parameter taken as the unencoded byte length of the identifier. The returned string will be roughly a third longer than it. The default security parameter (if one is not provided) is 32 bytes, returning a uid of 43 chars.

```js
// 1. Default security parameter

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

// 2. Provided security parameter length

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

## Alternative API

### magic.alt.util.sha{256,512}

Implements `SHA2` using OpenSSL through `crypto`. Each of the `SHA256`, `SHA384` (as `magic.util.hash`), and `SHA512` digest length variants are available. An alternative to `magic.util.hash`.

The functions' interface is the same as in [magic.utils.hash](#magicutilhash)
