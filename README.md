# magic
[![Build Status](https://www.travis-ci.org/auth0/magic.svg?branch=master)](https://travis-ci.org/auth0/magic)

`magic` is a lightweight wrapper around the `crypto` interface to OpenSSL and the `libsodium` library which provides a standard cryptography API for internal use, consistent with best current practices recommended by the product security team at Auth0. Named not for what it is intended to do, but for [what it is intended to prevent](https://en.wikipedia.org/wiki/Magic_(cryptography)).

All public functions support both callbacks and promises (and therefore async/await), allowing easy integration into any preexisting codebase. All constructions requiring secret keys will generate them as necessary if they are not supplied, and return them for future use.

## Why use magic
Most libraries offering a cryptography toolkit allow for a variety of configuration. Usually the reasoning behind this is to empower the developer to configure the cryptography functions as they like. At the same time however this requires developers to be knowledgable of what the different parameters are for and how they affect the security of the function output. Bad choices in parameters can lead to insecure cryptography with disastrous results.

magic is a library that supports as little configuration as possible allowing developers to use a cryptography library without needing expert knowledge. Secure configuration is embedded in the library following best current practices recommended by the Product Security team at Auth0. 

## Install
```
npm install auth0-magic
```

## Usage

magic offers a variety of functions for the following cases:
* [Encryption](/docs/encryption)
  * [Symmetric Authenticated Encryption](/docs/encryption.md#magicencryptaead--magicdecryptaead)
  * [Asymmetric Authenticated Encryption](/docs/encryption.md#magicencryptpki--magicdecryptpki)
  * [Streams Symmetric Authenticated Encryption](/docs/encryption.md#magicencryptstream--magicdecryptstream)
* [Authentication](/docs/authentication)
  * [Signing using PKI](/docs/authentication.md#magicauthsign--magicverifysign)
  * [HMAC](https://github.com/auth0/magic/blob/master/docs/authentication.md#magicauthmac--magicverifymac)
* [Password hashing](/docs/passwordHashing)
  * [argon2](/docs/passwordHashing.md#magicpasswordhash--magicverifypassword)
  * [bcrypt](/docs/passwordHashing.md#magicaltpasswordbcrypt--magicaltverifybcrypt)

magic also offers a variety of [utility functions](/docs/utils): 
 * [RSA key pair generation](/docs/utils.md#magicutilrsakeypairgen)
 * [Time safe comparison](/docs/utils.md#magicutiltimingsafecompare)
 * [UID generation](/docs/utils.md#magicutiluid)
 * [Random bytes generation](/docs/utils.md#magicutilrand)
 * [Hashing](/docs/utils.md#magicutilhash)

Magic implements a core and and alt API. The core api implements the recommended algorithms for each cryptographic operation. When in doubt, please use them. The alt api implements alternative algorithms for each cryptographic operation. They should only be used over the core api when required by an external specification or interoperability concerns.

Detailed documentation on the supported API can be found in the [/docs](/docs) folder 


### Recommended input type
It is recommended that `magic` is always used with [node.js buffers](https://nodejs.org/api/buffer.html) for all (non-boolean) inputs, with the exception of passwords. 

Due to the variety of tasks to which it may be put, the library attempts to be as unopinionated about encoding as it is opinionated about algorithms. There is minimal decoding functionality, which will attempt to break down any plaintext input as `utf-8` and any cryptographic input (keys, ciphertexts, macs, signatures, etc.) as `hex`. If as a consumer of this library you decide to depend on this builtin decoder it is recommended that you extensively test it to make sure your inputs are being parsed appropriately. When in doubt, it is always safer to parse them yourself and pass in binary data.
