# Change Log

All notable changes to this project will be documented in this file.

## v5.0.0 - 2021-09-15

### Changes
- BREAKING CHANGE: Drops support for node 10. Supported versions: =>12
- Updates the libsodium library to v0.7.9. Previous versions of the library were removing all uncaughtException listeners including ones attached by other code. This is now fixed in the new version.

### Misc
- Moves ed25519 crypto from libsodium to Node.js crypto module
- Enables non-blocking RSA sign/verify asynchronous operation when available
- Improves documentation

## v4.0.0 - 2020-09-02

### Changes
- Drops support for node 8 due to bcrypt update
- Updates bcrypt to version 5.x. This is a breaking change only in case of a
  passphrase longer than 255 or a passphrase that includes null byte

### Misc
- Cleans up code
- Improves documentation


## v3.1.0 - 2019-12-31

### Adds
- Adds support for Node 12

### Misc

- Updates the libsodium library to v0.7.6. The previous version was removing
  the unhandledRejection listener which was causing process.exit(1) without any
  logging


## v3.0.0 - 2019-07-09

### Changes
- Renames the output of magic.util.rsaKeypairGen() from
{ sk: ... , pk ...} to { privateKey: ... , publicKey: ...}

## v2.5.0 - 2019-07-03

### Adds
- Adds support for generating an RSA private/public keypair via the new
  function magic.util.rsaKeypairGen()

## v2.4.0 - 2019-04-30

### Adds
- Adds support for timing safe string comparisons via the new function
  magic.util.timingSafeCompare()

## v2.3.1 - 2019-04-17

### Misc

- Updates README
- Updates bcrypt to v3.0.6

## v2.3.0 - 2019-02-21

### Adds

- Adds support for encryption/decryption with user supplied password with two
  new functions: pwdEncrypt.aead(), pwdDecrypt.aead()

## v2.2.0 - 2019-01-31

### Adds

- Adds support for stream encryption/decryption with user supplied password

### Misc

- Fixes race condition issue in magic.util.uid()

## v2.1.0 - 2019-01-04

### Adds

- Adds support for stream encryption/decryption

## v2.0.0 - 2018-11-12

### Changes

- Rename `encrypt.sync` and `decrypt.sync` to `encrypt.aead` and `decrypt.aead`
- Rename `encrypt.async` and `decrypt.async` to `encrypt.pki` and `decrypt.pki`

## v1.0.3 - 2018-09-21

### Misc

- Change repo name to auth0-magic

## v1.0.1 - 2018-09-14

### Changes

- Decrease bcrypt rounds from 13 to 10 due to performance issues

### Misc

- Add LICENSE, CODEOWNERS, CHANGELOG file
