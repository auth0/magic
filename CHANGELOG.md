# Change Log

All notable changes to this project will be documented in this file.

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
