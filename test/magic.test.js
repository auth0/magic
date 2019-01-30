const magic = require('../magic');

const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');
const assert = require('assert');
const fs = require('fs');


describe('magic tests', () => {

  describe('core api', () => {

    sodium.ready.then(() => {

      describe('sign', () => {

        let sk, pk, seed;
        const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

        describe('success', () => {

          describe('without key generation - supplied keypair', () => {

            beforeEach(() => {
              const keys = sodium.crypto_sign_keypair();
              sk = Buffer.from(keys.privateKey);
              pk = Buffer.from(keys.publicKey);
            });

            it('should verify a computed signature - callback api', (done) => {
              magic.auth.sign(message, sk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.signature);

                magic.verify.sign(message, pk, output.signature, true, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });

            it('should verify a computed signature - promise api', (done) => {
              magic.auth.sign(message, sk).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.signature);

                return magic.verify.sign(message, pk, output.signature, true);
              }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
            });

            it('should verify a computed signature w/ hex encoding', (done) => {
              const esk = sk.toString('hex');
              const epk = pk.toString('hex');

              magic.auth.sign(message, esk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.signature);

                const esig = output.signature.toString('hex');

                magic.verify.sign(message, epk, esig, true, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });
          });

          describe('without key generation - supplied seed', () => {

            beforeEach(() => {
              const keys = sodium.crypto_sign_keypair();
              seed = Buffer.from(sodium.crypto_sign_ed25519_sk_to_seed(keys.privateKey));
            });

            it('should verify a computed signature - callback api', (done) => {
              magic.auth.sign(message, seed, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, seed) === 0);

                assert.ok(output.signature);

                magic.verify.sign(message, seed, output.signature, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });

            it('should verify a computed signature - promise api', (done) => {
              magic.auth.sign(message, seed).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, seed) === 0);

                assert.ok(output.signature);

                return magic.verify.sign(message, seed, output.signature);
              }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
            });

            it('should verify a computed signature w/ hex encoding', (done) => {
              const eseed = seed.toString('hex');

              magic.auth.sign(message, eseed, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, seed) === 0);

                assert.ok(output.signature);

                const esig = output.signature.toString('hex');

                magic.verify.sign(message, eseed, esig, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });
          });

          describe('with key generation', () => {

            it('should verify a computed signature - callback api', (done) => {
              magic.auth.sign(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.signature);

                magic.verify.sign(message, output.sk, output.signature, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });

            it('should verify a computed signature - promise api', (done) => {
              magic.auth.sign(message).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.signature);

                return magic.verify.sign(message, output.sk, output.signature);
              }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
            });

            it('should verify a computed signature w/ hex encoding', (done) => {
              magic.auth.sign(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'ed25519');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.signature);

                const eseed = output.sk.toString('hex');
                const esig  = output.signature.toString('hex');

                magic.verify.sign(message, eseed, esig, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });
          });
        });

        describe('failure', () => {

          it('should error without key on validation', (done) => {
            magic.auth.sign(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'ed25519');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.signature);

              magic.verify.sign(message, null, output.signature, false, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot verify without a key');

                done();
              });
            });
          });

          it('should fail if message is altered', (done) => {
            magic.auth.sign(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'ed25519');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.signature);

              const altered = 'Some other message';

              magic.verify.sign(altered, output.sk, output.signature, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Invalid signature');

                done();
              });
            });
          });

          it('should fail if key is altered', (done) => {
            magic.auth.sign(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'ed25519');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.signature);

              const altered = Buffer.from('b64a6fb5878091d0575d9b0d0be667fb5e37f54be2c2cd5cff139857c494c5eb', 'hex');

              magic.verify.sign(message, altered, output.signature, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Invalid signature');

                done();
              });
            });
          });
        });
      });


      describe('mac', () => {

        let key;
        const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

        describe('success', () => {

          describe('without key generation', () => {

            beforeEach(() => { key = crypto.randomBytes(48); });

            it('should verify a computed mac - callback api', (done) => {
              magic.auth.mac(message, key, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, key) === 0);

                assert.ok(output.mac);

                magic.verify.mac(message, key, output.mac, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });

            it('should verify a computed mac - promise api', (done) => {
              magic.auth.mac(message, key).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, key) === 0);

                assert.ok(output.mac);

                return magic.verify.mac(message, key, output.mac);
              }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
            });

            it('should verify a computed mac w/ hex encoding', (done) => {
              const ekey = key.toString('hex');

              magic.auth.mac(message, ekey, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, key) === 0);

                assert.ok(output.mac);

                const emac = output.mac.toString('hex');

                magic.verify.mac(message, ekey, emac, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });
          });

          describe('with key generation', () => {

            it('should verify a computed mac - callback api', (done) => {
              magic.auth.mac(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.mac);

                magic.verify.mac(message, output.sk, output.mac, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });

            it('should verify a computed mac - promise api', (done) => {
              magic.auth.mac(message).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.mac);

                return magic.verify.mac(message, output.sk, output.mac);
              }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
            });

            it('should verify a computed mac w/ hex encoding', (done) => {
              magic.auth.mac(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'hmacsha384');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.mac);

                const ekey = output.sk.toString('hex');
                const emac = output.mac.toString('hex');

                magic.verify.mac(message, ekey, emac, (err) => {
                  assert.ok(!err);
                  done();
                });
              });
            });
          });
        });

        describe('failure', () => {

          it('should error without key on validation', (done) => {
            magic.auth.mac(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              magic.verify.mac(message, null, output.mac, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot verify without a key');

                done();
              });
            });
          });

          it('should fail if message is altered', (done) => {
            magic.auth.mac(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const altered = 'Some other message';

              magic.verify.mac(altered, output.sk, output.mac, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Invalid mac');

                done();
              });
            });
          });

          it('should fail if key is altered', (done) => {
            magic.auth.mac(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const altered = Buffer.from('b3ae620c610b577c1a596fa96259426dc9bcc521c086a348e22b8169b092fcf01f20381e0edca71e4fa9811bc7ed05e9', 'hex');

              magic.verify.mac(message, altered, output.mac, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Invalid mac');

                done();
              });
            });
          });
        });
      });


      describe('async', () => {

        let sk, pk;
        const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

        describe('success', () => {

          describe('without key generation', () => {

            beforeEach(() => {
              const keys = sodium.crypto_box_keypair();
              sk = Buffer.from(keys.privateKey);
              pk = Buffer.from(keys.publicKey);
            });

            it('should encrypt and decrypt an authenticated message - callback api', (done) => {
              magic.encrypt.pki(message, sk, pk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);
                assert.ok(Buffer.compare(output.pk, pk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                magic.decrypt.pki(sk, pk, output.ciphertext, output.nonce, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });

            it('should encrypt and decrypt an authenticated message - promise api', (done) => {
              magic.encrypt.pki(message, sk, pk).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);
                assert.ok(Buffer.compare(output.pk, pk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                return magic.decrypt.pki(sk, pk, output.ciphertext, output.nonce);
              }).then((plaintext) => {
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              }).catch((err) => { assert.ok(!err); });
            });

            it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
              const esk = sk.toString('hex');
              const epk = pk.toString('hex');

              magic.encrypt.pki(message, esk, epk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);
                assert.ok(Buffer.compare(output.pk, pk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                const ect = output.ciphertext.toString('hex');
                const en  = output.nonce.toString('hex');

                magic.decrypt.pki(esk, epk, ect, en, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });
          });

          describe('with key generation', () => {

            it('should encrypt and decrypt an authenticated message - callback api', (done) => {
              magic.encrypt.pki(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.pk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                magic.decrypt.pki(output.sk, output.pk, output.ciphertext, output.nonce, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });

            it('should encrypt and decrypt an authenticated message - promise api', (done) => {
              magic.encrypt.pki(message).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.pk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                return magic.decrypt.pki(output.sk, output.pk, output.ciphertext, output.nonce);
              }).then((plaintext) => {
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              }).catch((err) => { assert.ok(!err); });
            });

            it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
              magic.encrypt.pki(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'x25519-xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.pk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                const esk = output.sk.toString('hex');
                const epk = output.pk.toString('hex');
                const ect = output.ciphertext.toString('hex');
                const en  = output.nonce.toString('hex');

                magic.decrypt.pki(esk, epk, ect, en, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });
          });
        });

        describe('failure', () => {

          it('should error with only private key on encryption', (done) => {
            magic.encrypt.pki(message, sodium.crypto_box_keypair().privateKey, null, (err, output) => {
              assert.ok(err);
              assert.equal(err.message, 'Requires both or neither of private and public keys');

              done();
            });
          });

          it('should error with only public key on encryption', (done) => {
            magic.encrypt.pki(message, null, sodium.crypto_box_keypair().publicKey, (err, output) => {
              assert.ok(err);
              assert.equal(err.message, 'Requires both or neither of private and public keys');

              done();
            });
          });

          it('should error without keys on decryption', (done) => {
            magic.encrypt.pki(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.pki(null, null, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot decrypt without both private and public keys');

                done();
              });
            });
          });

          it('should error without private key on decryption', (done) => {
            magic.encrypt.pki(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.pki(null, output.pk, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot decrypt without both private and public keys');

                done();
              });
            });
          });

          it('should error without public key on decryption', (done) => {
            magic.encrypt.pki(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.pki(output.sk, null, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot decrypt without both private and public keys');

                done();
              });
            });
          });

          it('should fail if ciphertext is altered', (done) => {
            magic.encrypt.pki(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              const altered = Buffer.from('b16da2bec401fc7a1d4723025ed2fa122f400631018cae837bade02289ee4e187541f57ee6efbc33ad4e08b5465bb6534d3edc7305c27fa6f61dc165f57f0ef79b64bb3d7409a83d2f196ad2496284d2caf934ad8047a17dfefe5c318afc96cda61e71e06d3ebcb60140a97666d7a0cc2512aa31', 'hex');

              magic.decrypt.pki(output.sk, output.pk, altered, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

                done();
              });
            });
          });

          it('should fail if nonce is altered', (done) => {
            magic.encrypt.pki(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              const altered = Buffer.from('f5319d1c72f6019683fa7992bb5acf3f540a9ae870f3806f', 'hex');

              magic.decrypt.pki(output.sk, output.pk, output.ciphertext, altered, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

                done();
              });
            });
          });
        });
      });


      describe('sync', () => {

        let sk;
        const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

        describe('success', () => {

          describe('without key generation', () => {

            beforeEach(() => { sk = Buffer.from(sodium.crypto_secretbox_keygen()); });

            it('should encrypt and decrypt an authenticated message - callback api', (done) => {
              magic.encrypt.aead(message, sk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                magic.decrypt.aead(sk, output.ciphertext, output.nonce, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });

            it('should encrypt and decrypt an authenticated message - promise api', (done) => {
              magic.encrypt.aead(message, sk).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                return magic.decrypt.aead(sk, output.ciphertext, output.nonce);
              }).then((plaintext) => {
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              }).catch((err) => { assert.ok(!err); });
            });

            it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
              const esk = sk.toString('hex');

              magic.encrypt.aead(message, esk, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);
                assert.ok(Buffer.compare(output.sk, sk) === 0);

                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                const ect = output.ciphertext.toString('hex');
                const en  = output.nonce.toString('hex');

                magic.decrypt.aead(esk, ect, en, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });
          });

          describe('with key generation', () => {

            it('should encrypt and decrypt an authenticated message - callback api', (done) => {
              magic.encrypt.aead(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                magic.decrypt.aead(output.sk, output.ciphertext, output.nonce, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });

            it('should encrypt and decrypt an authenticated message - promise api', (done) => {
              magic.encrypt.aead(message).then((output) => {
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                return magic.decrypt.aead(output.sk, output.ciphertext, output.nonce);
              }).then((plaintext) => {
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              }).catch((err) => { assert.ok(!err); });
            });

            it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
              magic.encrypt.aead(message, (err, output) => {
                assert.ok(!err);
                assert.ok(output);

                assert.equal(output.alg, 'xsalsa20poly1305');
                assert.equal(output.payload.toString('utf-8'), message);

                assert.ok(output.sk);
                assert.ok(output.ciphertext);
                assert.ok(output.nonce);

                const esk = output.sk.toString('hex');
                const ect = output.ciphertext.toString('hex');
                const en  = output.nonce.toString('hex');

                magic.decrypt.aead(esk, ect, en, (err, plaintext) => {
                  assert.ok(!err);
                  assert.equal(plaintext.toString('utf-8'), message);

                  done();
                });
              });
            });
          });
        });

        describe('failure', () => {

          it('should error without key on decryption', (done) => {
            magic.encrypt.aead(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.aead(null, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Cannot decrypt without a key');

                done();
              });
            });
          });

          it('should fail if ciphertext is altered', (done) => {
            magic.encrypt.aead(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              const altered = Buffer.from('b16da2bec401fc7a1d4723025ed2fa122f400631018cae837bade02289ee4e187541f57ee6efbc33ad4e08b5465bb6534d3edc7305c27fa6f61dc165f57f0ef79b64bb3d7409a83d2f196ad2496284d2caf934ad8047a17dfefe5c318afc96cda61e71e06d3ebcb60140a97666d7a0cc2512aa31', 'hex');

              magic.decrypt.aead(output.sk, altered, output.nonce, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Libsodium error: Error: wrong secret key for the given ciphertext');

                done();
              });
            });
          });

          it('should fail if nonce is altered', (done) => {
            magic.encrypt.aead(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              const altered = Buffer.from('f5319d1c72f6019683fa7992bb5acf3f540a9ae870f3806f', 'hex');

              magic.decrypt.aead(output.sk, output.ciphertext, altered, (err, plaintext) => {
                assert.ok(err);
                assert.equal(err.message, 'Libsodium error: Error: wrong secret key for the given ciphertext');

                done();
              });
            });
          });
        });
      });


      describe('password', () => {

        const password = 'ascreamingcomesacrossthesky';

        describe('success', () => {

          it('should verify a hashed password - callback api', (done) => {
            magic.password.hash(password, (err, output) => {
              assert.ok(!err);
              assert.ok(output);
              assert.ok(output.hash);

              assert.equal(output.alg, 'argon2id');
              assert.equal(output.hash.slice(0, 9), '$argon2id');

              magic.verify.password(password, output.hash, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a hashed password - promise api', (done) => {
            magic.password.hash(password).then((output) => {
              assert.ok(output);
              assert.ok(output.hash);

              assert.equal(output.alg, 'argon2id');
              assert.equal(output.hash.slice(0, 9), '$argon2id');

              return magic.verify.password(password, output.hash);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });
        });

        describe('failure', () => {

          it('should fail to verify the wrong password', (done) => {
            magic.password.hash(password, (err, output) => {
              assert.ok(!err);
              assert.ok(output);
              assert.ok(output.hash);

              assert.equal(output.alg, 'argon2id');
              assert.equal(output.hash.slice(0, 9), '$argon2id');

              magic.verify.password('someotherpassword', output.hash, (err) => {
                assert.ok(err);
                assert.equal(err.message, 'Invalid password');

                done();
              });
            });
          });
        });
      });


      describe('hash', () => {

        const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

        it('should hash an input - callback api', (done) => {
          magic.util.hash(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.equal(output.hash.toString('hex'), '150bf94de32b5a65892ff46a580abef8d9c7af652b3f7d57ce03b51e4268dafafcba6d5ef7fcd8d41a63ff60394184da');

            done();
          });
        });

        it('should hash an input - promise api', (done) => {
          magic.util.hash(message).then((output) => {
            assert.ok(output);

            assert.equal(output.alg, 'sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.equal(output.hash.toString('hex'), '150bf94de32b5a65892ff46a580abef8d9c7af652b3f7d57ce03b51e4268dafafcba6d5ef7fcd8d41a63ff60394184da');

            done();
          }).catch((err) => { assert.ok(!err); });
        });
      });


      describe('rand', () => {

        describe('success', () => {

          const length = 64;

          it('should return a random buffer of the requested byte length - callback api', (done) => {
            magic.util.rand(length, (err, bytes) => {
              assert.ok(!err);
              assert.ok(bytes);
              assert.equal(Buffer.byteLength(bytes), length);

              done();
            });
          });

          it('should return a random buffer of the requested byte length - promise api', (done) => {
            magic.util.rand(length).then((bytes) => {
              assert.ok(bytes);
              assert.equal(Buffer.byteLength(bytes), length);

              done();
            }).catch((err) => { assert.ok(!err); });
          });
        });

        describe('failure', () => {

          it('should fail with invalid byte length', (done) => {
            magic.util.rand(-1, (err, bytes) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid length');

              done();
            });
          });
        });
      });


      describe('uid', () => {

        describe('success', () => {

          const security = 24;

          it('should return a base64url encoded string of length corresponding to the default security parameter - callback api', (done) => {
            magic.util.uid((err, uid) => {
              assert.ok(!err);
              assert.ok(uid);
              assert.equal(uid.length, 43);

              done();
            });
          });

          it('should return a base64url encoded string of length corresponding to the default security parameter - promise api', (done) => {
            magic.util.uid().then((uid) => {
              assert.ok(uid);
              assert.equal(uid.length, 43);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should return a base64url encoded string of length corresponding to the provided security parameter - callback api', (done) => {
            magic.util.uid(security, (err, uid) => {
              assert.ok(!err);
              assert.ok(uid);
              assert.equal(uid.length, 32);

              done();
            });
          });

          it('should return a base64url encoded string of length corresponding to the provided security parameter - promise api', (done) => {
            magic.util.uid(security).then((uid) => {
              assert.ok(uid);
              assert.equal(uid.length, 32);

              done();
            }).catch((err) => { assert.ok(!err); });
          });
        });

        describe('failure', () => {

          it('should fail with invalid byte length', (done) => {
            magic.util.uid(-1, (err, uid) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid length');

              done();
            });
          });
        });
      });

      describe('stream encryption/decryption', () => {
        before(() => {
          this.HEADER_BYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + 1;
        })

        beforeEach(() => {
          readStream = fs.createReadStream('./test/plaintext.txt');
          writeStream = fs.createWriteStream('./test/decryptedtext.txt');
        });

        it('should encrypt and decrypt a stream with a given key', (done) => {
          const encryptStream = new magic.EncryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const decryptStream = new magic.DecryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          readStream
            .pipe(encryptStream)
            .pipe(decryptStream)
            .pipe(writeStream)
            .on('finish', function() {
              fs.readFile('./test/plaintext.txt', (err, plaindata) => {
                if (err) {
                  throw err;
                }
                fs.readFile('./test/decryptedtext.txt', (err, decrdata) => {
                  if (err) {
                    throw err;
                  }
                  assert.equal(plaindata.toString(), decrdata.toString())
                  done()
                });
              });
            });
        });

        it('should encrypt and decrypt a stream with an aytogenerated key ', (done) => {
          const encryptStream = new magic.EncryptStream()
          const decryptStream = new magic.DecryptStream(encryptStream.key)
          readStream
            .pipe(encryptStream)
            .pipe(decryptStream)
            .pipe(writeStream)
            .on('finish', function() {
              fs.readFile('./test/plaintext.txt', (err, plaindata) => {
                if (err) {
                  throw err;
                }
                fs.readFile('./test/decryptedtext.txt', (err, decrdata) => {
                  if (err) {
                    throw err;
                  }
                  assert.equal(plaindata.toString(), decrdata.toString())
                  done()
                });
              });
            });
        });

        it('should throw an error if no key is passed to DecryptStream', () => {
          try {
           const decryptStream = new magic.DecryptStream()
          } catch(err) {
            assert.ok(err)
            assert.equal(err.message, 'Missing key for DecryptStream')
          }
        });

        it('should encrypt the plaintext in a file and then decrypt it in a new file (asynchronous encryption/decryption)', (done) => {
          const encryptStream = new magic.EncryptStream()
          const decryptStream = new magic.DecryptStream(encryptStream.key)
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.createReadStream('./test/encryptedtext.txt')
              .pipe(decryptStream)
              .pipe(writeStream)
              .on('close', function() {
                fs.readFile('./test/plaintext.txt', (err, plaindata) => {
                  if (err) {
                    throw err;
                  }
                  fs.readFile('./test/decryptedtext.txt', (err, decrdata) => {
                    if (err) {
                      throw err;
                    }
                    assert.equal(plaindata.toString(), decrdata.toString())
                    done()
                  });
                });
              });
            });
        });

        it('should return an error when decrypting a truncated encrypted file', (done) => {
          const encryptStream = new magic.EncryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const decryptStream = new magic.DecryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', () => {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                let lastEncrChunk = (data.length - this.HEADER_BYTES) % (magic.STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
                decryptStream.write(data.slice(0, data.length - lastEncrChunk))
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Premature stream close')
                    done();
                  })
              })
            })
        });

        it('should return an error when decrypting a spliced stream', (done) => {
          const STREAM_CHUNK_SIZE = 4096
          const encryptStream = new magic.EncryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const decryptStream = new magic.DecryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                const secChunkStart = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + 1
                const secChunkEnd = secChunkStart + magic.STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
                let dataNoSecChunk = Buffer.concat([data.slice(0, secChunkStart), data.slice(secChunkEnd)])
                decryptStream.write(dataNoSecChunk)
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Corrupted chunk')
                    done();
                  })
              })
            })
        });

        it('should return an error when stream version is incorrect', (done) => {
          const encryptStream = new magic.EncryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const decryptStream = new magic.DecryptStream('012345678901234567890123456789ab012345678901234567890123456789ab')
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                let dataWrongStreamVersion = Buffer.concat([Buffer.from([10]), data.slice(1)])
                decryptStream.write(dataWrongStreamVersion)
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Unsupported version')
                    done();
                  })
              })
            })
        });

        after(() => {
          fs.unlink('./test/decryptedtext.txt', (err) => {
            if (err) throw err
            fs.unlink('./test/encryptedtext.txt', (err) => {
              if (err) throw err
            })
          });
        })
      });

      describe('stream encryption/decryption with password', () => {
        before(() => {
          this.HEADER_BYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + 1;
          this.PWD_HEADER_BYTES = sodium.crypto_pwhash_SALTBYTES + 1;
          password = 'random passw0rd!'
        })

        after(() => {
          fs.unlink('./test/decryptedtext.txt', (err) => {
            if (err) throw err
            fs.unlink('./test/encryptedtext.txt', (err) => {
              if (err) throw err
            })
          })
        })

        beforeEach(() => {
          readStream = fs.createReadStream('./test/plaintext.txt');
          writeStream = fs.createWriteStream('./test/decryptedtext.txt');
        });

        it('should successfully encrypt and decrypt a stream with a given password', (done) => {
          const encryptStream = new magic.PwdEncryptStream(password)
          const decryptStream = new magic.PwdDecryptStream(password)
          readStream
            .pipe(encryptStream)
            .pipe(decryptStream)
            .pipe(writeStream)
            .on('finish', function() {
              fs.readFile('./test/plaintext.txt', (err, plaindata) => {
                if (err) {
                  throw err;
                }
                fs.readFile('./test/decryptedtext.txt', (err, decrdata) => {
                  if (err) {
                    throw err;
                  }
                  assert.equal(plaindata.toString(), decrdata.toString())
                  done()
                });
              });
            });
        });

        it('should throw an error if no password is passed to PwdEncryptStream', () => {
          try {
           const decryptStream = new magic.PwdEncryptStream()
          } catch(err) {
            assert.ok(err)
            assert.equal(err.message, 'Missing password for PwdEncryptStream')
          }
        });

        it('should throw an error if no password is passed to PwdDecryptStream', () => {
          try {
           const decryptStream = new magic.PwdDecryptStream()
          } catch(err) {
            assert.ok(err)
            assert.equal(err.message, 'Missing password for PwdDecryptStream')
          }
        });

        it('should encrypt the plaintext in a file and then decrypt it in a new file (asynchronous encryption/decryption)', (done) => {
          const encryptStream = new magic.PwdEncryptStream(password)
          const decryptStream = new magic.PwdDecryptStream(password)
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.createReadStream('./test/encryptedtext.txt')
              .pipe(decryptStream)
              .pipe(writeStream)
              .on('close', function() {
                fs.readFile('./test/plaintext.txt', (err, plaindata) => {
                  if (err) {
                    throw err;
                  }
                  fs.readFile('./test/decryptedtext.txt', (err, decrdata) => {
                    if (err) {
                      throw err;
                    }
                    assert.equal(plaindata.toString(), decrdata.toString())
                    done()
                  });
                });
              });
            });
        });

        it('should return an error when decrypting a truncated encrypted file', (done) => {
          const encryptStream = new magic.PwdEncryptStream(password)
          const decryptStream = new magic.PwdDecryptStream(password)
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', () => {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                let lastEncrChunk = (data.length - this.HEADER_BYTES - this.PWD_HEADER_BYTES) % (magic.STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES)
                decryptStream.write(data.slice(0, data.length - lastEncrChunk))
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Premature stream close')
                    done();
                  })
              })
            })
        });

        it('should return an error when decrypting a spliced stream', (done) => {
          const STREAM_CHUNK_SIZE = 4096
          const encryptStream = new magic.PwdEncryptStream(password)
          const decryptStream = new magic.PwdDecryptStream(password)
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                const secChunkStart = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES + 1 + sodium.crypto_pwhash_SALTBYTES + 1;
                const secChunkEnd = secChunkStart + magic.STREAM_CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
                let dataNoSecChunk = Buffer.concat([data.slice(0, secChunkStart), data.slice(secChunkEnd)])
                decryptStream.write(dataNoSecChunk)
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Corrupted chunk')
                    done();
                  })
              })
            })
        });

        it('should return an error when the password stream version is incorrect', (done) => {
          const encryptStream = new magic.PwdEncryptStream(password)
          const decryptStream = new magic.PwdDecryptStream(password)
          const encTextStream = fs.createWriteStream('./test/encryptedtext.txt');
          readStream
            .pipe(encryptStream)
            .pipe(encTextStream)
            .on('finish', function() {
              fs.readFile('./test/encryptedtext.txt', (err, data) => {
                let dataWrongPwdStreamVersion = Buffer.concat([Buffer.from([10]), data.slice(1)])
                decryptStream.write(dataWrongPwdStreamVersion)
                decryptStream.end()
                decryptStream
                  .on('error', function(err) {
                    assert.ok(err)
                    assert.equal(err.message, 'Unsupported PwdEncryptionStream version')
                    done();
                  })
              })
            })
        });
      });
    });
  });


  describe('alt api', () => {

    const RSAKEYS = {
      sk: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLpqpUjdaBbsN9shuY0vNipkPrFZNK583n+VaXmMRPbASyTF
A6PlhC7W/e/g1dCspJH0Md+GU7nf/bosq8vlzQd0Q9iMWXybU08JYr/JIvSRprB3
pQ7LPjwkigHgPvXNqb7U/czmX2vfexRRR/gjuGmAGC8kVUMTHZGAQVdMl188Ydzv
namzh0XquypGuw44WShWMyCExRl44SoVFe2YkSKHU3Ivt2VfW9BjhC/5dSQGtzdj
p0ZsV7OOCwH19+xFtL3efSH6tJXbM1fuOuyg/X7kb9KTcmnSTaUst9NBjJYWe2fm
3c6oyatVy6gmdoiMnVLM2nIgzA3YYeR0CjFknwIDAQABAoIBAQCdpxR1xrnmtAJJ
iHl/c6z9/OOI/d/Taaw3ULt4APgzfh3fpvx59HMik2tWPN448NF33A6QUT/+aIHN
lTjaoaVWmCEv3Fe3PQ/9qZj0jy8Znj77TaRa5jipI7GLFxgaOxKR3IkK4bCah24a
DAYe4XykrW/nDreZo7nSwmGacEd+pu59EqxoB1z7gXytSedV/mah4hHn92wXgBwC
kwtzpvqh7qsvAEczdxLZx/gU2/Ri4LGQvdPg8kGftjFRmKTsUuDDq+PZ5bi58ere
lxBt5blocKwpKeyrRJVOX/UUKb6rLTn87XEOp09ogNdglcUZduJ7rOIzrk83zuKj
siZQnv8hAoGBAP88IelMtMk802z8ulGf/j2NZ9oNToIG+lbkewxqetdMEIzKTVYM
RN7LaXxRIJQ+d7Ojow9dLMeZAPXnQaUf0GcZQ7xqGtWZ8PDs6AoGgwZh276u2dy0
e+6HbcAvBhtHbUZ/o5Fr0lwG9YN+gWnP/oxDpss3tDpWofDYdSH43czxAoGBAMlU
dKM4mksYZZG1ZIUyqvmgL4is/jMmYnnj0i5rgc2k7r2v00yRLc9GbWOkS9JqyO4F
65dDczAvwrzxyGj4f0Yq2rSfvWFQkEBRnieXMzPVyrQcTdsOrCcCz+TK5RPnSluV
VgCMJjI2i92kzZ+na2FBeqPlz8aCKb1wPDpa8oqPAoGAQc0+8ObVtQv5dh+x6VlW
MohCPfUwSFWENOKy1oCdKuRxX9rIFWcUWlwW1fYUcCOquKV3ZH6hDNRlawAz7F5H
XE0nKWwxfuAxPevV5r/HB94yyPZLNJtTWCuSH/n/mQjRI1vEz7j8gr1Ijp4Ovzjg
Z0kJt1qlHGU5Wt5zVE7U4AECgYEAtCuBaeQoqBWAJ8JV36F1QolooH53yhyKuhv4
JxSMiBUWleg4RugRP9H96NLKC9cGU4Q2zhpNhgzn0CDrwYzIkWmeaVAesWzger7P
swxrhPLJQR+nSOc7hnnMxCoSkRpF/+mHmlvRftQznLl0TnEL9nAbqXrq0vH/GonL
TEnBjd8CgYAtlllCAqDQPD9GtW/idaKol/NE+WbDOFjO7PSIkcwS4WAC3v/a63xv
KLZ8E01N5J6GV6Twx7/o5GjbHMgJR8kCCMRbwZV2Iy8W539CTsRHr7q9MP9roWlJ
nkCAx8LYFGSCh+jjhCpXet468ipLdcWHTVCVaPVEHQ7sTVbLtNZ3Yw==
-----END RSA PRIVATE KEY-----`,
      pk: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyLpqpUjdaBbsN9shuY0v
NipkPrFZNK583n+VaXmMRPbASyTFA6PlhC7W/e/g1dCspJH0Md+GU7nf/bosq8vl
zQd0Q9iMWXybU08JYr/JIvSRprB3pQ7LPjwkigHgPvXNqb7U/czmX2vfexRRR/gj
uGmAGC8kVUMTHZGAQVdMl188Ydzvnamzh0XquypGuw44WShWMyCExRl44SoVFe2Y
kSKHU3Ivt2VfW9BjhC/5dSQGtzdjp0ZsV7OOCwH19+xFtL3efSH6tJXbM1fuOuyg
/X7kb9KTcmnSTaUst9NBjJYWe2fm3c6oyatVy6gmdoiMnVLM2nIgzA3YYeR0CjFk
nwIDAQAB
-----END PUBLIC KEY-----`
    }

    describe('RSASSA_PSS_SHA256', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA256(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA256(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA256(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA256(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA256(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA256(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA256(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA256(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA256(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PSS_SHA256(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PSS_SHA256(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('RSASSA_PSS_SHA384', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA384(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA384(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA384(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA384(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA384(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA384(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA384(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA384(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA384(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PSS_SHA384(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PSS_SHA384(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('RSASSA_PSS_SHA512', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA512(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA512(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA512(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA512(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA512(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA512(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PSS_SHA512(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PSS_SHA512(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PSS_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsapss-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PSS_SHA512(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PSS_SHA512(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PSS_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsapss-sha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PSS_SHA512(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('RSASSA_PKCS1V1_5_SHA256', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA256(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('RSASSA_PKCS1V1_5_SHA384', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA384(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('RSASSA_PKCS1V1_5_SHA512', () => {

      let sk, pk;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation (private key)', (done) => {

          before(() => { sk = RSAKEYS.sk; });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('without key generation (private and public keys)', (done) => {

          before(() => { sk = RSAKEYS.sk; pk = RSAKEYS.pk });

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, pk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.equal(output.sk, sk);

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, pk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, sk, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk, sk);

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, pk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed signature - callback api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, output.sk, output.signature, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed signature - promise api', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              return magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, output.sk, output.signature);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed signature w/ hex encoding', (done) => {
            magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'rsav1_5-sha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(output.sk.startsWith('-----BEGIN RSA PRIVATE KEY-----'));

              assert.ok(output.signature);

              const esig = output.signature.toString('hex');

              magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, output.sk, esig, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(message, null, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.RSASSA_PKCS1V1_5_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'rsav1_5-sha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.signature);

            const altered = 'Some other message';

            magic.alt.verify.RSASSA_PKCS1V1_5_SHA512(altered, output.sk, output.signature, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid signature');

              done();
            });
          });
        });
      });
    });

    describe('HMAC_SHA256', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(32); });

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.HMAC_SHA256(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              magic.alt.verify.HMAC_SHA256(message, key, output.mac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.HMAC_SHA256(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              return magic.alt.verify.HMAC_SHA256(message, key, output.mac);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.auth.HMAC_SHA256(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              const emac = output.mac.toString('hex');

              magic.alt.verify.HMAC_SHA256(message, ekey, emac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              magic.alt.verify.HMAC_SHA256(message, output.sk, output.mac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.HMAC_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              return magic.alt.verify.HMAC_SHA256(message, output.sk, output.mac);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            magic.alt.auth.HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const ekey = output.sk.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.verify.HMAC_SHA256(message, ekey, emac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            magic.alt.verify.HMAC_SHA256(message, null, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = 'Some other message';

            magic.alt.verify.HMAC_SHA256(altered, output.sk, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if key is altered', (done) => {
          magic.alt.auth.HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = Buffer.from('b3ae620c610b577c1a596fa96259426dc9bcc521c086a348e22b8169b092fcf01f20381e0edca71e4fa9811bc7ed05e9', 'hex');

            magic.alt.verify.HMAC_SHA256(message, altered, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });

    describe('HMAC_SHA512', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(32); });

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.HMAC_SHA512(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              magic.alt.verify.HMAC_SHA512(message, key, output.mac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.HMAC_SHA512(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              return magic.alt.verify.HMAC_SHA512(message, key, output.mac);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.auth.HMAC_SHA512(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              const emac = output.mac.toString('hex');

              magic.alt.verify.HMAC_SHA512(message, ekey, emac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              magic.alt.verify.HMAC_SHA512(message, output.sk, output.mac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.HMAC_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              return magic.alt.verify.HMAC_SHA512(message, output.sk, output.mac);
            }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            magic.alt.auth.HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const ekey = output.sk.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.verify.HMAC_SHA512(message, ekey, emac, (err) => {
                assert.ok(!err);
                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            magic.alt.verify.HMAC_SHA512(message, null, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = 'Some other message';

            magic.alt.verify.HMAC_SHA512(altered, output.sk, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if key is altered', (done) => {
          magic.alt.auth.HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = Buffer.from('b3ae620c610b577c1a596fa96259426dc9bcc521c086a348e22b8169b092fcf01f20381e0edca71e4fa9811bc7ed05e9', 'hex');

            magic.alt.verify.HMAC_SHA512(message, altered, output.mac, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_128_CBC_HMAC_SHA256', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(16);
            akey = crypto.randomBytes(32);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, crypto.randomBytes(16), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, null, crypto.randomBytes(32), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('1cf20c1e94ac59f3ac17e029bc05190f4f5d34d9ead66ed0315644e668dc9cab', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_128_CBC_HMAC_SHA384', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(16);
            akey = crypto.randomBytes(48);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, crypto.randomBytes(16), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, null, crypto.randomBytes(48), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9cba256455c5a1328cfe12578bc1558ef43974a2fa373074ed8091a6c61b63da0c58c6ee31e249a063baf0223e25c6d0', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_128_CBC_HMAC_SHA512', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(16);
            akey = crypto.randomBytes(64);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, crypto.randomBytes(16), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, null, crypto.randomBytes(64), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_128_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('42f77f17198794a8f02480775212498a24a3d88d0e0aecabf97098bb2bcd1ac8fda5943d434e5c66f7c570a36d569439023a97c820917dd5d28dfe513756091c', 'hex');

            magic.alt.decrypt.AES_128_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_192_CBC_HMAC_SHA256', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(24);
            akey = crypto.randomBytes(32);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, crypto.randomBytes(24), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, null, crypto.randomBytes(32), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('1cf20c1e94ac59f3ac17e029bc05190f4f5d34d9ead66ed0315644e668dc9cab', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_192_CBC_HMAC_SHA384', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(24);
            akey = crypto.randomBytes(48);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, crypto.randomBytes(24), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, null, crypto.randomBytes(48), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9cba256455c5a1328cfe12578bc1558ef43974a2fa373074ed8091a6c61b63da0c58c6ee31e249a063baf0223e25c6d0', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_192_CBC_HMAC_SHA512', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(24);
            akey = crypto.randomBytes(64);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, crypto.randomBytes(24), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, null, crypto.randomBytes(64), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_192_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('42f77f17198794a8f02480775212498a24a3d88d0e0aecabf97098bb2bcd1ac8fda5943d434e5c66f7c570a36d569439023a97c820917dd5d28dfe513756091c', 'hex');

            magic.alt.decrypt.AES_192_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_256_CBC_HMAC_SHA256', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(32);
            akey = crypto.randomBytes(32);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, crypto.randomBytes(32), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, null, crypto.randomBytes(32), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('1cf20c1e94ac59f3ac17e029bc05190f4f5d34d9ead66ed0315644e668dc9cab', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA256(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_256_CBC_HMAC_SHA384', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(32);
            akey = crypto.randomBytes(48);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, crypto.randomBytes(32), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, null, crypto.randomBytes(48), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha384');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA384(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9cba256455c5a1328cfe12578bc1558ef43974a2fa373074ed8091a6c61b63da0c58c6ee31e249a063baf0223e25c6d0', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA384(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_256_CBC_HMAC_SHA512', () => {

      let ekey, akey;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => {
            ekey = crypto.randomBytes(32);
            akey = crypto.randomBytes(64);
          });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, ekey, akey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, ekey, akey).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(ekey, akey, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const eekey = ekey.toString('hex');
            const eakey = akey.toString('hex');

            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, eekey, eakey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sek, ekey) === 0);
              assert.ok(Buffer.compare(output.sak, akey) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              return magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, output.mac);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

              const eekey = output.sek.toString('hex');
              const eakey = output.sak.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const emac  = output.mac.toString('hex');

              magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(eekey, eakey, eiv, ect, emac, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error with only encryption key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, crypto.randomBytes(32), null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error with only authentication key on encryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, null, crypto.randomBytes(64), (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of encryption and authentication keys');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(null, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without encryption key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, null, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should error without authentication key on decryption', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256cbc-hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sek);
              assert.ok(output.sak);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.mac);

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(null, output.sak, output.iv, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without encryption and authentication keys');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, output.sak, altered, output.ciphertext, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, altered, output.mac, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });

        it('should fail if mac is altered', (done) => {
          magic.alt.encrypt.AES_256_CBC_HMAC_SHA512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256cbc-hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sek);
            assert.ok(output.sak);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.mac);

            const altered = Buffer.from('42f77f17198794a8f02480775212498a24a3d88d0e0aecabf97098bb2bcd1ac8fda5943d434e5c66f7c570a36d569439023a97c820917dd5d28dfe513756091c', 'hex');

            magic.alt.decrypt.AES_256_CBC_HMAC_SHA512(output.sek, output.sak, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid mac');

              done();
            });
          });
        });
      });
    });


    describe('AES_128_GCM', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(16); });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_GCM(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_128_GCM(key, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_GCM(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_128_GCM(key, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.encrypt.AES_128_GCM(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const etag = output.tag.toString('hex');

              magic.alt.decrypt.AES_128_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_128_GCM(output.sk, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_128_GCM(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_128_GCM(output.sk, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes128gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const ekey  = output.sk.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const etag  = output.tag.toString('hex');

              magic.alt.decrypt.AES_128_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on decryption', (done) => {
          magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            magic.alt.decrypt.AES_128_GCM(null, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without a key');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('4cc885d1285fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_128_GCM(output.sk, altered, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_128_GCM(output.sk, output.iv, altered, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if tag is altered', (done) => {
          magic.alt.encrypt.AES_128_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes128gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('773280e4c1df5869284bb570e334864e', 'hex');

            magic.alt.decrypt.AES_128_GCM(output.sk, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });
      });
    });


    describe('AES_192_GCM', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(24); });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_GCM(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_192_GCM(key, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_GCM(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_192_GCM(key, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.encrypt.AES_192_GCM(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const etag = output.tag.toString('hex');

              magic.alt.decrypt.AES_192_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_192_GCM(output.sk, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_192_GCM(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_192_GCM(output.sk, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes192gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const ekey  = output.sk.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const etag  = output.tag.toString('hex');

              magic.alt.decrypt.AES_192_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on decryption', (done) => {
          magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            magic.alt.decrypt.AES_192_GCM(null, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without a key');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('4cc885d1925fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_192_GCM(output.sk, altered, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_192_GCM(output.sk, output.iv, altered, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if tag is altered', (done) => {
          magic.alt.encrypt.AES_192_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes192gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('773280e4c1df5869284bb570e334864e', 'hex');

            magic.alt.decrypt.AES_192_GCM(output.sk, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });
      });
    });


    describe('AES_256_GCM', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(32); });

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_GCM(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_256_GCM(key, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_GCM(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_256_GCM(key, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.encrypt.AES_256_GCM(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const eiv  = output.iv.toString('hex');
              const ect  = output.ciphertext.toString('hex');
              const etag = output.tag.toString('hex');

              magic.alt.decrypt.AES_256_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              magic.alt.decrypt.AES_256_GCM(output.sk, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.alt.encrypt.AES_256_GCM(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              return magic.alt.decrypt.AES_256_GCM(output.sk, output.iv, output.ciphertext, output.tag);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'aes256gcm');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.iv);
              assert.ok(output.ciphertext);
              assert.ok(output.tag);

              const ekey  = output.sk.toString('hex');
              const eiv   = output.iv.toString('hex');
              const ect   = output.ciphertext.toString('hex');
              const etag  = output.tag.toString('hex');

              magic.alt.decrypt.AES_256_GCM(ekey, eiv, ect, etag, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on decryption', (done) => {
          magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            magic.alt.decrypt.AES_256_GCM(null, output.iv, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without a key');

              done();
            });
          });
        });

        it('should fail if iv is altered', (done) => {
          magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('4cc885d2565fa7253eaf0d8d028e9587', 'hex');

            magic.alt.decrypt.AES_256_GCM(output.sk, altered, output.ciphertext, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('9b2d363003dc9e07acccdf47766ff43378e216d5c6aec796ce0f42af11c9c370eac6e33a2c169d0c24e09310735e4cb9d036a074b3d4cd855084f68cb9ad44475927f3d0931dcac131b9396074e0191103a67c8db673fe1ce13806693f77cd205b5011bad8acf4adfd4bb8a92e900d35', 'hex');

            magic.alt.decrypt.AES_256_GCM(output.sk, output.iv, altered, output.tag, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });

        it('should fail if tag is altered', (done) => {
          magic.alt.encrypt.AES_256_GCM(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'aes256gcm');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.iv);
            assert.ok(output.ciphertext);
            assert.ok(output.tag);

            const altered = Buffer.from('773280e4c1df5869284bb570e334864e', 'hex');

            magic.alt.decrypt.AES_256_GCM(output.sk, output.iv, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Crypto error: Error: Unsupported state or unable to authenticate data');

              done();
            });
          });
        });
      });
    });


    describe('bcrypt', () => {

      const password = 'ascreamingcomesacrossthesky';

      describe('success', () => {

        it('should verify a hashed password - callback api', (done) => {
          magic.alt.password.bcrypt(password, (err, output) => {
            assert.ok(!err);
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'bcrypt');
            assert.equal(output.hash.slice(0, 7), '$2b$10$');

            magic.alt.verify.bcrypt(password, output.hash, (err) => {
              assert.ok(!err);
              done();
            });
          });
        });

        it('should verify a hashed password - promise api', (done) => {
          magic.alt.password.bcrypt(password).then((output) => {
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'bcrypt');
            assert.equal(output.hash.slice(0, 7), '$2b$10$');

            return magic.alt.verify.bcrypt(password, output.hash);
          }).then(() => { done(); }).catch((err) => { assert.ok(!err); });
        });
      });

      describe('failure', () => {

        it('should fail to verify the wrong password', (done) => {
          magic.alt.password.bcrypt(password, (err, output) => {
            assert.ok(!err);
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'bcrypt');
            assert.equal(output.hash.slice(0, 7), '$2b$10$');

            magic.alt.verify.bcrypt('someotherpassword', output.hash, (err) => {
              assert.ok(err);
              assert.equal(err.message, 'Invalid password');

              done();
            });
          });
        });
      });
    });


    describe('sha256', () => {

      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      it('should hash an input - callback api', (done) => {
        magic.alt.util.sha256(message, (err, output) => {
          assert.ok(!err);
          assert.ok(output);

          assert.equal(output.alg, 'sha256');
          assert.equal(output.payload.toString('utf-8'), message);

          assert.equal(output.hash.toString('hex'), '8da03d5f2fd8e039448e8b33484dbeb074c19876828ebd2249b7f537ea70f116');

          done();
        });
      });

      it('should hash an input - promise api', (done) => {
        magic.alt.util.sha256(message).then((output) => {
          assert.ok(output);

          assert.equal(output.alg, 'sha256');
          assert.equal(output.payload.toString('utf-8'), message);

          assert.equal(output.hash.toString('hex'), '8da03d5f2fd8e039448e8b33484dbeb074c19876828ebd2249b7f537ea70f116');

          done();
        }).catch((err) => { assert.ok(!err); });
      });
    });


    describe('sha512', () => {

      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      it('should hash an input - callback api', (done) => {
        magic.alt.util.sha512(message, (err, output) => {
          assert.ok(!err);
          assert.ok(output);

          assert.equal(output.alg, 'sha512');
          assert.equal(output.payload.toString('utf-8'), message);

          assert.equal(output.hash.toString('hex'), '6bf3bdf9c4ad9658e142a9c27f6f0b20f9ed59cbeab30374ddeb2a7daad9bbd19eae14d679e42c25c8f92570d9c79deef9460c7b8c1070a4c988e7ee0ac1328c');

          done();
        });
      });

      it('should hash an input - promise api', (done) => {
        magic.alt.util.sha512(message).then((output) => {
          assert.ok(output);

          assert.equal(output.alg, 'sha512');
          assert.equal(output.payload.toString('utf-8'), message);

          assert.equal(output.hash.toString('hex'), '6bf3bdf9c4ad9658e142a9c27f6f0b20f9ed59cbeab30374ddeb2a7daad9bbd19eae14d679e42c25c8f92570d9c79deef9460c7b8c1070a4c988e7ee0ac1328c');

          done();
        }).catch((err) => { assert.ok(!err); });
      });
    });
  });
});
