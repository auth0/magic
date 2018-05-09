const magic = require('../magic');

const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');
const assert = require('assert');


describe('magic tests', () => {

  describe('core api', () => {

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

              magic.verify.sign(message, pk, output.signature, true, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
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

              magic.verify.sign(message, epk, esig, true, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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

              magic.verify.sign(message, seed, output.signature, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
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

              magic.verify.sign(message, eseed, esig, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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

              magic.verify.sign(message, output.sk, output.signature, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
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

              magic.verify.sign(message, eseed, esig, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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

            magic.verify.sign(message, null, output.signature, false, (err, verified) => {
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

            magic.verify.sign(altered, output.sk, output.signature, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

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

            magic.verify.sign(message, altered, output.signature, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

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

              magic.verify.mac(message, key, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
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

              magic.verify.mac(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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

              magic.verify.mac(message, output.sk, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
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

              magic.verify.mac(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

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

            magic.verify.mac(message, null, output.mac, (err, verified) => {
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

            magic.verify.mac(altered, output.sk, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

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

            magic.verify.mac(message, altered, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

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

          it.only('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.encrypt.async(message, sk, pk, (err, output) => {
              console.log(output);
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, sk) === 0);
              assert.ok(Buffer.compare(output.pk, pk) === 0);

              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.async(sk, pk, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.encrypt.async(message, sk, pk).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, sk) === 0);
              assert.ok(Buffer.compare(output.pk, pk) === 0);

              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              return magic.decrypt.async(sk, pk, output.ciphertext, output.nonce);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            const esk = sk.toString('hex');
            const epk = pk.toString('hex');

            magic.encrypt.async(message, esk, epk, (err, output) => {
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

              magic.decrypt.async(esk, epk, ect, en, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should encrypt and decrypt an authenticated message - callback api', (done) => {
            magic.encrypt.async(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              magic.decrypt.async(output.sk, output.pk, output.ciphertext, output.nonce, (err, plaintext) => {
                assert.ok(!err);
                assert.equal(plaintext.toString('utf-8'), message);

                done();
              });
            });
          });

          it('should encrypt and decrypt an authenticated message - promise api', (done) => {
            magic.encrypt.async(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'x25519-xsalsa20poly1305');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.pk);
              assert.ok(output.ciphertext);
              assert.ok(output.nonce);

              return magic.decrypt.async(output.sk, output.pk, output.ciphertext, output.nonce);
            }).then((plaintext) => {
              assert.equal(plaintext.toString('utf-8'), message);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should encrypt and decrypt an authenticated message w/ hex encoding', (done) => {
            magic.encrypt.async(message, (err, output) => {
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

              magic.decrypt.async(esk, epk, ect, en, (err, plaintext) => {
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
          magic.encrypt.async(message, sodium.crypto_box_keypair().privateKey, null, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of private and public keys.');

            done();
          });
        });

        it('should error with only public key on encryption', (done) => {
          magic.encrypt.async(message, null, sodium.crypto_box_keypair().publicKey, (err, output) => {
            assert.ok(err);
            assert.equal(err.message, 'Requires both or neither of private and public keys.');

            done();
          });
        });

        it('should error without keys on decryption', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            magic.decrypt.async(null, null, output.ciphertext, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without both private and public key.');

              done();
            });
          });
        });

        it('should error without private key on decryption', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            magic.decrypt.async(null, output.pk, output.ciphertext, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without both private and public key.');

              done();
            });
          });
        });

        it('should error without public key on decryption', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            magic.decrypt.async(output.sk, null, output.ciphertext, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot decrypt without both private and public key.');

              done();
            });
          });
        });

        it('should fail if ciphertext is altered', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            const altered = Buffer.from('b16da2bec401fc7a1d4723025ed2fa122f400631018cae837bade02289ee4e187541f57ee6efbc33ad4e08b5465bb6534d3edc7305c27fa6f61dc165f57f0ef79b64bb3d7409a83d2f196ad2496284d2caf934ad8047a17dfefe5c318afc96cda61e71e06d3ebcb60140a97666d7a0cc2512aa31', 'hex');

            magic.decrypt.async(output.sk, output.pk, altered, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

              done();
            });
          });
        });

        it('should fail if nonce is altered', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            const altered = Buffer.from('f5319d1c72f6019683fa7992bb5acf3f540a9ae870f3806f', 'hex');

            magic.decrypt.async(output.sk, output.pk, output.ciphertext, altered, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

              done();
            });
          });
        });

        it('should fail if private key is altered', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            const altered = Buffer.from('a6849c76c3c1e33e9a39109ebcc78876816e8ab5fab9326f8e0654d2fe987686', 'hex');

            magic.decrypt.async(altered, output.pk, output.ciphertext, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

              done();
            });
          });
        });

        it('should fail if public key is altered', (done) => {
          magic.encrypt.async(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'x25519-xsalsa20poly1305');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.pk);
            assert.ok(output.ciphertext);
            assert.ok(output.nonce);

            const altered = Buffer.from('a6849c76c3c1e33e9a39109ebcc78876816e8ab5fab9326f8e0654d2fe987686', 'hex');

            magic.decrypt.async(output.sk, altered, output.ciphertext, output.nonce, (err, plaintext) => {
              assert.ok(err);
              assert.equal(err.message, 'Libsodium error: Error: incorrect key pair for the given ciphertext');

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

    describe('pwhash', () => {

      const password = 'ascreamingcomesacrossthesky';

      describe('success', () => {

        it('should verify a hashed password - callback api', (done) => {
          magic.util.pwhash(password, (err, output) => {
            assert.ok(!err);
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'argon2id');
            assert.equal(output.hash.slice(0, 9), '$argon2id');

            magic.util.pwverify(password, output.hash, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, true);

              done();
            });
          });
        });

        it('should verify a hashed password - promise api', (done) => {
          magic.util.pwhash(password).then((output) => {
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'argon2id');
            assert.equal(output.hash.slice(0, 9), '$argon2id');

            return magic.util.pwverify(password, output.hash);
          }).then((verified) => {
            assert.equal(verified, true);

            done();
          }).catch((err) => { assert.ok(!err); });
        });
      });

      describe('failure', () => {

        it('should fail to verify the wrong password', (done) => {
          magic.util.pwhash(password, (err, output) => {
            assert.ok(!err);
            assert.ok(output);
            assert.ok(output.hash);

            assert.equal(output.alg, 'argon2id');
            assert.equal(output.hash.slice(0, 9), '$argon2id');

            magic.util.pwverify('someotherpassword', output.hash, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

              done();
            });
          });
        });
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
  });


  describe('alt api', () => {

    describe('hmacsha256', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(32); });

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.hmacsha256(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              magic.alt.verify.hmacsha256(message, key, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.hmacsha256(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              return magic.alt.verify.hmacsha256(message, key, output.mac);
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.auth.hmacsha256(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              const emac = output.mac.toString('hex');

              magic.alt.verify.hmacsha256(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.hmacsha256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              magic.alt.verify.hmacsha256(message, output.sk, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.hmacsha256(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              return magic.alt.verify.hmacsha256(message, output.sk, output.mac);
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            magic.alt.auth.hmacsha256(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha256');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const ekey = output.sk.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.verify.hmacsha256(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.hmacsha256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            magic.alt.verify.hmacsha256(message, null, output.mac, (err, verified) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.hmacsha256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = 'Some other message';

            magic.alt.verify.hmacsha256(altered, output.sk, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

              done();
            });
          });
        });

        it('should fail if key is altered', (done) => {
          magic.alt.auth.hmacsha256(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha256');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = Buffer.from('b3ae620c610b577c1a596fa96259426dc9bcc521c086a348e22b8169b092fcf01f20381e0edca71e4fa9811bc7ed05e9', 'hex');

            magic.alt.verify.hmacsha256(message, altered, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

              done();
            });
          });
        });
      });
    });

    describe('hmacsha512', () => {

      let key;
      const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

      describe('success', () => {

        describe('without key generation', () => {

          beforeEach(() => { key = crypto.randomBytes(32); });

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.hmacsha512(message, key, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              magic.alt.verify.hmacsha512(message, key, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.hmacsha512(message, key).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              return magic.alt.verify.hmacsha512(message, key, output.mac);
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            const ekey = key.toString('hex');

            magic.alt.auth.hmacsha512(message, ekey, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);
              assert.ok(Buffer.compare(output.sk, key) === 0);

              assert.ok(output.mac);

              const emac = output.mac.toString('hex');

              magic.alt.verify.hmacsha512(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });
        });

        describe('with key generation', () => {

          it('should verify a computed mac - callback api', (done) => {
            magic.alt.auth.hmacsha512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              magic.alt.verify.hmacsha512(message, output.sk, output.mac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });

          it('should verify a computed mac - promise api', (done) => {
            magic.alt.auth.hmacsha512(message).then((output) => {
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              return magic.alt.verify.hmacsha512(message, output.sk, output.mac);
            }).then((verified) => {
              assert.equal(verified, true);

              done();
            }).catch((err) => { assert.ok(!err); });
          });

          it('should verify a computed mac w/ hex encoding', (done) => {
            magic.alt.auth.hmacsha512(message, (err, output) => {
              assert.ok(!err);
              assert.ok(output);

              assert.equal(output.alg, 'hmacsha512');
              assert.equal(output.payload.toString('utf-8'), message);

              assert.ok(output.sk);
              assert.ok(output.mac);

              const ekey = output.sk.toString('hex');
              const emac = output.mac.toString('hex');

              magic.alt.verify.hmacsha512(message, ekey, emac, (err, verified) => {
                assert.ok(!err);
                assert.equal(verified, true);

                done();
              });
            });
          });
        });
      });

      describe('failure', () => {

        it('should error without key on validation', (done) => {
          magic.alt.auth.hmacsha512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            magic.alt.verify.hmacsha512(message, null, output.mac, (err, verified) => {
              assert.ok(err);
              assert.equal(err.message, 'Cannot verify without a key');

              done();
            });
          });
        });

        it('should fail if message is altered', (done) => {
          magic.alt.auth.hmacsha512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = 'Some other message';

            magic.alt.verify.hmacsha512(altered, output.sk, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

              done();
            });
          });
        });

        it('should fail if key is altered', (done) => {
          magic.alt.auth.hmacsha512(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmacsha512');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const altered = Buffer.from('b3ae620c610b577c1a596fa96259426dc9bcc521c086a348e22b8169b092fcf01f20381e0edca71e4fa9811bc7ed05e9', 'hex');

            magic.alt.verify.hmacsha512(message, altered, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.equal(verified, false);

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
