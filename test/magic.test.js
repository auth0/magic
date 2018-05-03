const magic = require('../magic');

const crypto = require('crypto');
const sodium = require('libsodium-wrappers-sumo');
const assert = require('assert');


describe('magic tests', () => {

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
              assert.ok(verified);

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
            assert.ok(verified);

            done();
          }).catch((err) => { assert.ok(false); });
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
              assert.ok(verified);

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

            magic.verify.sign(message, output.sk, output.signature, (err, verified) => {
              assert.ok(!err);
              assert.ok(verified);

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

            return magic.verify.sign(message, output.sk, output.signature);
          }).then((verified) => {
            assert.ok(verified);

            done();
          }).catch((err) => { assert.ok(false); });
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
              assert.ok(verified);

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
              assert.ok(verified);

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
            assert.ok(verified);

            done();
          }).catch((err) => { assert.ok(false); });
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
              assert.ok(verified);

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

      it('should error if message is altered', (done) => {
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

      it('should error if key is altered', (done) => {
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

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);
            assert.ok(Buffer.compare(output.sk, key) === 0);

            assert.ok(output.mac);

            magic.verify.mac(message, output.sk, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.ok(verified);

              done();
            });
          });
        });

        it('should verify a computed mac - promise api', (done) => {
          magic.auth.mac(message, key).then((output) => {
            assert.ok(output);

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);
            assert.ok(Buffer.compare(output.sk, key) === 0);

            assert.ok(output.mac);

            return magic.verify.mac(message, output.sk, output.mac);
          }).then((verified) => {
            assert.ok(verified);

            done();
          }).catch((err) => { assert.ok(false); });
        });

        it('should verify a computed mac w/ hex encoding', (done) => {
          const ekey = key.toString('hex');

          magic.auth.mac(message, ekey, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);
            assert.ok(Buffer.compare(output.sk, key) === 0);

            assert.ok(output.mac);

            const emac = output.mac.toString('hex');

            magic.verify.mac(message, ekey, emac, (err, verified) => {
              assert.ok(!err);
              assert.ok(verified);

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

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            magic.verify.mac(message, output.sk, output.mac, (err, verified) => {
              assert.ok(!err);
              assert.ok(verified);

              done();
            });
          });
        });

        it('should verify a computed mac - promise api', (done) => {
          magic.auth.mac(message).then((output) => {
            assert.ok(output);

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            return magic.verify.mac(message, output.sk, output.mac);
          }).then((verified) => {
            assert.ok(verified);

            done();
          }).catch((err) => { assert.ok(false); });
        });

        it('should verify a computed mac w/ hex encoding', (done) => {
          magic.auth.mac(message, (err, output) => {
            assert.ok(!err);
            assert.ok(output);

            assert.equal(output.alg, 'hmac-sha384');
            assert.equal(output.payload.toString('utf-8'), message);

            assert.ok(output.sk);
            assert.ok(output.mac);

            const ekey = output.sk.toString('hex');
            const emac = output.mac.toString('hex');

            magic.verify.mac(message, ekey, emac, (err, verified) => {
              assert.ok(!err);
              assert.ok(verified);

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

          assert.equal(output.alg, 'hmac-sha384');
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

      it('should error if message is altered', (done) => {
        magic.auth.mac(message, (err, output) => {
          assert.ok(!err);
          assert.ok(output);

          assert.equal(output.alg, 'hmac-sha384');
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

      it('should error if key is altered', (done) => {
        magic.auth.mac(message, (err, output) => {
          assert.ok(!err);
          assert.ok(output);

          assert.equal(output.alg, 'hmac-sha384');
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
});
