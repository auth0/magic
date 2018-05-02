const magic = require('./magic');

const crypto = require('crypto');
const assert = require('assert');


describe('magic tests', () => {

  describe('mac', () => {

    let key;
    const message = 'A screaming comes across the sky. It has happened before, but there is nothing to compare it to now.';

    describe('success', () => {

      describe('without key generation', () => {

        beforeEach(() => { key = crypto.randomBytes(48); })

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

          const altered = Buffer.from('Some other key that is not the original key and therefore should not work.');

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
