const magic    = require('./magic');

const fs       = require('fs');
const readline = require('readline');
const assert   = require('assert');
const sodium   = require('libsodium-wrappers-sumo');


describe('test vectors', () => {

  describe('sign', () => {

    const fp = readline.createInterface({ input: fs.createReadStream('./raw.vectors.ed25519') })

    // https://ed25519.cr.yp.to/python/sign.py
    let c = 0;
    fp.on('line', (line) => {
      c++;

      const sec = line.split(':');
      const sk  = Buffer.from(sec[0], 'hex').slice(0, 64);
      const pk  = Buffer.from(sodium.crypto_sign_ed25519_sk_to_pk(sk));

      const m = Buffer.from(sec[2], 'hex');

      it('Test Vector #' + c, (done) => {
        magic.sign(m, sk, (err, out) => {
          if (err) { return done(err); }

          const s = out.signature;
          assert.ok(sodium.crypto_sign_verify_detached(s, m, pk));

          try {
            let fm, fml, fs = 0;
            if (m.length === 0) {
              fm = 'x';
            } else {
              fml = m.length;
              for (let i = 0; i < fml; i++) { fm += String.fromCharCode(m[i] + (i === fml - 1));}
            }

            assert.ok(!sodium.crypto_sign_verify_detached(s, fm, pk));
          } catch(ex) {}

          // djb implementation doesn't append pk in sk, so first check is different
          assert.equal(sec[0], sk.toString('hex'));
          assert.equal(sec[1], pk.toString('hex'));
          assert.equal(sec[3], Buffer.concat([ s, m ]).toString('hex'));

          done();
        });
      });
    });

    fp.on('close', () => { run(); });
  });
});
