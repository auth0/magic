const magic = require('../magic');

const fs       = require('fs');
const readline = require('readline');
const assert   = require('assert');
const sodium   = require('libsodium-wrappers-sumo');


/***
 * sign
 *
 * test vectors for magic.auth.sign()
 *
 */
function sign(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/ed25519.vec') });

  // https://ed25519.cr.yp.to/python/sign.py
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const sk  = Buffer.from(sec[0], 'hex'); // djb implementation doesn't append pk to sk, so parsing is different
    const pk  = Buffer.from(sodium.crypto_sign_ed25519_sk_to_pk(sk));

    const m = Buffer.from(sec[2], 'hex');

    it('magic.auth.sign - Test Vector #' + c, (done) => {
      magic.auth.sign(m, sk, (err, out) => {
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

        assert.equal(sec[0], sk.toString('hex')); // djb implementation doesn't append pk to sk, so check is different
        assert.equal(sec[1], pk.toString('hex'));
        assert.equal(sec[3], Buffer.concat([ s, m ]).toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * mac
 *
 * test vectors for magic.auth.mac()
 *
 */
function mac(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/hmacsha384.vec') });

  // https://tools.ietf.org/html/rfc4231
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const k = Buffer.from(sec[0], 'hex');
    const m = Buffer.from(sec[1], 'hex');

    it('magic.auth.mac - Test Vector #' + c, (done) => {
      magic.auth.mac(m, k, (err, out) => {
        if (err) { return done(err); }

        const t = out.mac;
        assert.equal(sec[2], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * hash
 *
 * test vectors for magic.util.hash()
 *
 */
function hash(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/sha384.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#sha-2
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.util.hash - Test Vector #' + c, (done) => {
      magic.util.hash(m, (err, out) => {
        if (err) { return done(err); }

        const t = out.hash;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * core
 *
 * core api test definer
 *
 */
function core() {
  const fs = [ sign, mac, hash ];

  (function setup() {
    const f = fs.shift();
    if (!f) { return alt(); }

    f(setup);
  })();
}


// pulled out manually from vector suite so tests can be defined async
const RSAKEYS = {
  pss:  {
    key: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2Vtxyd/uRTuhsafeLB8LCmdXnukdHTrZfkgYKbhu2sdQxI4S
qM2wJsgvJz2vwiIAnw2zsIstsQppxLLd2q7OrBsMhiaC7vKU5Xn1WquHG8Cn7qvJ
I8noDd3CLsCicAKu5qW6Zjl/QSu69ftOr2ahoPgur2gnGYyvSbNHJYsSg+jLsQ2i
g39uzDSQxyj+kn9ERVpvGU83dr95FR2a1+La93CzfRJifMDF+2JIT0YljZziwRsm
JW0Jy0EvjY+PH+kbuUrCfebSaoOoQ55Rs12+5Gs7j/mR1me7U+7uhf8WUsiYHxQd
R8ggV5HO9bMtcY3cCC7Q3VQoJkFrInEGTvQ3qQIDAQABAoIBAC8hsBvpTd5/XsGK
OBfzJ067N/nCbMjA0RacBXlOf+M64x2r/QnTiEXwlKD6tFjxTJcwvm0i0OaZ7nNz
ob3gt/oD54RTZ4Lu4TCdcIGXvjVbYk7Tu0riZkpTct72cIK/YjOrbi7qetij5eee
9eH87EFeb6kjeY8FvaDKmjve20X014HvGk9Qdc2bs5ljXaPppogO0CGnULyYBq+B
+//NSs6vgE7HaAiuGGcVx3LKqWGoYpkcZ8qL/+9rNAh7RNtbWavOCTF3R/x1JS8X
BSYLE91izLx0UJHzwbZPWQMdNAxzYqDhBmqwVU1GbyCaPPUbxks8cMPOUvQT2Bsi
j6Mdnv0CgYEA97ZkCTyr+DNLHA/4JFZNtcE/lBonlzOJOn5avtU20rUaK+rIBzC1
GUoMci9XNUzkt9tEfqMoaxzRx1RUjqPJGg3xveP/cIILY+88dKARlnHRTbPiYDho
oNYHqBvxTz9B+BDDokv1KpT5tpQHilVhlN0Ms2xWqRhG01aQlsYxth8CgYEA4KER
GqEU1bFwLjTSlWXWUyDgXCHXlPOFcq0opgsv/lDQ3T3z+1oO7wSOxQ4US/5SvjDr
8urO7J8RCmALsMK8rPa02r7Am5OHyJqP3hneXO7HgL443KhG15X4JgjPKETpvO2N
gdotkljD70EhVPnlkKFY6grZGArGp5hhS6NBCTcCgYArbdzICc0UrNmESAB3TnI9
ZW4iJxu91JlAmhqKzpLYCkxWWslLCW0Wy/a2pjoh7CNFYLn3gd96OAlHay+P+oMt
gDhb1HdaYFJi6PSudcnfmIDboKgVuo4NdLjO7mc2P57vQPErqSmIl6nYKsfPpvx+
vuqVIm9nIgx4zPp4lLLufQKBgHs4H1fKMNGgCfduxm1pdY4YJLqlXcq5YuSrE/cx
f9wznL8gMuwYVMTMbTyvInclRWJLF8MjButJvmFAmmkWCcWfd0nfBWzSGtPx5SVi
b1XvLcTzk+GG9YVhIMRMZMakNsuKS+uFMSZsRt7BjXU9t64Es+9+j+PeVWat8gE5
xn01AoGBANj3VdHJpjHffzQfddTEkJSKCvGpqH3PdI8MKMNHHIl53LEtA2nVJex9
YqWxdJrctSiHxOcScPMo4m0wbGEHee9N+Wqlluptl8wjAWLD/G1KMCufuYXJJkX6
D82L3vRFgWpfwq9hI8Oah7uHVgc7X3dZeqkSMokG91u/fep36ao1
-----END RSA PRIVATE KEY-----`,
    salt: '6f2841166a64471d4f0b8ed0dbb7db32161da13b'
  },
  v1_5: `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4LFLmc1hzT25wgdmaIQTJPoxdPM85m/9UUOU00F40ppJSTJ2
tndyM+fUaj5ovHyn6JnpAdVPbe4HScPkjd9oaFhn7irmbfiOtWP22xN6n2sXWhEu
DtqDaOiORe/hzhS8YBbVJjlicGavGHLHL2C5FhwdI37rNLD4QbPwiW+f4OFrD3Q1
LRASksxGSn54YbvrhvbfYVHLJlQXxmxWXtiXS9j8mE1d39TrkaPVI0zhtUZ/Ot43
X4AuwHKT8SNu+jBovJGxWFUch1xdwKnW+jIb+UIfCN6skQ41wcKFSe6O7YMwz3BZ
X/cLlLSZB+J2mKnZEfesBwavyxpKOf6ziwqASQIDAQABAoIBAB28qS5CRcLVe/un
YhDMBgKbUCdTt8ghoyt5n70zyYtJ2xAiax6sAUPIV072UoM7ljdNA074TapVWcaT
8/Ao1JcWuC6Ho/aC8lQkVjvZQJ3PnQgRBQD3P3QHbyjnXgGZsfKfovcLmjEZDexU
6HKnQOehseOMPRG8qCZ964Qs70JiI3rIdXJQaPMlY7R4rKjWqZ80y4h2uXFFsuhS
nsit6oPq1Oxj4/8tF6L/77BckCynqSFoN4yJ91ySj8TwcH5DSHpPR99wyuh+JCcs
E20+mM9ZBm1Bo9A4hX0HPYtNLCe48Opr+lDSYwkaShjGP0RryaYejEpog0eyQ17I
5y7drqcCgYEA9VYIoLvyKKPKwgdfzVHO6N1m/kglkrW8QwUtIfKlhanmYsTS+MMb
mYPFauoO5gZcK326G55MCyXCWMC6KfmiDYMtgUDBMXePelNxzI0C6gsIJ/qeSLiQ
RGKJ+53CZrDhEmBH0l5otgPmx7RwcIR9yCnkMbpLRvWwrkep9Uxt8qsCgYEA6nWN
R4gv7M9IJqEdToCPoCE4FEyvFC41kdfiXJG43shpFF3ZzmBL2q1hqdW1nzSrFRdB
Y4cw7MON8HEd+nDabLWN26C64fo1YfLyCuOoWnEaBYKCiBCetpsSJrEvBXxeVUrQ
QVOd87VVjVnAYqXyL0fJvJeWoMYE4vk2+l+zuNsCgYEAwfQBIClVmWFb8ybnSyeo
vxoByXd6FNEOA6H8+0CcMN6Pn3fhHf8JO8Ub9pkRrDJM/akIz7rGfW2dhpLe2j5b
KfmRqQRrd1MBIAEGD2NPcX3FNe4A4pbenuGUGlKvFIYzeVaakSpH99V/xlPVLG7i
DbNojxOrXW7w/ebz61Q/+78CgYEA4+Bm9TxfYCnC9ZCoXFFFxxwiVlCF5fZXqK2L
2+7iIN3mi54AAL7FWwAjKR+GS/uzwGb+7c5K9gPHJAe9XFltYjU/cFSS7unyEoY/
S+gjC+xbnzlOxxJoQBEOHj8d9ZYAVaPGL4gmv+TiBuVRwE+LyPpcEAnBo/dybmxM
TCLSGfsCgYEA3nca2fjl7q9y6DKHNcLqXgxApqrcixpZhTepbrEIwAyq9+fsGrlc
fUJGTMojm+lySSNIY4BwW9PNmbxDhi6X7KTpHeytRychzUaOZrq6xOKIGZYzh5wU
tHfCire4oghtHumbIkmGYWI8CgkzyCd1QdrCl4jHzbKN5oaiJ+O+1Aw=
-----END RSA PRIVATE KEY-----`
}


/***
 * rsapsssha256
 *
 * test vectors for magic.alt.auth.rsapsssha256()
 *
 */
function rsapsssha256(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsapsssha256.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    // crypto api doesn't allow specifying salt, so we must skip
    it.skip('magic.alt.auth.rsapsssha256 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsapsssha256(m, RSAKEYS.pss, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * rsapsssha384
 *
 * test vectors for magic.alt.auth.rsapsssha384()
 *
 */
function rsapsssha384(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsapsssha384.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    // crypto api doesn't allow specifying salt, so we must skip
    it.skip('magic.alt.auth.rsapsssha384 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsapsssha384(m, RSAKEYS.pss, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * rsapsssha512
 *
 * test vectors for magic.alt.auth.rsapsssha512()
 *
 */
function rsapsssha512(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsapsssha512.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    // crypto api doesn't allow specifying salt, so we must skip
    it.skip('magic.alt.auth.rsapsssha512 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsapsssha512(m, RSAKEYS.pss, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * rsav1_5sha256
 *
 * test vectors for magic.alt.auth.rsav1_5sha256()
 *
 */
function rsav1_5sha256(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsav1_5sha256.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.alt.auth.rsav1_5sha256 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsav1_5sha256(m, RSAKEYS.v1_5, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * rsav1_5sha384
 *
 * test vectors for magic.alt.auth.rsav1_5sha384()
 *
 */
function rsav1_5sha384(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsav1_5sha384.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.alt.auth.rsav1_5sha384 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsav1_5sha384(m, RSAKEYS.v1_5, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * rsav1_5sha512
 *
 * test vectors for magic.alt.auth.rsav1_5sha512()
 *
 */
function rsav1_5sha512(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/rsav1_5sha512.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.alt.auth.rsav1_5sha512 - Test Vector #' + c, (done) => {
      magic.alt.auth.rsav1_5sha512(m, RSAKEYS.v1_5, (err, out) => {
        if (err) { return done(err); }

        const t = out.signature;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * hmacsha256
 *
 * test vectors for magic.alt.auth.hmacsha256()
 *
 */
function hmacsha256(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/hmacsha256.vec') });

  // https://tools.ietf.org/html/rfc4231
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const k = Buffer.from(sec[0], 'hex');
    const m = Buffer.from(sec[1], 'hex');

    it('magic.alt.auth.hmacsha256 - Test Vector #' + c, (done) => {
      magic.alt.auth.hmacsha256(m, k, (err, out) => {
        if (err) { return done(err); }

        const t = out.mac;
        assert.equal(sec[2], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * hmacsha512
 *
 * test vectors for magic.alt.auth.hmacsha512()
 *
 */
function hmacsha512(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/hmacsha512.vec') });

  // https://tools.ietf.org/html/rfc4231
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const k = Buffer.from(sec[0], 'hex');
    const m = Buffer.from(sec[1], 'hex');

    it('magic.alt.auth.hmacsha512 - Test Vector #' + c, (done) => {
      magic.alt.auth.hmacsha512(m, k, (err, out) => {
        if (err) { return done(err); }

        const t = out.mac;
        assert.equal(sec[2], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * sha256
 *
 * test vectors for magic.alt.util.sha256()
 *
 */
function sha256(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/sha256.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#sha-2
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.alt.util.sha256 - Test Vector #' + c, (done) => {
      magic.alt.util.sha256(m, (err, out) => {
        if (err) { return done(err); }

        const t = out.hash;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * sha512
 *
 * test vectors for magic.alt.util.sha512()
 *
 */
function sha512(cont) {

  // path resolution is from parent directory
  const fp = readline.createInterface({ input: fs.createReadStream('./test/vectors/sha512.vec') });

  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#sha-2
  let c = 0;
  fp.on('line', (line) => {
    c++;

    const sec = line.split(':');
    const m = Buffer.from(sec[0], 'hex');

    it('magic.alt.util.sha512 - Test Vector #' + c, (done) => {
      magic.alt.util.sha512(m, (err, out) => {
        if (err) { return done(err); }

        const t = out.hash;
        assert.equal(sec[1], t.toString('hex'));

        done();
      });
    });
  });

  fp.on('close', () => { cont(); });
}


/***
 * alt
 *
 * alt api test definer
 *
 */
function alt() {
  const fs = [ rsapsssha256, rsapsssha384, rsapsssha512, rsav1_5sha256, rsav1_5sha384, rsav1_5sha512, hmacsha256, hmacsha512, sha256, sha512 ];

  (function setup() {
    const f = fs.shift();
    if (!f) { return run(); }

    f(setup);
  })();
}


// TODO: Figure out why this describe doesn't print
describe('test vectors', () => {
  const apis = [ core, alt ];

  (function setup() {
    const api = apis.shift();
    if (!api) { return run(); }

    api(setup);
  })();
});
