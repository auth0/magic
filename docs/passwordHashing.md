# Password Hashing

magic supports the following password hash functions in its core API:
* [magic.password.hash | magic.verify.password](#magicpasswordhash--magicverifypassword): Implements argon2

The alt API also supports the following functions:
* [magic.alt.password.bcrypt | magic.alt.verify.bcrypt](magicaltpasswordbcrypt--magicaltverifybcrypt): Implements bcrypt with 10 rounds

Remember that the alt API should only be used over the core API when required by an external specification or interoperability concerns.

## core API

### magic.password.hash | magic.verify.password

Implements `argon2id` password hashing using `libsodium.js`.

The winner of the [Password Hashing Competition](https://password-hashing.net/) and now the [OWASP recommendation](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Leverage_an_adaptive_one-way_function), `argon2id` is robust against both memory tradeoff and side-channel attacks.

The output of the `argon2id` function is encoded with a prefix and other metadata, and so `output.hash` is encoded as a string, not a raw binary buffer as is normal for the rest of the `magic` api. Nor is the raw password itself returned.

```js
const pw = 'ascream...';

// callback
magic.password.hash(password, (err, output) => {
  if (err) { return cb(err); }
  console.log(output);
  // { alg:  'argon2id',
  //   hash: '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM' }
});

// promise
magic.password.hash(password)
  .then((output) => {
    console.log(output);
    // { alg:  'argon2id',
    //   hash: '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM' }
  })
  .catch((err) => {
    return reject(err);
  });
});
```

Due to the metadata in the hash output, it must be provided in the same encoded format for verification.

```js
const pw   = 'ascream...';
const hash = '$argon2id$v=19$m=65536,t=2,p=1$yLZ6CoF5exPHbHjvbZ3esQ$yAM5pHM9KnTYDg/9Nr9rgDdQqRpAe8JVky4mJ7escHM';

// callback
magic.verify.password(password, hash, (err) => {
  if (err) { return cb(err); }
  console.log('verified');
  // verified
});

// promise
magic.verify.password(password, hash)
  .then(() => {
    console.log('verified');
    // verified
  })
  .catch((err) => {
    return reject(err);
  });
});
```

## alt API

### magic.alt.password.bcrypt | magic.alt.verify.bcrypt

Implements `bcrypt` using [node.bcrypt.js](https://github.com/kelektiv/node.bcrypt.js/), wrapping the OpenBSD implementation of the algorithm. An alterative to `magic.util.pwhash`. The security parameter (rounds) is set to 10.
