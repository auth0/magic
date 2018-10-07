const magic = require('../magic')
const sodium = require('libsodium-wrappers-sumo');
const fs  = require('fs')

const args = process.argv.slice(2)

const passwordHash = function(password, cb) {
  magic.password.hash(password, (err, output) => {
    if (err) { return cb(err); }
	cb(null, output.hash)
  });
}

const passwordCompare = function(password, hash, cb) {
  magic.verify.password(password, hash, (err) => {
    cb(!err);
  });
}

const prng = function(length, cb) {
  magic.util.rand(length, (err, bytes) => {
    if (err) { return cb(err) }
	cb(null, bytes.toString('hex')) 
  })
}

const utilHash =  function(message, cb) {
  magic.util.hash(message, (err, output) => {
    if (err) { return cb(err); }
	cb(err, output.hash.toString('hex'))
  });
}

const hmacAuth =  function(message, cb) {
  magic.auth.mac(message, (err, output) => {
    if (err) { return cb(err); }
	cb(err, output.mac.toString('hex'), output.sk.toString('hex'))
  });
}

const hmacVerify =  function(message, key, mac, cb) {
  magic.verify.mac(message, key, mac, (err) => {
    cb(!err);
  });
}

const signAuth =  function(message, cb) {
  magic.auth.sign(message, (err, output) => {
    if (err) { return cb(err); }
	cb(err, output.signature.toString('hex'), output.sk.toString('hex'))
  });
}

const signVerify =  function(message, key, signature, cb) {
  magic.verify.sign(message, key, signature, (err) => {
    cb(!err);
  });
}

const uid = function(cb) {
  magic.util.uid((err, uid) => {
	if (err) { return cb(err); }
	cb(null, uid);
  });
}
const encrAsync = function(message, cb) {
  magic.encrypt.async(message, (err, output) => {
	if (err) { return cb(err) }
	cb(
	  null,
	  output.sk.toString('hex'), 
	  output.pk.toString('hex'),
	  output.ciphertext.toString('hex'),
	  output.nonce.toString('hex')
	)
  })
}

const decrAsync = function(sk, pk, ciphertext, nonce, cb) {
  magic.decrypt.async(sk, pk, ciphertext, nonce, (err, plaintext) => {
	if (err) { return cb(err) }
	cb(null, plaintext.toString('utf-8'))
  });
}

const encrSync = function(message, cb) {
  magic.encrypt.sync(message, (err, output) => {
	if (err) { return cb(err) }
	cb(
	  null,
	  output.sk.toString('hex'), 
	  output.ciphertext.toString('hex'),
	  output.nonce.toString('hex')
	)
  })
}

const decrSync = function(sk, ciphertext, nonce, cb) {
  magic.decrypt.sync(sk, ciphertext, nonce, (err, plaintext) => {
	if (err) { return cb(err) }
	cb(null, plaintext.toString('utf-8'))
  });
}

switch(args[0]) {
  case 'passwordhash':
	if (!args[1]) {
      console.log('you should provide a password')
    } else {
      passwordHash(args[1], (err, hash) => {
	    if (err) { console.log(err) }
	    console.log(hash)
	  })	
    }
    break;
  case 'passwordcompare':
	if (!args[1] || !args[2]) {
      console.log('you should provide the following with this order: message, hash')
    } else {
      passwordCompare(args[1], args[2], (success) => {
	    if (success) { 
	      console.log('password verified')
	    } else {
	    	console.log('invalid hash')
	    }
	  })	
    }
    break;
  case 'prng':
	if (!args[1]) {
      console.log('you should provide the length of the random value')
    } else {
      prng(parseInt(args[1], 10), (err, random) => {
	    if (err) { console.log(err) }
	    console.log(random)
	  })	
    }
    break;
  case 'hash':
	if (!args[1]) {
      console.log('you should provide a message to be hashed')
    } else {
      utilHash(args[1], (err, hash) => {
	    if (err) { console.log(err) }
	    console.log(hash)
	  })	
    }
    break;
  case 'uid':
    uid((err, uid) => {
	  if (err) { console.log(err) }
	  console.log(uid)
	})	
    break;
  case 'hmacauth':
	if (!args[1]) {
      console.log('you should provide the message to be hmac\'ed')
    } else {
      hmacAuth(args[1], (err, mac, key) => {
	    if (err) { console.log(err) }
	    console.log('mac:', mac, '\nsecret key:', key)
	  })	
	}
    break;
  case 'hmacverify':
	if (!args[1] || !args[2] || !args[3]) {
      console.log('you should provide the following with this order: message, key, mac')
    } else {
      hmacVerify(args[1], args[2], args[3], (success) => {
	    if (success) { 
	      console.log('message signature verified')
	    } else {
	      console.log('invalid mac')
	    }
	  })	
	}
    break;
  case 'signauth':
	if (!args[1]) {
      console.log('you should provide the message to be signed')
    } else {
      signAuth(args[1], (err, sign, key) => {
	    if (err) { console.log(err) }
	    console.log('signature:', sign, '\nsecret key:', key)
	  })	
	}
    break;
  case 'signverify':
	if (!args[1] || !args[2] || !args[3]) {
      console.log('you should provide the following with this order: message, key, signature')
    } else {
      signVerify(args[1], args[2], args[3], (success) => {
	    if (success) { 
	      console.log('message signature verified')
	    } else {
	      console.log('invalid signature')
	    }
	  })	
	}
    break;
  case 'encrasync':
	if (!args[1]) {
      console.log('you should provide the message to be encrypted')
    } else {
      encrAsync(args[1], (err, sk, pk, ciphertext, nonce) => {
	    if (err) { console.log(err) }
	    console.log('secret key used:', sk)
	    console.log('public key used:', pk)
	    console.log('nonce used:', nonce)
	    console.log('ciphertext:', ciphertext)
	  })	
	}
    break;
  case 'decrasync':
	if (!args[1] || !args[2] || !args[3] || !args[4]) {
      console.log('you should provide the following with this order: secret key for decryption, pyblic key for verification, ciphertext, nonce')
    } else {
      decrAsync(args[1], args[2], args[3], args[4], (err, plaintext) => {
	    if (err) { console.log(err) }
	    console.log('plaintext:', plaintext)
	  })	
	}
    break;
  case 'encrsync':
	if (!args[1]) {
      console.log('you should provide the message to be encrypted')
    } else {
      encrSync(args[1], (err, sk, ciphertext, nonce) => {
	    if (err) { console.log(err) }
	    console.log('secret key used:', sk)
	    console.log('nonce used:', nonce)
	    console.log('ciphertext:', ciphertext)
	  })	
	}
    break;
  case 'decrsync':
	if (!args[1] || !args[2] || !args[3]) {
      console.log('you should provide the following with this order: secret key, ciphertext, nonce')
    } else {
      decrSync(args[1], args[2], args[3], (err, plaintext) => {
	    if (err) { console.log(err) }
	    console.log('plaintext:', plaintext)
	  })	
	}
    break;
  default:
    fs.readFile('./usage.txt', function (err, data) {
      if (err) throw err;
      console.log(data.toString('utf-8'));
    });
}
