// extcrypto.cc - some openssl wrappers to extend RSA support
#include <node.h>
#include <string.h>
#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <nan.h>

namespace extcrypto {

  using Nan::Callback;
  using Nan::FunctionCallbackInfo;
  using Nan::GetFunction;
  using Nan::New;
  using Nan::Set;
  using Nan::Utf8String;

  using v8::Exception;
  using v8::Function;
  using v8::Isolate;
  using v8::Local;
  using v8::Null;
  using v8::Object;
  using v8::String;
  using v8::Value;


  void ret(Isolate* isolate, Local<Function> cb, Local<String> statement) {
    const uint64_t argc = 2;
    Local<Value> argv[argc] = { Null(isolate), statement };
    Nan::Callback callback(cb);

    callback.Call(v8::Object::New(isolate), argc, argv);
  }


  void eret(Isolate* isolate, Local<Function> cb, Local<String> statement) {
    const uint64_t argc = 1;
    Local<Value> argv[argc] = { Exception::Error(statement) };
    Nan::Callback callback(cb);

    callback.Call(v8::Object::New(isolate), argc, argv);
  }


  void keygen(const Nan::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate   = args.GetIsolate();
    Local<Function> cb = Local<Function>::Cast(args[0]);

    BIGNUM* exp = BN_new();
    BN_set_word(exp, RSA_F4); // 65537

    RSA* rsa   = RSA_new();
    int64_t kg = RSA_generate_key_ex(rsa, 2048, exp, NULL);
    if (!kg) { return eret(isolate, cb, String::NewFromUtf8(isolate, "Unable to generate key")); }

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    uint64_t kl = BIO_pending(bio);
    char* key   = (char *) calloc(kl + 1, 1);

    if (!key || (kl == UINT64_MAX)) {
      free(key); // in case overflow has calloc return a non-null pointer to zero memory
      BIO_vfree(bio);
      RSA_free(rsa);
      BN_free(exp);
      return eret(isolate, cb, String::NewFromUtf8(isolate, "Unable to generate key"));
    }

    BIO_read(bio, key, kl);

    BIO_vfree(bio);
    RSA_free(rsa);
    BN_free(exp);

    Local<String> rval = String::NewFromUtf8(isolate, key);
    free(key);

    return ret(isolate, cb, rval);
  }


  void extract(const Nan::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate   = args.GetIsolate();
    Local<String> pem  = Local<String>::Cast(args[0]);
    Local<Function> cb = Local<Function>::Cast(args[1]);

    Nan::Utf8String ipem(pem);
    char* skey(*ipem);

    BIO* bio = BIO_new(BIO_s_mem());
    RSA* rsa = RSA_new();

    BIO_write(bio, skey, strlen(skey));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio, rsa);

    uint64_t kl = BIO_pending(bio);
    char* pkey  = (char *) calloc(kl + 1, 1);

    if (!pkey || (kl == UINT64_MAX)) {
      free(pkey); // in case overflow has calloc return a non-null pointer to zero memory
      BIO_vfree(bio);
      RSA_free(rsa);
      return eret(isolate, cb, String::NewFromUtf8(isolate, "Unable to generate key"));
    }

    BIO_read(bio, pkey, kl);

    BIO_vfree(bio);
    RSA_free(rsa);

    Local<String> rval = String::NewFromUtf8(isolate, pkey);
    free(pkey);

    return ret(isolate, cb, rval);
  }

  void extractSPKI(const Nan::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate   = args.GetIsolate();
    Local<String> pem  = Local<String>::Cast(args[0]);
    Local<Function> cb = Local<Function>::Cast(args[1]);

    Nan::Utf8String ipem(pem);
    char* skey(*ipem);

    BIO* bio = BIO_new(BIO_s_mem());
    RSA* rsa = RSA_new();

    BIO_write(bio, skey, strlen(skey));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(bio, rsa);

    uint64_t kl = BIO_pending(bio);
    char* pkey  = (char *) calloc(kl + 1, 1);

    if (!pkey || (kl == UINT64_MAX)) {
      free(pkey); // in case overflow has calloc return a non-null pointer to zero memory
      BIO_vfree(bio);
      RSA_free(rsa);
      return eret(isolate, cb, String::NewFromUtf8(isolate, "Unable to generate key"));
    }

    BIO_read(bio, pkey, kl);

    BIO_vfree(bio);
    RSA_free(rsa);

    Local<String> rval = String::NewFromUtf8(isolate, pkey);
    free(pkey);

    return ret(isolate, cb, rval);
  }

  void init(v8::Local<v8::Object> exports) {
    v8::Local<v8::Context> context = exports->CreationContext();
    exports->Set(context,
                 Nan::New("keygen").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(keygen)
                     ->GetFunction(context)
                     .ToLocalChecked());

    exports->Set(context,
                 Nan::New("extract").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(extract)
                     ->GetFunction(context)
                     .ToLocalChecked());

    exports->Set(context,
                 Nan::New("extractSPKI").ToLocalChecked(),
                 Nan::New<v8::FunctionTemplate>(extractSPKI)
                     ->GetFunction(context)
                     .ToLocalChecked());
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, init)
}
