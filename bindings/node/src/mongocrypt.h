#ifndef NODE_MONGOCRYPT_H
#define NODE_MONGOCRYPT_H

#include <nan.h>
#include <memory>

extern "C" {
#include <mongocrypt/mongocrypt.h>
}

struct MongoCryptBinaryDeleter {
    void operator()(mongocrypt_binary_t* binary) {
        mongocrypt_binary_destroy(binary);
    }
};

struct MongoCryptDeleter {
    void operator()(mongocrypt_t* mongo_crypt) {
        mongocrypt_destroy(mongo_crypt);
    }
};

struct MongoCryptContextDeleter {
    void operator()(mongocrypt_ctx_t* context) {
        mongocrypt_ctx_destroy(context);
    }
};

class MongoCrypt : public Nan::ObjectWrap {
   public:
    static NAN_MODULE_INIT(Init);

   private:
    static Nan::Persistent<v8::Function> constructor;

    static NAN_METHOD(New);
    static NAN_METHOD(MakeEncryptionContext);
    static NAN_METHOD(MakeExplicitEncryptionContext);
    static NAN_METHOD(MakeDecryptionContext);
    static NAN_METHOD(MakeExplicitDecryptionContext);
    static NAN_METHOD(MakeDataKeyContext);

    static NAN_GETTER(Status);

   private:
    struct CryptoHooks {
        std::unique_ptr<Nan::Callback> aes256CbcEncryptHook;
        std::unique_ptr<Nan::Callback> aes256CbcDecryptHook;
        std::unique_ptr<Nan::Callback> randomHook;
        std::unique_ptr<Nan::Callback> hmacSha512Hook;
        std::unique_ptr<Nan::Callback> hmacSha256Hook;
        std::unique_ptr<Nan::Callback> sha256Hook;
    };

    friend class MongoCryptContext;
    explicit MongoCrypt(mongocrypt_t* mongo_crypt, Nan::Callback* logger, CryptoHooks* hooks);
    static bool setupCryptoHooks(mongocrypt_t* mongoCrypt, CryptoHooks* cryptoHooks);

    static void logHandler(mongocrypt_log_level_t level,
                           const char* message,
                           uint32_t message_len,
                           void* ctx);

    std::unique_ptr<mongocrypt_t, MongoCryptDeleter> _mongo_crypt;
    std::unique_ptr<Nan::Callback> _logger;
    std::unique_ptr<CryptoHooks> _cryptoHooks;
};

class MongoCryptContext : public Nan::ObjectWrap {
   public:
    static NAN_MODULE_INIT(Init);
    static v8::Local<v8::Object> NewInstance(mongocrypt_ctx_t* context);

   private:
    static Nan::Persistent<v8::Function> constructor;

    static NAN_METHOD(NextMongoOperation);
    static NAN_METHOD(AddMongoOperationResponse);
    static NAN_METHOD(FinishMongoOperation);
    static NAN_METHOD(NextKMSRequest);
    static NAN_METHOD(FinishKMSRequests);
    static NAN_METHOD(Finalize);

    static NAN_GETTER(Status);
    static NAN_GETTER(State);

   private:
    explicit MongoCryptContext(mongocrypt_ctx_t* context);
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> _context;
};

class MongoCryptKMSRequest : public Nan::ObjectWrap {
   public:
    static NAN_MODULE_INIT(Init);
    static v8::Local<v8::Object> NewInstance(mongocrypt_kms_ctx_t* kms_context);

   private:
    static Nan::Persistent<v8::Function> constructor;

    static NAN_METHOD(AddResponse);

    static NAN_GETTER(Status);
    static NAN_GETTER(Message);
    static NAN_GETTER(BytesNeeded);
    static NAN_GETTER(Endpoint);

   private:
    explicit MongoCryptKMSRequest(mongocrypt_kms_ctx_t* kms_context);
    mongocrypt_kms_ctx_t* _kms_context;
};

#endif  // NODE_MONGOCRYPT_H
