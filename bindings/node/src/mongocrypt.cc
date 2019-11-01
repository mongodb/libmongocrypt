#include "mongocrypt.h"

namespace Nan {
void ThrowTypeError(std::string error) {
    Nan::ThrowTypeError(error.c_str());
}
}  // namespace Nan

struct MongoCryptStatusDeleter {
    void operator()(mongocrypt_status_t* status) {
        mongocrypt_status_destroy(status);
    }
};

v8::Local<v8::Object> ExtractStatus(mongocrypt_status_t* status) {
    Nan::EscapableHandleScope scope;
    v8::Local<v8::Object> result = Nan::New<v8::Object>();
    Nan::Set(result, Nan::New("type").ToLocalChecked(),
                Nan::New<v8::Number>(mongocrypt_status_type(status)));
    Nan::Set(result, Nan::New("code").ToLocalChecked(),
                Nan::New<v8::Number>(mongocrypt_status_code(status)));

    const char* message = mongocrypt_status_message(status, NULL);
    if (message != NULL) {
        Nan::Set(result, Nan::New("message").ToLocalChecked(), Nan::New(message).ToLocalChecked());
    }

    return scope.Escape(result);
}

std::string StringFromBinary(mongocrypt_binary_t* binary) {
    const uint8_t* data = mongocrypt_binary_data(binary);
    size_t len = mongocrypt_binary_len(binary);
    return std::string(data, data + len);
}

mongocrypt_binary_t* BufferToBinary(v8::Local<v8::Object> node_buffer) {
    uint8_t* buffer = (uint8_t*)node::Buffer::Data(node_buffer);
    size_t buffer_len = node::Buffer::Length(node_buffer);

    uint8_t* buffer_copy = new uint8_t[buffer_len];
    memcpy(buffer_copy, buffer, buffer_len);

    return mongocrypt_binary_new_from_data(buffer_copy, buffer_len);
}

v8::Local<v8::Object> BufferFromBinary(mongocrypt_binary_t* binary) {
    Nan::EscapableHandleScope scope;
    const uint8_t* data = mongocrypt_binary_data(binary);
    size_t len = mongocrypt_binary_len(binary);
    v8::Local<v8::Object> buffer = Nan::CopyBuffer((char*)data, len).ToLocalChecked();
    return scope.Escape(buffer);
}

static void NoopFreeCallback(char* data, void* message) {
   // in a no-copy scenario we want to let libmongoc clean up the memory
}

v8::Local<v8::Object> BufferFromBinaryNoCopy(mongocrypt_binary_t* binary) {
    Nan::EscapableHandleScope scope;
    const uint8_t* data = mongocrypt_binary_data(binary);
    size_t len = mongocrypt_binary_len(binary);
    v8::Local<v8::Object> buffer = Nan::NewBuffer((char*)data, len, NoopFreeCallback, nullptr).ToLocalChecked();
    return scope.Escape(buffer);
}

NAN_INLINE bool BooleanOptionValue(v8::Local<v8::Object> options,
                                   const char* _key,
                                   bool def = false) {
    Nan::HandleScope scope;
    v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
    if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
        return def;
    }

    v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
    if (!value->IsBoolean()) {
        return def;
    }

    return Nan::To<bool>(value).FromMaybe(def);
}

NAN_INLINE std::string StringOptionValue(v8::Local<v8::Object> options, const char* _key) {
    Nan::HandleScope scope;
    v8::Local<v8::String> key = Nan::New(_key).ToLocalChecked();
    if (options.IsEmpty() || !Nan::Has(options, key).FromMaybe(false)) {
        return std::string();
    }

    v8::Local<v8::Value> value = Nan::Get(options, key).ToLocalChecked();
    if (!value->IsString()) {
        return std::string();
    }

    return std::string(*(Nan::Utf8String(value)));
}

std::string errorStringFromStatus(mongocrypt_t* crypt) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_status(crypt, status.get());
    const char* errorMessage = mongocrypt_status_message(status.get(), NULL);
    if (!errorMessage) {
        return "Operation failed";
    }

    return errorMessage;
}

std::string errorStringFromStatus(mongocrypt_ctx_t* context) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_ctx_status(context, status.get());
    const char* errorMessage = mongocrypt_status_message(status.get(), NULL);
    if (!errorMessage) {
        return "Operation failed";
    }

    return errorMessage;
}

std::pair<bool, std::string> setKmsProviderOptions(mongocrypt_t* crypt,
                                                   v8::Local<v8::Object> options) {
    Nan::HandleScope scope;
    v8::Local<v8::String> AWS_KEY = Nan::New("aws").ToLocalChecked();
    v8::Local<v8::String> LOCAL_KEY = Nan::New("local").ToLocalChecked();
    v8::Local<v8::String> LOCAL_KEY_KEY = Nan::New("key").ToLocalChecked();

    if (Nan::Has(options, AWS_KEY).FromMaybe(false)) {
        v8::Local<v8::Object> awsOptions =
            Nan::To<v8::Object>(Nan::Get(options, AWS_KEY).ToLocalChecked()).ToLocalChecked();
        std::string accessKeyId = StringOptionValue(awsOptions, "accessKeyId");
        std::string secretAccessKey = StringOptionValue(awsOptions, "secretAccessKey");

        if (!mongocrypt_setopt_kms_provider_aws(crypt,
                                                accessKeyId.c_str(),
                                                accessKeyId.size(),
                                                secretAccessKey.c_str(),
                                                secretAccessKey.size())) {
            return std::make_pair(false, errorStringFromStatus(crypt));
        }
    }

    if (Nan::Has(options, LOCAL_KEY).FromMaybe(false)) {
        v8::Local<v8::Object> localOptions =
            Nan::To<v8::Object>(Nan::Get(options, LOCAL_KEY).ToLocalChecked()).ToLocalChecked();

        if (Nan::Has(localOptions, LOCAL_KEY_KEY).FromMaybe(false)) {
            v8::Local<v8::Object> key =
                Nan::To<v8::Object>(Nan::Get(localOptions, LOCAL_KEY_KEY).ToLocalChecked())
                    .ToLocalChecked();
            if (!node::Buffer::HasInstance(key)) {
                return std::make_pair(false, "Local key must be a Buffer");
            }

            std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(BufferToBinary(key));
            if (!mongocrypt_setopt_kms_provider_local(crypt, binary.get())) {
                return std::make_pair(false, errorStringFromStatus(crypt));
            }
        }
    }

    return std::make_pair(true, std::string());
}

Nan::Persistent<v8::Function> MongoCrypt::constructor;
NAN_MODULE_INIT(MongoCrypt::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("MongoCrypt").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    Nan::SetPrototypeMethod(tpl, "makeEncryptionContext", MakeEncryptionContext);
    Nan::SetPrototypeMethod(tpl, "makeExplicitEncryptionContext", MakeExplicitEncryptionContext);
    Nan::SetPrototypeMethod(tpl, "makeDecryptionContext", MakeDecryptionContext);
    Nan::SetPrototypeMethod(tpl, "makeExplicitDecryptionContext", MakeExplicitDecryptionContext);
    Nan::SetPrototypeMethod(tpl, "makeDataKeyContext", MakeDataKeyContext);

    v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
    itpl->SetInternalFieldCount(1);

    Nan::SetAccessor(itpl, Nan::New("status").ToLocalChecked(), Status);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(
        target, Nan::New("MongoCrypt").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
}

void MongoCrypt::logHandler(mongocrypt_log_level_t level,
                            const char* message,
                            uint32_t message_len,
                            void* ctx) {
    MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
    if (!mongoCrypt) {
        fprintf(stderr, "Log handler called without `MongoCrypt` instance\n");
        return;
    }

    if (!mongoCrypt->_logger) {
        fprintf(stderr, "No logger set, but log handler registered\n");
        return;
    }

    Nan::HandleScope scope;
    v8::Local<v8::Value> argv[] = {Nan::New(level), Nan::New(message).ToLocalChecked()};
    Nan::Call(*mongoCrypt->_logger.get(), Nan::GetCurrentContext()->Global(), 2, argv);
}


void MaybeSetCryptoHookErrorStatus(v8::Local<v8::Value> result, mongocrypt_status_t *status) {
    if (!result->IsObject()) {
        return;
    }
    auto kErrorMessageKey = Nan::New("message").ToLocalChecked();
    auto hookError = Nan::To<v8::Object>(result).ToLocalChecked();
    if (!Nan::Has(hookError, kErrorMessageKey).FromMaybe(false)) {
        return;
    }
    v8::Local<v8::Value> emptyString = Nan::New("").ToLocalChecked();
    auto errorMessageValue = Nan::To<v8::String>(Nan::Get(hookError, kErrorMessageKey).ToLocalChecked()).FromMaybe(emptyString);
    std::string errorMessage(*Nan::Utf8String(errorMessageValue));
    mongocrypt_status_set(
        status,
        MONGOCRYPT_STATUS_ERROR_CLIENT,
        1,
        errorMessage.c_str(),
        errorMessage.length() + 1
    );
}

MongoCrypt::MongoCrypt(mongocrypt_t* mongo_crypt, Nan::Callback* logger, CryptoHooks* hooks)
    : _mongo_crypt(mongo_crypt), _logger(logger), _cryptoHooks(hooks) {}


bool MongoCrypt::setupCryptoHooks(mongocrypt_t* mongoCrypt, CryptoHooks* cryptoHooks) {
    auto aes_256_cbc_encrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->aes256CbcEncryptHook.get();

            v8::Local<v8::Object> keyBuffer = BufferFromBinary(key);
            v8::Local<v8::Object> ivBuffer = BufferFromBinary(iv);
            v8::Local<v8::Object> inBuffer = BufferFromBinary(in);
            v8::Local<v8::Object> outBuffer = BufferFromBinaryNoCopy(out);

            v8::Local<v8::Value> argv[] = {keyBuffer, ivBuffer, inBuffer, outBuffer};
            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result =
                Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 4, argv).FromMaybe(defaultValue);

            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            *bytes_written = Nan::To<uint32_t>(result).ToChecked();
            return true;
        };

    auto aes_256_cbc_decrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->aes256CbcDecryptHook.get();

            v8::Local<v8::Object> keyBuffer = BufferFromBinary(key);
            v8::Local<v8::Object> ivBuffer = BufferFromBinary(iv);
            v8::Local<v8::Object> inBuffer = BufferFromBinary(in);
            v8::Local<v8::Object> outBuffer = BufferFromBinaryNoCopy(out);

            v8::Local<v8::Value> argv[] = {keyBuffer, ivBuffer, inBuffer, outBuffer};
            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result =
                Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 4, argv).FromMaybe(defaultValue);

            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            *bytes_written = Nan::To<uint32_t>(result).ToChecked();
            return true;
        };

    auto random =
        [](void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status) -> bool{
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->randomHook.get();

            v8::Local<v8::Object> outBuffer = BufferFromBinaryNoCopy(out);
            v8::Local<v8::Value> argv[] = {outBuffer, Nan::New(count)};
            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result = Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 2, argv).FromMaybe(defaultValue);

            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            return true;
        };

    auto hmac_sha_512 =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->hmacSha512Hook.get();

            v8::Local<v8::Object> keyBuffer = BufferFromBinary(key);
            v8::Local<v8::Object> inputBuffer = BufferFromBinary(in);
            v8::Local<v8::Object> outputBuffer = BufferFromBinaryNoCopy(out);

            v8::Local<v8::Value> argv[] = {keyBuffer, inputBuffer, outputBuffer};
            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result = Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 3, argv).FromMaybe(defaultValue);
            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }
            return true;
        };

    auto hmac_sha_256 =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->hmacSha256Hook.get();

            v8::Local<v8::Object> keyBuffer = BufferFromBinary(key);
            v8::Local<v8::Object> inputBuffer = BufferFromBinary(in);
            v8::Local<v8::Object> outputBuffer = BufferFromBinaryNoCopy(out);

            v8::Local<v8::Value> argv[] = {keyBuffer, inputBuffer, outputBuffer};
            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result = Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 3, argv).FromMaybe(defaultValue);
            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }
            return true;
        };

    auto sha_256 =
        [](void *ctx, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            Nan::HandleScope scope;
            CryptoHooks* cryptoHooks = static_cast<CryptoHooks*>(ctx);
            Nan::Callback* hook = cryptoHooks->sha256Hook.get();

            v8::Local<v8::Object> inputBuffer = BufferFromBinary(in);
            v8::Local<v8::Object> outputBuffer = BufferFromBinaryNoCopy(out);
            v8::Local<v8::Value> argv[] = {inputBuffer, outputBuffer};

            v8::Local<v8::Value> defaultValue = Nan::False();
            v8::Local<v8::Value> result = Nan::Call(*hook, Nan::GetCurrentContext()->Global(), 2, argv).FromMaybe(defaultValue);

            if (!result->IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }
            return true;
        };

    return mongocrypt_setopt_crypto_hooks(mongoCrypt,
        aes_256_cbc_encrypt,
        aes_256_cbc_decrypt,
        random,
        hmac_sha_512,
        hmac_sha_256,
        sha_256,
        cryptoHooks
    );
}

NAN_METHOD(MongoCrypt::New) {
    Nan::HandleScope scope;

    if (info.IsConstructCall()) {
        if (info.Length() >= 1 && !info[0]->IsObject()) {
            Nan::ThrowTypeError("First parameter must be an object");
            return;
        }

        Nan::Callback* logger = nullptr;
        CryptoHooks *cryptoHooks = nullptr;
        std::unique_ptr<mongocrypt_t, MongoCryptDeleter> crypt(mongocrypt_new());

        if (info.Length() >= 1) {
            v8::Local<v8::Object> options = Nan::To<v8::Object>(info[0]).ToLocalChecked();
            v8::Local<v8::String> KMS_PROVIDERS_KEY = Nan::New("kmsProviders").ToLocalChecked();
            v8::Local<v8::String> SCHEMA_MAP_KEY = Nan::New("schemaMap").ToLocalChecked();
            v8::Local<v8::String> LOGGER_KEY = Nan::New("logger").ToLocalChecked();
            v8::Local<v8::String> CRYPTO_CALLBACKS_KEY = Nan::New("cryptoCallbacks").ToLocalChecked();

            v8::Local<v8::String> AES256_ENCRYPT_HOOK_KEY = Nan::New("aes256CbcEncryptHook").ToLocalChecked();
            v8::Local<v8::String> AES256_DECRYPT_HOOK_KEY = Nan::New("aes256CbcDecryptHook").ToLocalChecked();
            v8::Local<v8::String> RANDOM_HOOK_KEY = Nan::New("randomHook").ToLocalChecked();
            v8::Local<v8::String> HMAC_SHA512_HOOK_KEY = Nan::New("hmacSha512Hook").ToLocalChecked();
            v8::Local<v8::String> HMAC_SHA256_HOOK_KEY = Nan::New("hmacSha256Hook").ToLocalChecked();
            v8::Local<v8::String> SHA256_HOOK_KEY = Nan::New("sha256Hook").ToLocalChecked();

            if (Nan::Has(options, KMS_PROVIDERS_KEY).FromMaybe(false)) {
                v8::Local<v8::Object> kmsProvidersOptions =
                    Nan::To<v8::Object>(Nan::Get(options, KMS_PROVIDERS_KEY).ToLocalChecked())
                        .ToLocalChecked();

                auto result = setKmsProviderOptions(crypt.get(), kmsProvidersOptions);
                if (!result.first) {
                    Nan::ThrowTypeError(result.second);
                    return;
                }
            }

            if (Nan::Has(options, SCHEMA_MAP_KEY).FromMaybe(false)) {
                v8::Local<v8::Object> schemaMapBuffer =
                    Nan::To<v8::Object>(Nan::Get(options, SCHEMA_MAP_KEY).ToLocalChecked())
                        .ToLocalChecked();

                if (!node::Buffer::HasInstance(schemaMapBuffer)) {
                    Nan::ThrowTypeError("Option `schemaMap` must be a Buffer");
                    return;
                }

                if (!mongocrypt_setopt_schema_map(crypt.get(), BufferToBinary(schemaMapBuffer))) {
                    Nan::ThrowTypeError(errorStringFromStatus(crypt.get()));
                    return;
                }
            }

            if (Nan::Has(options, LOGGER_KEY).FromMaybe(false)) {
                logger = new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(options, LOGGER_KEY).ToLocalChecked())
                        .ToLocalChecked());
            }

            if (Nan::Has(options, CRYPTO_CALLBACKS_KEY).FromMaybe(false)) {
                v8::Local<v8::Object> cryptoCallbacks =
                    Nan::To<v8::Object>(Nan::Get(options, CRYPTO_CALLBACKS_KEY).ToLocalChecked())
                        .ToLocalChecked();

                cryptoHooks = new CryptoHooks();
                cryptoHooks->aes256CbcEncryptHook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, AES256_ENCRYPT_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));

                cryptoHooks->aes256CbcDecryptHook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, AES256_DECRYPT_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));

                cryptoHooks->randomHook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, RANDOM_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));

                cryptoHooks->hmacSha512Hook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, HMAC_SHA512_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));

                cryptoHooks->hmacSha256Hook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, HMAC_SHA256_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));

                cryptoHooks->sha256Hook.reset(new Nan::Callback(
                    Nan::To<v8::Function>(Nan::Get(cryptoCallbacks, SHA256_HOOK_KEY).ToLocalChecked())
                        .ToLocalChecked()));
            }
        }

        MongoCrypt* class_instance = new MongoCrypt(crypt.release(), logger, cryptoHooks);
        if (logger) {
            if (!mongocrypt_setopt_log_handler(
                    class_instance->_mongo_crypt.get(), MongoCrypt::logHandler, class_instance)) {
                Nan::ThrowTypeError(errorStringFromStatus(class_instance->_mongo_crypt.get()));
                return;
            }
        }

        if (cryptoHooks) {
            if (!setupCryptoHooks(class_instance->_mongo_crypt.get(), cryptoHooks)) {
                Nan::ThrowError("unable to configure crypto hooks");
                return;
            }
        }

        // initialize afer all options are set, but after `MongoCrypt` instance is created so we can
        // optionally pass the instance to the logging function.
        if (!mongocrypt_init(class_instance->_mongo_crypt.get())) {
            Nan::ThrowTypeError(errorStringFromStatus(class_instance->_mongo_crypt.get()));
            return;
        }

        class_instance->Wrap(info.This());
        return info.GetReturnValue().Set(info.This());
    }

    const int argc = 1;
    v8::Local<v8::Value> argv[argc] = {info[0]};
    v8::Local<v8::Function> ctor = Nan::New<v8::Function>(MongoCrypt::constructor);
    info.GetReturnValue().Set(Nan::NewInstance(ctor, argc, argv).ToLocalChecked());
}

NAN_GETTER(MongoCrypt::Status) {
    Nan::HandleScope scope;
    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_status(mc->_mongo_crypt.get(), status.get());
    v8::Local<v8::Object> result = ExtractStatus(status.get());
    info.GetReturnValue().Set(result);
}

NAN_METHOD(MongoCrypt::MakeEncryptionContext) {
    Nan::HandleScope scope;
    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::string ns(*Nan::Utf8String(Nan::To<v8::String>(info[0]).FromMaybe(v8::Local<v8::String>())));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    v8::Local<v8::Object> commandBuffer = Nan::To<v8::Object>(info[1]).ToLocalChecked();
    if (!node::Buffer::HasInstance(commandBuffer)) {
        Nan::ThrowTypeError("Paramter `command` must be a Buffer");
        return;
    }


    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binaryCommand(BufferToBinary(commandBuffer));
    if (!mongocrypt_ctx_encrypt_init(
            context.get(), ns.c_str(), ns.size(), binaryCommand.get())) {
        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
        return;
    }

    v8::Local<v8::Object> context_obj = MongoCryptContext::NewInstance(context.release());
    info.GetReturnValue().Set(context_obj);
}

NAN_METHOD(MongoCrypt::MakeExplicitEncryptionContext) {
    Nan::HandleScope scope;
    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    v8::Local<v8::Object> valueBuffer = Nan::To<v8::Object>(info[0]).ToLocalChecked();
    if (!node::Buffer::HasInstance(valueBuffer)) {
        Nan::ThrowTypeError("Paramter `value` must be a Buffer");
        return;
    }

    if (info.Length() > 1) {
        v8::Local<v8::Object> options = Nan::To<v8::Object>(info[1]).ToLocalChecked();

        v8::Local<v8::String> KEY_ID_KEY = Nan::New("keyId").ToLocalChecked();
        v8::Local<v8::String> ALGORITHM_KEY = Nan::New("algorithm").ToLocalChecked();
        v8::Local<v8::String> KEY_ALT_NAME_KEY = Nan::New("keyAltName").ToLocalChecked();

        if (Nan::Has(options, KEY_ID_KEY).FromMaybe(false)) {
            if (!Nan::Get(options, KEY_ID_KEY).ToLocalChecked()->IsObject()) {
                Nan::ThrowTypeError("`keyId` must be a Buffer");
                return;
            }

            v8::Local<v8::Object> keyId =
                Nan::To<v8::Object>(Nan::Get(options, KEY_ID_KEY).ToLocalChecked()).ToLocalChecked();
            if (!node::Buffer::HasInstance(keyId)) {
                Nan::ThrowTypeError("`keyId` must be a Buffer");
                return;
            }

            std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(BufferToBinary(keyId));
            if (!mongocrypt_ctx_setopt_key_id(context.get(), binary.get())) {
                Nan::ThrowTypeError(errorStringFromStatus(context.get()));
                return;
            }
        }

        if (Nan::Has(options, KEY_ALT_NAME_KEY).FromMaybe(false)) {
            v8::Local<v8::Value> keyAltName = Nan::Get(options, KEY_ALT_NAME_KEY).ToLocalChecked();
            if (!keyAltName->IsObject()) {
                Nan::ThrowTypeError("`keyAltName` must be a Buffer");
                return;
            }

            v8::Local<v8::Object> keyAltNameObj = Nan::To<v8::Object>(keyAltName).ToLocalChecked();
            if (!node::Buffer::HasInstance(keyAltNameObj)) {
                Nan::ThrowTypeError("`keyAltName` must be a Buffer");
                return;
            }

            std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(BufferToBinary(keyAltNameObj));
            if (!mongocrypt_ctx_setopt_key_alt_name(context.get(), binary.get())) {
                Nan::ThrowTypeError(errorStringFromStatus(context.get()));
                return;
            } 
        }

        if (Nan::Has(options, ALGORITHM_KEY).FromMaybe(false)) {
            std::string algorithm = StringOptionValue(options, "algorithm");
            if (!mongocrypt_ctx_setopt_algorithm(
                    context.get(), const_cast<char*>(algorithm.c_str()), algorithm.size())) {
                
                Nan::ThrowTypeError(errorStringFromStatus(context.get()));
                return;
            }
        }
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binaryValue(BufferToBinary(valueBuffer));
    if (!mongocrypt_ctx_explicit_encrypt_init(context.get(), binaryValue.get())) {
        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
        return;
    }

    v8::Local<v8::Object> context_obj = MongoCryptContext::NewInstance(context.release());
    info.GetReturnValue().Set(context_obj);
}

NAN_METHOD(MongoCrypt::MakeDecryptionContext) {
    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First parameter must be a Buffer");
        return;
    }

    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(Nan::To<v8::Object>(info[0]).ToLocalChecked()));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    if (!mongocrypt_ctx_decrypt_init(context.get(), binary.get())) {
        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
        return;
    }

    v8::Local<v8::Object> context_obj = MongoCryptContext::NewInstance(context.release());
    info.GetReturnValue().Set(context_obj);
}

NAN_METHOD(MongoCrypt::MakeExplicitDecryptionContext) {
    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First parameter must be a Buffer");
        return;
    }

    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(Nan::To<v8::Object>(info[0]).ToLocalChecked()));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    if (!mongocrypt_ctx_explicit_decrypt_init(context.get(), binary.get())) {
        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
        return;
    }

    v8::Local<v8::Object> context_obj = MongoCryptContext::NewInstance(context.release());
    info.GetReturnValue().Set(context_obj);
}

NAN_METHOD(MongoCrypt::MakeDataKeyContext) {
    MongoCrypt* mc = Nan::ObjectWrap::Unwrap<MongoCrypt>(info.This());
    std::string kmsProvider(*Nan::Utf8String(Nan::To<v8::String>(info[0]).FromMaybe(v8::Local<v8::String>())));

    // TODO: context should use unique_ptr
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    // TODO: defer resolution to JS, require `aws` or `local`
    if (kmsProvider == "aws") {
        if (!info[1]->IsObject()) {
            Nan::ThrowTypeError("Missing required parameter `options` for kms provider `aws`");
            return;
        }

        // TODO: defer options resolution to JS
        v8::Local<v8::Object> options = Nan::To<v8::Object>(info[1]).ToLocalChecked();
        v8::Local<v8::String> MASTER_KEY_KEY = Nan::New("masterKey").ToLocalChecked();
        v8::Local<v8::Object> masterKey =
            Nan::To<v8::Object>(Nan::Get(options, MASTER_KEY_KEY).ToLocalChecked())
                .ToLocalChecked();
        std::string region = StringOptionValue(masterKey, "region");
        std::string key = StringOptionValue(masterKey, "key");

        if (!mongocrypt_ctx_setopt_masterkey_aws(
                context.get(), region.c_str(), region.size(), key.c_str(), key.size())) {
            Nan::ThrowTypeError(errorStringFromStatus(context.get()));
            return;
        }

        v8::Local<v8::String> ENDPOINT_KEY = Nan::New("endpoint").ToLocalChecked();
        if (Nan::Has(masterKey, ENDPOINT_KEY).FromMaybe(false)) {
            std::string endpoint = StringOptionValue(masterKey, "endpoint");
            if (!mongocrypt_ctx_setopt_masterkey_aws_endpoint(context.get(), endpoint.c_str(), endpoint.size())) {
                Nan::ThrowTypeError(errorStringFromStatus(context.get()));
                return;
            }
        }

    } else if (kmsProvider == "local") {
        mongocrypt_ctx_setopt_masterkey_local(context.get());
    } else {
        Nan::ThrowTypeError("Invalid KMS provider");
    }


    if (info[1]->IsObject()) {
        v8::Local<v8::Object> options = Nan::To<v8::Object>(info[1]).ToLocalChecked();
        auto ALT_NAMES_KEY = Nan::New("keyAltNames").ToLocalChecked();
        if (Nan::Has(options, ALT_NAMES_KEY).FromMaybe(false)) {
            v8::Local<v8::Value> keyAltNames = Nan::Get(options, ALT_NAMES_KEY).ToLocalChecked();
            if (!keyAltNames->IsArray()) {
                Nan::ThrowTypeError("keyAltNames must be an array of strings");
                return;
            }

            v8::Local<v8::Array> keyAltNamesArray = v8::Local<v8::Array>::Cast(keyAltNames);
            uint32_t keyAltNamesLength = keyAltNamesArray->Length();
            for (uint32_t i = 0; i < keyAltNamesLength; i += 1) {
                if (Nan::Has(keyAltNamesArray, i).FromMaybe(false)) {
                    v8::Local<v8::Object> keyAltName = Nan::To<v8::Object>(Nan::Get(keyAltNamesArray, i).ToLocalChecked()).ToLocalChecked();
                    if (!node::Buffer::HasInstance(keyAltName)) {
                        // We should never get here
                        Nan::ThrowTypeError("Serialized keyAltName must be a Buffer");
                        return;
                    }

                    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(keyAltName));
                    if (!mongocrypt_ctx_setopt_key_alt_name(context.get(), binary.get())) {
                        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
                        return;
                    } 
                }
            }
        }
    }

    if (!mongocrypt_ctx_datakey_init(context.get())) {
        Nan::ThrowTypeError(errorStringFromStatus(context.get()));
        return;
    }

    v8::Local<v8::Object> context_obj = MongoCryptContext::NewInstance(context.release());
    info.GetReturnValue().Set(context_obj);
}

Nan::Persistent<v8::Function> MongoCryptContext::constructor;
NAN_MODULE_INIT(MongoCryptContext::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>();
    tpl->SetClassName(Nan::New("MongoCryptContext").ToLocalChecked());
    Nan::SetPrototypeMethod(tpl, "nextMongoOperation", NextMongoOperation);
    Nan::SetPrototypeMethod(tpl, "addMongoOperationResponse", AddMongoOperationResponse);
    Nan::SetPrototypeMethod(tpl, "finishMongoOperation", FinishMongoOperation);
    Nan::SetPrototypeMethod(tpl, "nextKMSRequest", NextKMSRequest);
    Nan::SetPrototypeMethod(tpl, "finishKMSRequests", FinishKMSRequests);
    Nan::SetPrototypeMethod(tpl, "finalize", Finalize);

    v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
    itpl->SetInternalFieldCount(1);

    Nan::SetAccessor(itpl, Nan::New("status").ToLocalChecked(), Status);
    Nan::SetAccessor(itpl, Nan::New("state").ToLocalChecked(), State);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(target,
             Nan::New("MongoCryptContext").ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
}

v8::Local<v8::Object> MongoCryptContext::NewInstance(mongocrypt_ctx_t* context) {
    Nan::EscapableHandleScope scope;
    v8::Local<v8::Function> ctor = Nan::New<v8::Function>(MongoCryptContext::constructor);
    v8::Local<v8::Object> object = Nan::NewInstance(ctor).ToLocalChecked();
    MongoCryptContext* class_instance = new MongoCryptContext(context);
    class_instance->Wrap(object);
    return scope.Escape(object);
}

MongoCryptContext::MongoCryptContext(mongocrypt_ctx_t* context) : _context(context) {}

NAN_GETTER(MongoCryptContext::Status) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_ctx_status(mcc->_context.get(), status.get());
    v8::Local<v8::Object> result = ExtractStatus(status.get());
    info.GetReturnValue().Set(result);
}

NAN_GETTER(MongoCryptContext::State) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());
    v8::Local<v8::Number> result = Nan::New<v8::Number>(mongocrypt_ctx_state(mcc->_context.get()));
    info.GetReturnValue().Set(result);
}

NAN_METHOD(MongoCryptContext::NextMongoOperation) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> op_bson(mongocrypt_binary_new());
    mongocrypt_ctx_mongo_op(mcc->_context.get(), op_bson.get());
    v8::Local<v8::Object> buffer = BufferFromBinary(op_bson.get());
    info.GetReturnValue().Set(buffer);
}

NAN_METHOD(MongoCryptContext::AddMongoOperationResponse) {
    Nan::HandleScope scope;
    if (info.Length() != 1 || (info.Length() == 1 && !info[0]->IsObject())) {
        Nan::ThrowTypeError("Missing required parameter `buffer`");
        return;
    }

    if (!node::Buffer::HasInstance(info[0])) {
        Nan::ThrowTypeError("First parameter must be a Buffer");
        return;
    }

    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> reply_bson(
        BufferToBinary(Nan::To<v8::Object>(info[0]).ToLocalChecked()));
    mongocrypt_ctx_mongo_feed(mcc->_context.get(), reply_bson.get());
    // return value
}

NAN_METHOD(MongoCryptContext::FinishMongoOperation) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());
    mongocrypt_ctx_mongo_done(mcc->_context.get());
}

NAN_METHOD(MongoCryptContext::NextKMSRequest) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());

    mongocrypt_kms_ctx_t* kms_context = mongocrypt_ctx_next_kms_ctx(mcc->_context.get());
    if (kms_context == NULL) {
        info.GetReturnValue().Set(Nan::Null());
    } else {
        v8::Local<v8::Object> result = MongoCryptKMSRequest::NewInstance(kms_context);
        info.GetReturnValue().Set(result);
    }
}

NAN_METHOD(MongoCryptContext::FinishKMSRequests) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());
    mongocrypt_ctx_kms_done(mcc->_context.get());
}

NAN_METHOD(MongoCryptContext::Finalize) {
    Nan::HandleScope scope;
    MongoCryptContext* mcc = Nan::ObjectWrap::Unwrap<MongoCryptContext>(info.This());

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> output(mongocrypt_binary_new());
    mongocrypt_ctx_finalize(mcc->_context.get(), output.get());
    v8::Local<v8::Object> buffer = BufferFromBinary(output.get());
    info.GetReturnValue().Set(buffer);
}

Nan::Persistent<v8::Function> MongoCryptKMSRequest::constructor;
NAN_MODULE_INIT(MongoCryptKMSRequest::Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>();
    tpl->SetClassName(Nan::New("MongoCryptKMSRequest").ToLocalChecked());
    Nan::SetPrototypeMethod(tpl, "addResponse", AddResponse);

    v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
    itpl->SetInternalFieldCount(1);

    Nan::SetAccessor(itpl, Nan::New("status").ToLocalChecked(), Status);
    Nan::SetAccessor(itpl, Nan::New("bytesNeeded").ToLocalChecked(), BytesNeeded);
    Nan::SetAccessor(itpl, Nan::New("endpoint").ToLocalChecked(), Endpoint);
    Nan::SetAccessor(itpl, Nan::New("message").ToLocalChecked(), Message);

    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(target,
             Nan::New("MongoCryptKMSRequest").ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
}

v8::Local<v8::Object> MongoCryptKMSRequest::NewInstance(mongocrypt_kms_ctx_t* kms_context) {
    Nan::EscapableHandleScope scope;
    v8::Local<v8::Function> ctor = Nan::New<v8::Function>(MongoCryptKMSRequest::constructor);
    v8::Local<v8::Object> object = Nan::NewInstance(ctor).ToLocalChecked();
    MongoCryptKMSRequest* class_instance = new MongoCryptKMSRequest(kms_context);
    class_instance->Wrap(object);
    return scope.Escape(object);
}

MongoCryptKMSRequest::MongoCryptKMSRequest(mongocrypt_kms_ctx_t* kms_context)
    : _kms_context(kms_context) {}

NAN_GETTER(MongoCryptKMSRequest::Status) {
    Nan::HandleScope scope;
    MongoCryptKMSRequest* mckr = Nan::ObjectWrap::Unwrap<MongoCryptKMSRequest>(info.This());
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_kms_ctx_status(mckr->_kms_context, status.get());
    v8::Local<v8::Object> result = ExtractStatus(status.get());
    info.GetReturnValue().Set(result);
}

NAN_GETTER(MongoCryptKMSRequest::BytesNeeded) {
    Nan::HandleScope scope;
    MongoCryptKMSRequest* mckr = Nan::ObjectWrap::Unwrap<MongoCryptKMSRequest>(info.This());
    v8::Local<v8::Number> result =
        Nan::New<v8::Number>(mongocrypt_kms_ctx_bytes_needed(mckr->_kms_context));
    info.GetReturnValue().Set(result);
}

NAN_GETTER(MongoCryptKMSRequest::Message) {
    Nan::HandleScope scope;
    MongoCryptKMSRequest* mckr = Nan::ObjectWrap::Unwrap<MongoCryptKMSRequest>(info.This());

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> message(mongocrypt_binary_new());
    mongocrypt_kms_ctx_message(mckr->_kms_context, message.get());
    v8::Local<v8::Object> result = BufferFromBinary(message.get());
    info.GetReturnValue().Set(result);
}

NAN_GETTER(MongoCryptKMSRequest::Endpoint) {
    Nan::HandleScope scope;
    MongoCryptKMSRequest* mckr = Nan::ObjectWrap::Unwrap<MongoCryptKMSRequest>(info.This());
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> message(mongocrypt_binary_new());

    const char* endpoint;
    mongocrypt_kms_ctx_endpoint(mckr->_kms_context, &endpoint);
    info.GetReturnValue().Set(Nan::New(endpoint).ToLocalChecked());
}

NAN_METHOD(MongoCryptKMSRequest::AddResponse) {
    Nan::HandleScope scope;
    MongoCryptKMSRequest* mckr = Nan::ObjectWrap::Unwrap<MongoCryptKMSRequest>(info.This());

    auto buffer = Nan::To<v8::Object>(info[0]);
    if (buffer.IsEmpty()) {
        Nan::ThrowTypeError("First parameter must be of type Buffer");
        return;
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> reply_bytes(
        BufferToBinary(buffer.ToLocalChecked()));
    mongocrypt_kms_ctx_feed(mckr->_kms_context, reply_bytes.get());
}

NAN_MODULE_INIT(Init) {
    MongoCrypt::Init(target);
    MongoCryptContext::Init(target);
    MongoCryptKMSRequest::Init(target);
}

NODE_MODULE(mongocrypt, Init)
