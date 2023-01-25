#include "mongocrypt.h"
#include <cassert>

#ifdef _MSC_VER 
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif

namespace node_mongocrypt {

using namespace Napi;

// anonymous namepace for helpers
namespace {
struct InstanceData {
    Reference<Function> MongoCryptContextCtor;
    Reference<Function> MongoCryptKMSRequestCtor;
};

struct MongoCryptStatusDeleter {
    void operator()(mongocrypt_status_t* status) {
        mongocrypt_status_destroy(status);
    }
};

Object ExtractStatus(Env env, mongocrypt_status_t* status) {
    Object result = Object::New(env);
    result["type"] = Number::New(env, mongocrypt_status_type(status));
    result["code"] = Number::New(env, mongocrypt_status_code(status));
    const char* message = mongocrypt_status_message(status, nullptr);
    if (message != nullptr) {
        result["message"] = String::New(env, message);
    }

    return result;
}

std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter>
BufferToBinary(Uint8Array node_buffer) {
    uint8_t* buffer = node_buffer.Data();
    size_t buffer_len = node_buffer.ByteLength();
    return std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter>(
        mongocrypt_binary_new_from_data(buffer, buffer_len));
}

Uint8Array BufferFromBinary(Env env, mongocrypt_binary_t* binary) {
    const uint8_t* data = mongocrypt_binary_data(binary);
    size_t len = mongocrypt_binary_len(binary);
    return Buffer<uint8_t>::Copy(env, data, len);
}

Uint8Array BufferWithLengthOf(Env env, mongocrypt_binary_t* binary) {
    size_t len = mongocrypt_binary_len(binary);
    return Buffer<uint8_t>::New(env, len);
}

void CopyBufferData(mongocrypt_binary_t* out, Uint8Array buffer, size_t count) {
    assert(count <= mongocrypt_binary_len(out));
    assert(count <= buffer.ByteLength());
    memcpy(mongocrypt_binary_data(out), buffer.Data(), count);
}

void CopyBufferData(mongocrypt_binary_t* out, Uint8Array buffer) {
    CopyBufferData(out, buffer, mongocrypt_binary_len(out));
}

std::string errorStringFromStatus(mongocrypt_t* crypt) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_status(crypt, status.get());
    const char* errorMessage = mongocrypt_status_message(status.get(), nullptr);
    if (!errorMessage) {
        return "Operation failed";
    }

    return errorMessage;
}

std::string errorStringFromStatus(mongocrypt_ctx_t* context) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_ctx_status(context, status.get());
    const char* errorMessage = mongocrypt_status_message(status.get(), nullptr);
    if (!errorMessage) {
        return "Operation failed";
    }

    return errorMessage;
}

template<typename E>
E strToEnumValue(
    Env env,
    const std::string& str,
    const char* option_name,
    const std::initializer_list<std::pair<const char*, E>>& values) {
    for (const auto& candidate : values) {
        if (candidate.first == str) {
            return candidate.second;
        }
    }
    throw Error::New(env,
        std::string("invalid enum value: '") + str + "' for " + option_name);
}

}  // anonymous namespace

Function MongoCrypt::Init(Napi::Env env) {
  return
      DefineClass(env,
                  "MongoCrypt",
                  {
                    InstanceMethod("makeEncryptionContext", &MongoCrypt::MakeEncryptionContext),
                    InstanceMethod("makeExplicitEncryptionContext", &MongoCrypt::MakeExplicitEncryptionContext),
                    InstanceMethod("makeDecryptionContext", &MongoCrypt::MakeDecryptionContext),
                    InstanceMethod("makeExplicitDecryptionContext", &MongoCrypt::MakeExplicitDecryptionContext),
                    InstanceMethod("makeDataKeyContext", &MongoCrypt::MakeDataKeyContext),
                    InstanceMethod("makeRewrapManyDataKeyContext", &MongoCrypt::MakeRewrapManyDataKeyContext),
                    InstanceAccessor("status", &MongoCrypt::Status, nullptr),
                    InstanceAccessor("cryptSharedLibVersionInfo", &MongoCrypt::CryptSharedLibVersionInfo, nullptr),
                    StaticValue("libmongocryptVersion", String::New(env, mongocrypt_version(nullptr)))
                  });
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

    Napi::Env env = mongoCrypt->Env();
    HandleScope scope(env);
    Function logger = mongoCrypt->GetCallback("logger");

    if (logger.IsEmpty()) {
        fprintf(stderr, "No logger set, but log handler registered\n");
        return;
    }

    try {
        logger.Call(std::initializer_list<napi_value>
            { Number::New(env, level), String::New(env, message, message_len) });
    } catch (const std::exception& ex) {
        fprintf(stderr, "Uncaught exception in logger callback: %s\n", ex.what());
    } catch (...) {
        fprintf(stderr, "Uncaught exception in logger callback\n");
    }
}


static void MaybeSetCryptoHookErrorStatus(Value result, mongocrypt_status_t *status) {
    if (!result.IsObject()) {
        return;
    }
    Object hookError = result.As<Object>();
    if (!hookError.Has("message")) {
        return;
    }
    std::string errorMessage = hookError.Get("message").ToString();
    mongocrypt_status_set(
        status,
        MONGOCRYPT_STATUS_ERROR_CLIENT,
        1,
        errorMessage.c_str(),
        errorMessage.length() + 1
    );
}

static bool aes_256_generic_hook (MongoCrypt* mongoCrypt, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status, Function hook) {
    Env env = mongoCrypt->Env();
    HandleScope scope(env);

    Uint8Array keyBuffer = BufferFromBinary(env, key);
    Uint8Array ivBuffer = BufferFromBinary(env, iv);
    Uint8Array inBuffer = BufferFromBinary(env, in);
    Uint8Array outBuffer = BufferWithLengthOf(env, out);

    Value result;
    try {
        result = hook.Call(std::initializer_list<napi_value>
            { keyBuffer, ivBuffer, inBuffer, outBuffer });
    } catch (...) {
        return false;
    }

    if (!result.IsNumber()) {
        MaybeSetCryptoHookErrorStatus(result, status);
        return false;
    }

    *bytes_written = result.ToNumber().Uint32Value();
    CopyBufferData(out, outBuffer, *bytes_written);
    return true;
}

bool MongoCrypt::setupCryptoHooks() {
    auto aes_256_cbc_encrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
        MongoCrypt* mc = static_cast<MongoCrypt*>(ctx);
        return aes_256_generic_hook(mc, key, iv, in, out, bytes_written, status, mc->GetCallback("aes256CbcEncryptHook"));
    };

    auto aes_256_cbc_decrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
        MongoCrypt* mc = static_cast<MongoCrypt*>(ctx);
        return aes_256_generic_hook(mc, key, iv, in, out, bytes_written, status, mc->GetCallback("aes256CbcDecryptHook"));
    };

    auto aes_256_ctr_encrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
        MongoCrypt* mc = static_cast<MongoCrypt*>(ctx);
        return aes_256_generic_hook(mc, key, iv, in, out, bytes_written, status, mc->GetCallback("aes256CtrEncryptHook"));
    };

    auto aes_256_ctr_decrypt =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *iv, mongocrypt_binary_t *in, mongocrypt_binary_t *out, uint32_t *bytes_written, mongocrypt_status_t *status) -> bool {
        MongoCrypt* mc = static_cast<MongoCrypt*>(ctx);
        return aes_256_generic_hook(mc, key, iv, in, out, bytes_written, status, mc->GetCallback("aes256CtrDecryptHook"));
    };

    auto random =
        [](void *ctx, mongocrypt_binary_t *out, uint32_t count, mongocrypt_status_t *status) -> bool {
            MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
            Napi::Env env = mongoCrypt->Env();
            HandleScope scope(env);
            Function hook = mongoCrypt->GetCallback("randomHook");

            Uint8Array outBuffer = BufferWithLengthOf(env, out);
            Napi::Value result;
            try {
                result = hook.Call(std::initializer_list<napi_value>
                    { outBuffer, Number::New(env, count) });
            } catch (...) {
                return false;
            }

            if (!result.IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            CopyBufferData(out, outBuffer);
            return true;
        };

    auto hmac_sha_512 =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
            Napi::Env env = mongoCrypt->Env();
            HandleScope scope(env);
            Function hook = mongoCrypt->GetCallback("hmacSha512Hook");

            Uint8Array keyBuffer = BufferFromBinary(env, key);
            Uint8Array inputBuffer = BufferFromBinary(env, in);
            Uint8Array outputBuffer = BufferWithLengthOf(env, out);

            Napi::Value result;
            try {
                result = hook.Call(std::initializer_list<napi_value>
                    { keyBuffer, inputBuffer, outputBuffer });
            } catch (...) {
                return false;
            }

            if (!result.IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            CopyBufferData(out, outputBuffer);
            return true;
        };

    auto hmac_sha_256 =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
            Napi::Env env = mongoCrypt->Env();
            HandleScope scope(env);
            Function hook = mongoCrypt->GetCallback("hmacSha256Hook");

            Uint8Array keyBuffer = BufferFromBinary(env, key);
            Uint8Array inputBuffer = BufferFromBinary(env, in);
            Uint8Array outputBuffer = BufferWithLengthOf(env, out);

            Napi::Value result;
            try {
                result = hook.Call(std::initializer_list<napi_value>
                    { keyBuffer, inputBuffer, outputBuffer });
            } catch (...) {
                return false;
            }

            if (!result.IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            CopyBufferData(out, outputBuffer);
            return true;
        };

    auto sha_256 =
        [](void *ctx, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
            Napi::Env env = mongoCrypt->Env();
            HandleScope scope(env);
            Function hook = mongoCrypt->GetCallback("sha256Hook");

            Uint8Array inputBuffer = BufferFromBinary(env, in);
            Uint8Array outputBuffer = BufferWithLengthOf(env, out);

            Napi::Value result;
            try {
                result = hook.Call(std::initializer_list<napi_value>
                    { inputBuffer, outputBuffer });
            } catch (...) {
                return false;
            }

            if (!result.IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            CopyBufferData(out, outputBuffer);
            return true;
        };

    auto sign_rsa_sha256 =
        [](void *ctx, mongocrypt_binary_t *key, mongocrypt_binary_t *in, mongocrypt_binary_t *out, mongocrypt_status_t *status) -> bool {
            MongoCrypt* mongoCrypt = static_cast<MongoCrypt*>(ctx);
            Napi::Env env = mongoCrypt->Env();
            HandleScope scope(env);
            Function hook = mongoCrypt->GetCallback("signRsaSha256Hook");

            Uint8Array keyBuffer = BufferFromBinary(env, key);
            Uint8Array inputBuffer = BufferFromBinary(env, in);
            Uint8Array outputBuffer = BufferWithLengthOf(env, out);

            Napi::Value result;
            try {
                result = hook.Call(std::initializer_list<napi_value>
                    { keyBuffer, inputBuffer, outputBuffer });
            } catch (...) {
                return false;
            }

            if (!result.IsNumber()) {
                MaybeSetCryptoHookErrorStatus(result, status);
                return false;
            }

            CopyBufferData(out, outputBuffer);
            return true;
        };

    if (!mongocrypt_setopt_crypto_hooks(_mongo_crypt.get(),
        aes_256_cbc_encrypt,
        aes_256_cbc_decrypt,
        random,
        hmac_sha_512,
        hmac_sha_256,
        sha_256,
        this)) {
        return false;
    }

    // Added after `mongocrypt_setopt_crypto_hooks`, they should be treated as the same during configuration
    if (!mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(_mongo_crypt.get(), sign_rsa_sha256, this)) {
        return false;
    }

    if (!mongocrypt_setopt_aes_256_ctr(_mongo_crypt.get(), aes_256_ctr_encrypt, aes_256_ctr_decrypt, this)) {
        return false;
    }

    return true;
}

MongoCrypt::MongoCrypt(const CallbackInfo& info)
    : ObjectWrap(info), _mongo_crypt(mongocrypt_new()) {
    if (info.Length() < 1 || !info[0].IsObject()) {
        throw TypeError::New(Env(), "First parameter must be an object");
    }

    Object options = info[0].ToObject();

    if (options.Has("kmsProviders")) {
        Napi::Value kmsProvidersOptions = options["kmsProviders"];

        if (!kmsProvidersOptions.IsBuffer()) {
            throw TypeError::New(Env(), "Option `kmsProviders` must be a Buffer");
        }

        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> kmsProvidersBinary(
            BufferToBinary(kmsProvidersOptions.As<Uint8Array>()));
        if (!mongocrypt_setopt_kms_providers(_mongo_crypt.get(), kmsProvidersBinary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(_mongo_crypt.get()));
        }
    }

    if (options.Has("schemaMap")) {
        Napi::Value schemaMapBuffer = options["schemaMap"];

        if (!schemaMapBuffer.IsBuffer()) {
            throw TypeError::New(Env(), "Option `schemaMap` must be a Buffer");
        }

        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> schemaMapBinary(
            BufferToBinary(schemaMapBuffer.As<Uint8Array>()));
        if (!mongocrypt_setopt_schema_map(_mongo_crypt.get(), schemaMapBinary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(_mongo_crypt.get()));
        }
    }

    if (options.Has("encryptedFieldsMap")) {
        Napi::Value encryptedFieldsMapBuffer = options["encryptedFieldsMap"];

        if (!encryptedFieldsMapBuffer.IsBuffer()) {
            throw TypeError::New(Env(), "Option `encryptedFieldsMap` must be a Buffer");
        }

        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> encryptedFieldsMapBinary(
            BufferToBinary(encryptedFieldsMapBuffer.As<Uint8Array>()));
        if (!mongocrypt_setopt_encrypted_field_config_map(_mongo_crypt.get(), encryptedFieldsMapBinary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(_mongo_crypt.get()));
        }
    }

    if (options.Has("logger")) {
        SetCallback("logger", options["logger"]);
        if (!mongocrypt_setopt_log_handler(
                _mongo_crypt.get(), MongoCrypt::logHandler, this)) {
            throw TypeError::New(Env(), errorStringFromStatus(_mongo_crypt.get()));
        }
    }

    if (options.Has("cryptoCallbacks")) {
        Object cryptoCallbacks = options.Get("cryptoCallbacks").ToObject();

        SetCallback("aes256CbcEncryptHook", cryptoCallbacks["aes256CbcEncryptHook"]);
        SetCallback("aes256CbcDecryptHook", cryptoCallbacks["aes256CbcDecryptHook"]);
        SetCallback("aes256CtrEncryptHook", cryptoCallbacks["aes256CtrEncryptHook"]);
        SetCallback("aes256CtrDecryptHook", cryptoCallbacks["aes256CtrDecryptHook"]);
        SetCallback("randomHook", cryptoCallbacks["randomHook"]);
        SetCallback("hmacSha512Hook", cryptoCallbacks["hmacSha512Hook"]);
        SetCallback("hmacSha256Hook", cryptoCallbacks["hmacSha256Hook"]);
        SetCallback("sha256Hook", cryptoCallbacks["sha256Hook"]);
        SetCallback("signRsaSha256Hook", cryptoCallbacks["signRsaSha256Hook"]);

        if (!setupCryptoHooks()) {
            throw Error::New(Env(), "unable to configure crypto hooks");
        }
    }

    if (options.Has("cryptSharedLibSearchPaths")) {
        Napi::Value search_paths_v = options["cryptSharedLibSearchPaths"];
        if (!search_paths_v.IsArray()) {
            throw TypeError::New(Env(), "Option `cryptSharedLibSearchPaths` must be an array");
        }
        Array search_paths = search_paths_v.As<Array>();
        for (uint32_t i = 0; i < search_paths.Length(); i++) {
            mongocrypt_setopt_append_crypt_shared_lib_search_path(
                _mongo_crypt.get(),
                search_paths.Get(i).ToString().Utf8Value().c_str());
        }
    }

    if (options.Has("cryptSharedLibPath")) {
        mongocrypt_setopt_set_crypt_shared_lib_path_override(
            _mongo_crypt.get(),
            options.Get("cryptSharedLibPath").ToString().Utf8Value().c_str());
    }

    if (options.Get("bypassQueryAnalysis").ToBoolean()) {
        mongocrypt_setopt_bypass_query_analysis(_mongo_crypt.get());
    }

    mongocrypt_setopt_use_need_kms_credentials_state(_mongo_crypt.get());

    // Initialize after all options are set.
    if (!mongocrypt_init(_mongo_crypt.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(_mongo_crypt.get()));
    }
}

Value MongoCrypt::CryptSharedLibVersionInfo(const CallbackInfo& info) {
    uint64_t version_numeric = mongocrypt_crypt_shared_lib_version(_mongo_crypt.get());
    const char* version_string = mongocrypt_crypt_shared_lib_version_string(_mongo_crypt.get(), nullptr);
    if (version_string == nullptr) {
        return Env().Null();
    }

    Object ret = Object::New(Env());
    ret["version"] = BigInt::New(Env(), version_numeric);
    ret["versionStr"] = String::New(Env(), version_string);
    return ret;
}

Value MongoCrypt::Status(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_status(_mongo_crypt.get(), status.get());
    return ExtractStatus(Env(), status.get());
}

Value MongoCrypt::MakeEncryptionContext(const CallbackInfo& info) {
    std::string ns = info[0].ToString();
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));

    Napi::Value commandBuffer = info[1];
    if (!commandBuffer.IsBuffer()) {
        throw TypeError::New(Env(), "Parameter `command` must be a Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binaryCommand(BufferToBinary(commandBuffer.As<Uint8Array>()));
    if (!mongocrypt_ctx_encrypt_init(
            context.get(), ns.c_str(), ns.size(), binaryCommand.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

Value MongoCrypt::MakeExplicitEncryptionContext(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));

    Napi::Value valueBuffer = info[0];
    if (!valueBuffer.IsBuffer()) {
        throw TypeError::New(Env(), "Parameter `value` must be a Buffer");
    }

    Object options = info.Length() > 1 ? info[1].ToObject() : Object::New(info.Env());

    if (options.Has("keyId")) {
        Napi::Value keyId = options["keyId"];

        if (!keyId.IsBuffer()) {
            throw TypeError::New(Env(), "`keyId` must be a Buffer");
        }

        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(BufferToBinary(keyId.As<Uint8Array>()));
        if (!mongocrypt_ctx_setopt_key_id(context.get(), binary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }
    }

    if (options.Has("keyAltName")) {
        Napi::Value keyAltName = options["keyAltName"];

        if (!keyAltName.IsBuffer()) {
            throw TypeError::New(Env(), "`keyAltName` must be a Buffer");
        }

        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
            BufferToBinary(keyAltName.As<Uint8Array>()));
        if (!mongocrypt_ctx_setopt_key_alt_name(context.get(), binary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }
    }

    if (options.Has("algorithm")) {
        std::string algorithm = options.Get("algorithm").ToString();
        if (!mongocrypt_ctx_setopt_algorithm(
                    context.get(), algorithm.c_str(), algorithm.size())) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }

        if (strcasecmp(algorithm.c_str(), "rangepreview") == 0) {
            if (!options.Has("rangeOptions")) {
                throw TypeError::New(Env(), "`rangeOptions` must be provided if `algorithm` is set to RangePreview");
            }

            Napi::Value rangeOptions = options["rangeOptions"];

            if (!rangeOptions.IsBuffer()) {
                throw TypeError::New(Env(), "`rangeOptions` must be a Buffer");
            }

            std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(BufferToBinary(rangeOptions.As<Uint8Array>()));
            if (!mongocrypt_ctx_setopt_algorithm_range(context.get(), binary.get())) {
                throw TypeError::New(Env(), errorStringFromStatus(context.get()));
            }
        }
    }

    if (options.Has("contentionFactor")) {
        Napi::Value contention_factor_value = options["contentionFactor"];
        int64_t contention_factor = contention_factor_value.IsBigInt() ?
            contention_factor_value.As<BigInt>().Int64Value(nullptr) :
            contention_factor_value.ToNumber().Int64Value();
        if (!mongocrypt_ctx_setopt_contention_factor(context.get(), contention_factor)) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }
    }

    if (options.Has("queryType")) {
        std::string query_type_str = options.Get("queryType").ToString();
        if (!mongocrypt_ctx_setopt_query_type(context.get(), query_type_str.data(), -1)) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binaryValue(BufferToBinary(valueBuffer.As<Uint8Array>()));

    const bool isExpressionMode = options.Get("expressionMode").ToBoolean();

    const bool status = isExpressionMode
                        ? mongocrypt_ctx_explicit_encrypt_expression_init(context.get(), binaryValue.get())
                        : mongocrypt_ctx_explicit_encrypt_init(context.get(), binaryValue.get());

    if (!status) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

Value MongoCrypt::MakeDecryptionContext(const CallbackInfo& info) {
    if (!info[0].IsBuffer()) {
        throw TypeError::New(Env(), "First parameter must be a Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(info[0].As<Uint8Array>()));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));

    if (!mongocrypt_ctx_decrypt_init(context.get(), binary.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

Value MongoCrypt::MakeExplicitDecryptionContext(const CallbackInfo& info) {
    if (!info[0].IsBuffer()) {
        throw TypeError::New(Env(), "First parameter must be a Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(info[0].As<Uint8Array>()));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));

    if (!mongocrypt_ctx_explicit_decrypt_init(context.get(), binary.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

Value MongoCrypt::MakeDataKeyContext(const CallbackInfo& info) {
    Napi::Value optionsBuffer = info[0];
    if (!optionsBuffer.IsBuffer()) {
        throw TypeError::New(Env(), "Parameter `options` must be a Buffer");
    }

    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
        BufferToBinary(optionsBuffer.As<Uint8Array>()));

    if (!mongocrypt_ctx_setopt_key_encryption_key(context.get(), binary.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    Object options = info[1].ToObject();
    if (options.Has("keyAltNames")) {
        Napi::Value keyAltNames = options["keyAltNames"];

        if (keyAltNames.IsArray()) {
            Array keyAltNamesArray = keyAltNames.As<Array>();
            uint32_t keyAltNamesLength = keyAltNamesArray.Length();
            for (uint32_t i = 0; i < keyAltNamesLength; i += 1) {
                if (keyAltNamesArray.Has(i)) {
                    Napi::Value keyAltName = keyAltNamesArray[i];
                    if (!keyAltName.IsBuffer()) {
                        // We should never get here
                        throw TypeError::New(Env(), "Serialized keyAltName must be a Buffer");
                    }

                    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
                        BufferToBinary(keyAltName.As<Uint8Array>()));
                    if (!mongocrypt_ctx_setopt_key_alt_name(context.get(), binary.get())) {
                        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
                    }
                }
            }
        }
    }

    if (options.Has("keyMaterial")) {
        Napi::Value keyMaterial = options["keyMaterial"];

        if (!keyMaterial.IsUndefined()) {
            if (!keyMaterial.IsBuffer()) {
                // We should never get here
                throw TypeError::New(Env(), "Serialized keyMaterial must be a Buffer");
            }

            std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> binary(
                BufferToBinary(keyMaterial.As<Uint8Array>()));
            if (!mongocrypt_ctx_setopt_key_material(context.get(), binary.get())) {
                throw TypeError::New(Env(), errorStringFromStatus(context.get()));
            }
        }
    }

    if (!mongocrypt_ctx_datakey_init(context.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

Value MongoCrypt::MakeRewrapManyDataKeyContext(const CallbackInfo& info) {
    Napi::Value filter_buffer = info[0];
    if (!filter_buffer.IsBuffer()) {
        throw TypeError::New(Env(), "Parameter `options` must be a Buffer");
    }

    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(_mongo_crypt.get()));

    Napi::Value key_encryption_key = info[1];
    if (key_encryption_key.IsBuffer()) {
        std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> key_binary(
            BufferToBinary(key_encryption_key.As<Uint8Array>()));
        if (!mongocrypt_ctx_setopt_key_encryption_key(context.get(), key_binary.get())) {
            throw TypeError::New(Env(), errorStringFromStatus(context.get()));
        }
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> filter_binary(
        BufferToBinary(filter_buffer.As<Uint8Array>()));
    if (!mongocrypt_ctx_rewrap_many_datakey_init(context.get(), filter_binary.get())) {
        throw TypeError::New(Env(), errorStringFromStatus(context.get()));
    }

    return MongoCryptContext::NewInstance(Env(), std::move(context));
}

// Store callbacks as nested properties on the MongoCrypt binding object
// itself, and use these helpers to do so. Storing them as JS engine
// References is a big memory leak footgun.
Function MongoCrypt::GetCallback(const char* name) {
    Napi::Value storage = Value().Get("__callbackStorage");
    if (!storage.IsObject()) {
        throw Error::New(Env(), "Cannot get callbacks becauses none were registered");
    }
    Napi::Value entry = storage.As<Object>().Get(name);
    if (!entry.IsFunction()) {
        throw Error::New(Env(), std::string("Trying to look up unknown callback ") + name);
    }
    return entry.As<Function>();
}

void MongoCrypt::SetCallback(const char* name, Napi::Value fn) {
    if (!fn.IsFunction()) {
        throw Error::New(Env(), std::string("Storing non-function as callback ") + name);
    }

    Napi::Value storage = Value().Get("__callbackStorage");
    if (!storage.IsObject()) {
        storage = Object::New(Env());
        Value().Set("__callbackStorage", storage);
    }
    storage.As<Object>().Set(name, fn);
}

Function MongoCryptContext::Init(Napi::Env env) {
  return
      DefineClass(env,
                  "MongoCryptContext",
                  {
                    InstanceMethod("nextMongoOperation", &MongoCryptContext::NextMongoOperation),
                    InstanceMethod("addMongoOperationResponse", &MongoCryptContext::AddMongoOperationResponse),
                    InstanceMethod("finishMongoOperation", &MongoCryptContext::FinishMongoOperation),
                    InstanceMethod("nextKMSRequest", &MongoCryptContext::NextKMSRequest),
                    InstanceMethod("provideKMSProviders", &MongoCryptContext::ProvideKMSProviders),
                    InstanceMethod("finishKMSRequests", &MongoCryptContext::FinishKMSRequests),
                    InstanceMethod("finalize", &MongoCryptContext::FinalizeContext),
                    InstanceAccessor("status", &MongoCryptContext::Status, nullptr),
                    InstanceAccessor("state", &MongoCryptContext::State, nullptr)
                  });
}

Object MongoCryptContext::NewInstance(Napi::Env env, std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context) {
    InstanceData* instance_data = env.GetInstanceData<InstanceData>();
    Object obj = instance_data->MongoCryptContextCtor.Value().New({});
    MongoCryptContext* instance = MongoCryptContext::Unwrap(obj);
    instance->_context = std::move(context);
    return obj;
}

MongoCryptContext::MongoCryptContext(const CallbackInfo& info)
    : ObjectWrap(info) {}

Value MongoCryptContext::Status(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_ctx_status(_context.get(), status.get());
    return ExtractStatus(Env(), status.get());
}

Value MongoCryptContext::State(const CallbackInfo& info) {
    return Number::New(Env(), mongocrypt_ctx_state(_context.get()));
}

Value MongoCryptContext::NextMongoOperation(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> op_bson(mongocrypt_binary_new());
    mongocrypt_ctx_mongo_op(_context.get(), op_bson.get());
    return BufferFromBinary(Env(), op_bson.get());
}

void MongoCryptContext::AddMongoOperationResponse(const CallbackInfo& info) {
    if (info.Length() != 1 || !info[0].IsObject()) {
        throw TypeError::New(Env(), "Missing required parameter `buffer`");
    }

    if (!info[0].IsBuffer()) {
        throw TypeError::New(Env(), "First parameter must be a Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> reply_bson(
        BufferToBinary(info[0].As<Uint8Array>()));
    mongocrypt_ctx_mongo_feed(_context.get(), reply_bson.get());
    // return value
}

void MongoCryptContext::FinishMongoOperation(const CallbackInfo& info) {
    mongocrypt_ctx_mongo_done(_context.get());
}

void MongoCryptContext::ProvideKMSProviders(const CallbackInfo& info) {
    if (info.Length() != 1 || !info[0].IsObject()) {
        throw TypeError::New(Env(), "Missing required parameter `buffer`");
    }

    if (!info[0].IsBuffer()) {
        throw TypeError::New(Env(), "First parameter must be a Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> kms_bson(
        BufferToBinary(info[0].As<Uint8Array>()));
    mongocrypt_ctx_provide_kms_providers(_context.get(), kms_bson.get());
}

Value MongoCryptContext::NextKMSRequest(const CallbackInfo& info) {
    mongocrypt_kms_ctx_t* kms_context = mongocrypt_ctx_next_kms_ctx(_context.get());
    if (kms_context == nullptr) {
        return Env().Null();
    } else {
        Object result = MongoCryptKMSRequest::NewInstance(Env(), kms_context);
        // The lifetime of the `kms_context` pointer is not specified
        // anywhere, so it seems reasonable to assume that it is at
        // least the lifetime of this context object.
        // Use a symbol to enforce that lifetime dependency.
        result.Set("__kmsRequestContext", Value());
        return result;
    }
}

void MongoCryptContext::FinishKMSRequests(const CallbackInfo& info) {
    mongocrypt_ctx_kms_done(_context.get());
}

Value MongoCryptContext::FinalizeContext(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> output(mongocrypt_binary_new());
    mongocrypt_ctx_finalize(_context.get(), output.get());
    return BufferFromBinary(Env(), output.get());
}

Function MongoCryptKMSRequest::Init(Napi::Env env) {
  return
      DefineClass(env,
                  "MongoCryptKMSRequest",
                  {
                    InstanceMethod("addResponse", &MongoCryptKMSRequest::AddResponse),
                    InstanceAccessor("status", &MongoCryptKMSRequest::Status, nullptr),
                    InstanceAccessor("bytesNeeded", &MongoCryptKMSRequest::BytesNeeded, nullptr),
                    InstanceAccessor("kmsProvider", &MongoCryptKMSRequest::KMSProvider, nullptr),
                    InstanceAccessor("endpoint", &MongoCryptKMSRequest::Endpoint, nullptr),
                    InstanceAccessor("message", &MongoCryptKMSRequest::Message, nullptr)
                  });
}

Object MongoCryptKMSRequest::NewInstance(Napi::Env env, mongocrypt_kms_ctx_t* kms_context) {
    InstanceData* instance_data = env.GetInstanceData<InstanceData>();
    Object obj = instance_data->MongoCryptKMSRequestCtor.Value().New({});
    MongoCryptKMSRequest* instance = MongoCryptKMSRequest::Unwrap(obj);
    instance->_kms_context = kms_context;
    return obj;
}

MongoCryptKMSRequest::MongoCryptKMSRequest(const CallbackInfo& info)
    : ObjectWrap(info), _kms_context(nullptr) {}

Value MongoCryptKMSRequest::Status(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_status_t, MongoCryptStatusDeleter> status(mongocrypt_status_new());
    mongocrypt_kms_ctx_status(_kms_context, status.get());
    return ExtractStatus(Env(), status.get());
}

Value MongoCryptKMSRequest::BytesNeeded(const CallbackInfo& info) {
    return Number::New(Env(), mongocrypt_kms_ctx_bytes_needed(_kms_context));
}

Value MongoCryptKMSRequest::KMSProvider(const CallbackInfo& info) {
    return String::New(Env(), mongocrypt_kms_ctx_get_kms_provider(_kms_context, nullptr));
}

Value MongoCryptKMSRequest::Message(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> message(mongocrypt_binary_new());
    mongocrypt_kms_ctx_message(_kms_context, message.get());
    return BufferFromBinary(Env(), message.get());
}

Value MongoCryptKMSRequest::Endpoint(const CallbackInfo& info) {
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> message(mongocrypt_binary_new());

    const char* endpoint;
    mongocrypt_kms_ctx_endpoint(_kms_context, &endpoint);
    return String::New(Env(), endpoint);
}

void MongoCryptKMSRequest::AddResponse(const CallbackInfo& info) {
    if (!info[0].IsBuffer()) {
        throw TypeError::New(Env(), "First parameter must be of type Buffer");
    }

    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> reply_bytes(
        BufferToBinary(info[0].As<Uint8Array>()));
    mongocrypt_kms_ctx_feed(_kms_context, reply_bytes.get());
}

static Object Init(Env env, Object exports) {
    Function MongoCryptCtor = MongoCrypt::Init(env);
    Function MongoCryptContextCtor = MongoCryptContext::Init(env);
    Function MongoCryptKMSRequestCtor = MongoCryptKMSRequest::Init(env);
    exports["MongoCrypt"] = MongoCryptCtor;
    exports["MongoCryptContextCtor"] = MongoCryptContextCtor;
    exports["MongoCryptKMSRequestCtor"] = MongoCryptKMSRequestCtor;
    env.SetInstanceData(new InstanceData {
        Reference<Function>::New(MongoCryptContextCtor, 1),
        Reference<Function>::New(MongoCryptKMSRequestCtor, 1)
    });
    return exports;
}

NODE_API_MODULE(mongocrypt, Init)

} // namespace node_mongocrypt
