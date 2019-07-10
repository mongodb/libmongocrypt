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
    result->Set(Nan::New("type").ToLocalChecked(),
                Nan::New<v8::Number>(mongocrypt_status_type(status)));
    result->Set(Nan::New("code").ToLocalChecked(),
                Nan::New<v8::Number>(mongocrypt_status_code(status)));

    const char* message = mongocrypt_status_message(status, NULL);
    if (message != NULL) {
        result->Set(Nan::New("message").ToLocalChecked(), Nan::New(message).ToLocalChecked());
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

    uint8_t* data_copy = new uint8_t[len];
    memcpy(data_copy, data, len);

    v8::Local<v8::Object> buffer = Nan::NewBuffer((char*)data_copy, len).ToLocalChecked();
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

            mongocrypt_binary_t* binary = BufferToBinary(key);
            if (!mongocrypt_setopt_kms_provider_local(crypt, binary)) {
                return std::make_pair(false, errorStringFromStatus(crypt));
            }
        }
    }

    return std::make_pair(true, std::string());
}

std::pair<bool, std::string> setEncryptionOptions(mongocrypt_ctx_t* context,
                                                  v8::Local<v8::Object> options) {
    Nan::HandleScope scope;
    v8::Local<v8::String> KEY_ID_KEY = Nan::New("keyId").ToLocalChecked();
    v8::Local<v8::String> ALGORITHM_KEY = Nan::New("algorithm").ToLocalChecked();

    if (Nan::Has(options, KEY_ID_KEY).FromMaybe(false)) {
        if (!Nan::Get(options, KEY_ID_KEY).ToLocalChecked()->IsObject()) {
            return std::make_pair(false, "`keyId` must be a Buffer");
        }

        v8::Local<v8::Object> keyId =
            Nan::To<v8::Object>(Nan::Get(options, KEY_ID_KEY).ToLocalChecked()).ToLocalChecked();
        if (!node::Buffer::HasInstance(keyId)) {
            return std::make_pair(false, "`keyId` must be a Buffer");
        }

        mongocrypt_binary_t* binary = BufferToBinary(keyId);
        if (!mongocrypt_ctx_setopt_key_id(context, binary)) {
            return std::make_pair(false, errorStringFromStatus(context));
        }
    }

    if (Nan::Has(options, ALGORITHM_KEY).FromMaybe(false)) {
        std::string algorithm = StringOptionValue(options, "algorithm");
        if (!mongocrypt_ctx_setopt_algorithm(
                context, const_cast<char*>(algorithm.c_str()), algorithm.size())) {
            return std::make_pair(false, errorStringFromStatus(context));
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
        fprintf(stderr, "No logger set, but long handler registered\n");
        return;
    }

    Nan::HandleScope scope;
    v8::Local<v8::Value> argv[] = {Nan::New(level), Nan::New(message).ToLocalChecked()};
    Nan::Call(*mongoCrypt->_logger.get(), Nan::GetCurrentContext()->Global(), 2, argv);
}

MongoCrypt::MongoCrypt(mongocrypt_t* mongo_crypt, Nan::Callback* logger)
    : _mongo_crypt(mongo_crypt), _logger(logger) {}

NAN_METHOD(MongoCrypt::New) {
    Nan::HandleScope scope;

    if (info.IsConstructCall()) {
        if (info.Length() >= 1 && !info[0]->IsObject()) {
            Nan::ThrowTypeError("First parameter must be an object");
            return;
        }

        Nan::Callback* logger = 0;
        std::unique_ptr<mongocrypt_t, MongoCryptDeleter> crypt(mongocrypt_new());

        if (info.Length() >= 1) {
            v8::Local<v8::Object> options = Nan::To<v8::Object>(info[0]).ToLocalChecked();
            v8::Local<v8::String> KMS_PROVIDERS_KEY = Nan::New("kmsProviders").ToLocalChecked();
            v8::Local<v8::String> SCHEMA_MAP_KEY = Nan::New("schemaMap").ToLocalChecked();
            v8::Local<v8::String> LOGGER_KEY = Nan::New("logger").ToLocalChecked();

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
        }

        MongoCrypt* class_instance = new MongoCrypt(crypt.release(), logger);
        if (logger) {
            if (!mongocrypt_setopt_log_handler(
                    class_instance->_mongo_crypt.get(), MongoCrypt::logHandler, class_instance)) {
                Nan::ThrowTypeError(errorStringFromStatus(class_instance->_mongo_crypt.get()));
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
    std::string ns(*Nan::Utf8String(info[0]->ToString()));
    std::unique_ptr<mongocrypt_ctx_t, MongoCryptContextDeleter> context(
        mongocrypt_ctx_new(mc->_mongo_crypt.get()));

    v8::Local<v8::Object> commandBuffer = Nan::To<v8::Object>(info[1]).ToLocalChecked();
    if (!node::Buffer::HasInstance(commandBuffer)) {
        Nan::ThrowTypeError("Paramter `command` must be a Buffer");
        return;
    }

    if (info.Length() > 2) {
        v8::Local<v8::Object> options = Nan::To<v8::Object>(info[2]).ToLocalChecked();
        auto result = setEncryptionOptions(context.get(), options);
        if (!result.first) {
            Nan::ThrowTypeError(result.second);
            return;
        }
    }

    if (!mongocrypt_ctx_encrypt_init(
            context.get(), ns.c_str(), ns.size(), BufferToBinary(commandBuffer))) {
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
        auto result = setEncryptionOptions(context.get(), options);
        if (!result.first) {
            Nan::ThrowTypeError(result.second);
            return;
        }
    }

    if (!mongocrypt_ctx_explicit_encrypt_init(context.get(), BufferToBinary(valueBuffer))) {
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
        BufferToBinary(info[0]->ToObject()));
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
        BufferToBinary(info[0]->ToObject()));
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
    std::string kmsProvider(*Nan::Utf8String(info[0]->ToString()));

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
    } else if (kmsProvider == "local") {
        mongocrypt_ctx_setopt_masterkey_local(context.get());
    } else {
        Nan::ThrowTypeError("Invalid KMS provider");
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
        BufferToBinary(info[0]->ToObject()));
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
    std::unique_ptr<mongocrypt_binary_t, MongoCryptBinaryDeleter> reply_bytes(
        BufferToBinary(info[0]->ToObject()));
    mongocrypt_kms_ctx_feed(mckr->_kms_context, reply_bytes.get());
}

NAN_MODULE_INIT(Init) {
    MongoCrypt::Init(target);
    MongoCryptContext::Init(target);
    MongoCryptKMSRequest::Init(target);
}

NODE_MODULE(mongocrypt, Init)
