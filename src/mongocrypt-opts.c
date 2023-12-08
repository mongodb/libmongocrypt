/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bson/bson.h>

#include "mongocrypt-log-private.h"
#include "mongocrypt-opts-private.h"
#include "mongocrypt-private.h"
#include <mongocrypt-util-private.h> // mc_iter_document_as_bson

#include <kms_message/kms_b64.h>

void _mongocrypt_opts_init(_mongocrypt_opts_t *opts) {
    BSON_ASSERT_PARAM(opts);
    memset(opts, 0, sizeof(*opts));
}

static void _mongocrypt_opts_kms_provider_azure_cleanup(_mongocrypt_opts_kms_provider_azure_t *kms_provider_azure) {
    if (!kms_provider_azure) {
        return;
    }
    bson_free(kms_provider_azure->client_id);
    bson_free(kms_provider_azure->client_secret);
    bson_free(kms_provider_azure->tenant_id);
    bson_free(kms_provider_azure->access_token);
    _mongocrypt_endpoint_destroy(kms_provider_azure->identity_platform_endpoint);
}

static void _mongocrypt_opts_kms_provider_gcp_cleanup(_mongocrypt_opts_kms_provider_gcp_t *kms_provider_gcp) {
    if (!kms_provider_gcp) {
        return;
    }
    bson_free(kms_provider_gcp->email);
    _mongocrypt_endpoint_destroy(kms_provider_gcp->endpoint);
    _mongocrypt_buffer_cleanup(&kms_provider_gcp->private_key);
    bson_free(kms_provider_gcp->access_token);
}

void _mongocrypt_opts_kms_providers_cleanup(_mongocrypt_opts_kms_providers_t *kms_providers) {
    if (!kms_providers) {
        return;
    }
    bson_free(kms_providers->aws_mut.secret_access_key);
    bson_free(kms_providers->aws_mut.access_key_id);
    bson_free(kms_providers->aws_mut.session_token);
    _mongocrypt_buffer_cleanup(&kms_providers->local_mut.key);
    _mongocrypt_opts_kms_provider_azure_cleanup(&kms_providers->azure_mut);
    _mongocrypt_opts_kms_provider_gcp_cleanup(&kms_providers->gcp_mut);
    _mongocrypt_endpoint_destroy(kms_providers->kmip_mut.endpoint);
}

void _mongocrypt_opts_merge_kms_providers(_mongocrypt_opts_kms_providers_t *dest,
                                          const _mongocrypt_opts_kms_providers_t *source) {
    BSON_ASSERT_PARAM(dest);
    BSON_ASSERT_PARAM(source);

    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
        memcpy(&dest->aws_mut, &source->aws_mut, sizeof(source->aws_mut));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
        memcpy(&dest->local_mut, &source->local_mut, sizeof(source->local_mut));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_AZURE) {
        memcpy(&dest->azure_mut, &source->azure_mut, sizeof(source->azure_mut));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_GCP) {
        memcpy(&dest->gcp_mut, &source->gcp_mut, sizeof(source->gcp_mut));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
    }
    if (source->configured_providers & MONGOCRYPT_KMS_PROVIDER_KMIP) {
        memcpy(&dest->kmip_mut, &source->kmip_mut, sizeof(source->kmip_mut));
        dest->configured_providers |= MONGOCRYPT_KMS_PROVIDER_KMIP;
    }
    /* ensure all providers were copied */
    BSON_ASSERT(!(source->configured_providers & ~dest->configured_providers));
}

void _mongocrypt_opts_cleanup(_mongocrypt_opts_t *opts) {
    if (!opts) {
        return;
    }
    _mongocrypt_opts_kms_providers_cleanup(&opts->kms_providers);
    _mongocrypt_buffer_cleanup(&opts->schema_map);
    _mongocrypt_buffer_cleanup(&opts->encrypted_field_config_map);
    // Free any lib search paths added by the caller
    for (int i = 0; i < opts->n_crypt_shared_lib_search_paths; ++i) {
        mstr_free(opts->crypt_shared_lib_search_paths[i]);
    }
    bson_free(opts->crypt_shared_lib_search_paths);
    mstr_free(opts->crypt_shared_lib_override_path);
}

bool _mongocrypt_opts_kms_providers_validate(_mongocrypt_opts_t *opts,
                                             _mongocrypt_opts_kms_providers_t *kms_providers,
                                             mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(opts);
    BSON_ASSERT_PARAM(kms_providers);

    if (!kms_providers->configured_providers && !kms_providers->need_credentials) {
        CLIENT_ERR("no kms provider set");
        return false;
    }

    if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) {
        if (!kms_providers->aws_mut.access_key_id || !kms_providers->aws_mut.secret_access_key) {
            CLIENT_ERR("aws credentials unset");
            return false;
        }
    }

    if (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) {
        if (_mongocrypt_buffer_empty(&kms_providers->local_mut.key)) {
            CLIENT_ERR("local data key unset");
            return false;
        }
    }

    if (kms_providers->need_credentials && !opts->use_need_kms_credentials_state) {
        CLIENT_ERR("on-demand credentials not enabled");
        return false;
    }

    return true;
}

/* _shares_bson_fields checks if @one or @two share any top-level field names.
 * Returns false on error and sets @status. Returns true if no error
 * occurred. Sets @found to the first shared field name found.
 * If no shared field names are found, @found is set to NULL.
 */
static bool _shares_bson_fields(bson_t *one, bson_t *two, const char **found, mongocrypt_status_t *status) {
    bson_iter_t iter1;
    bson_iter_t iter2;

    BSON_ASSERT_PARAM(one);
    BSON_ASSERT_PARAM(two);
    BSON_ASSERT_PARAM(found);
    *found = NULL;
    if (!bson_iter_init(&iter1, one)) {
        CLIENT_ERR("error iterating one BSON in _shares_bson_fields");
        return false;
    }
    while (bson_iter_next(&iter1)) {
        const char *key1 = bson_iter_key(&iter1);

        if (!bson_iter_init(&iter2, two)) {
            CLIENT_ERR("error iterating two BSON in _shares_bson_fields");
            return false;
        }
        while (bson_iter_next(&iter2)) {
            const char *key2 = bson_iter_key(&iter2);
            if (0 == strcmp(key1, key2)) {
                *found = key1;
                return true;
            }
        }
    }
    return true;
}

/* _validate_encrypted_field_config_map_and_schema_map validates that the same
 * namespace is not both in encrypted_field_config_map and schema_map. */
static bool _validate_encrypted_field_config_map_and_schema_map(_mongocrypt_buffer_t *encrypted_field_config_map,
                                                                _mongocrypt_buffer_t *schema_map,
                                                                mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(encrypted_field_config_map);
    BSON_ASSERT_PARAM(schema_map);

    const char *found;
    bson_t schema_map_bson;
    bson_t encrypted_field_config_map_bson;

    /* If either map is unset, there is nothing to validate. Return true to
     * signal no error. */
    if (_mongocrypt_buffer_empty(encrypted_field_config_map)) {
        return true;
    }
    if (_mongocrypt_buffer_empty(schema_map)) {
        return true;
    }

    if (!_mongocrypt_buffer_to_bson(schema_map, &schema_map_bson)) {
        CLIENT_ERR("error converting schema_map to BSON");
        return false;
    }
    if (!_mongocrypt_buffer_to_bson(encrypted_field_config_map, &encrypted_field_config_map_bson)) {
        CLIENT_ERR("error converting encrypted_field_config_map to BSON");
        return false;
    }
    if (!_shares_bson_fields(&schema_map_bson, &encrypted_field_config_map_bson, &found, status)) {
        return false;
    }
    if (found != NULL) {
        CLIENT_ERR("%s is present in both schema_map and encrypted_field_config_map", found);
        return false;
    }
    return true;
}

bool _mongocrypt_opts_validate(_mongocrypt_opts_t *opts, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(opts);

    if (!_validate_encrypted_field_config_map_and_schema_map(&opts->encrypted_field_config_map,
                                                             &opts->schema_map,
                                                             status)) {
        return false;
    }
    return _mongocrypt_opts_kms_providers_validate(opts, &opts->kms_providers, status);
}

bool _mongocrypt_opts_kms_providers_lookup(const _mongocrypt_opts_kms_providers_t *kms_providers,
                                           const char *kmsid,
                                           mc_kms_creds_t *out) {
    *out = (mc_kms_creds_t){0};
    if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AWS) && 0 == strcmp(kmsid, "aws")) {
        out->type = MONGOCRYPT_KMS_PROVIDER_AWS;
        out->value.aws = kms_providers->aws_mut;
        return true;
    }
    if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AZURE) && 0 == strcmp(kmsid, "azure")) {
        out->type = MONGOCRYPT_KMS_PROVIDER_AZURE;
        out->value.azure = kms_providers->azure_mut;
        return true;
    }

    if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_GCP) && 0 == strcmp(kmsid, "gcp")) {
        out->type = MONGOCRYPT_KMS_PROVIDER_GCP;
        out->value.gcp = kms_providers->gcp_mut;
        return true;
    }

    if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_LOCAL) && 0 == strcmp(kmsid, "local")) {
        out->type = MONGOCRYPT_KMS_PROVIDER_LOCAL;
        out->value.local = kms_providers->local_mut;
        return true;
    }

    if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_KMIP) && 0 == strcmp(kmsid, "kmip")) {
        out->type = MONGOCRYPT_KMS_PROVIDER_KMIP;
        out->value.kmip = kms_providers->kmip_mut;
        return true;
    }

    // TODO: MONGOCRYPT-605: check for KMS providers with a name.

    return false;
}

bool _mongocrypt_parse_optional_utf8(const bson_t *bson, const char *dotkey, char **out, mongocrypt_status_t *status) {
    bson_iter_t iter;
    bson_iter_t child;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    *out = NULL;

    if (!bson_iter_init(&iter, bson)) {
        CLIENT_ERR("invalid BSON");
        return false;
    }
    if (!bson_iter_find_descendant(&iter, dotkey, &child)) {
        /* Not found. Not an error. */
        return true;
    }
    if (!BSON_ITER_HOLDS_UTF8(&child)) {
        CLIENT_ERR("expected UTF-8 %s", dotkey);
        return false;
    }

    *out = bson_strdup(bson_iter_utf8(&child, NULL));
    return true;
}

bool _mongocrypt_parse_required_utf8(const bson_t *bson, const char *dotkey, char **out, mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_utf8(bson, dotkey, out, status)) {
        return false;
    }

    if (!*out) {
        CLIENT_ERR("expected UTF-8 %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_optional_endpoint(const bson_t *bson,
                                         const char *dotkey,
                                         _mongocrypt_endpoint_t **out,
                                         _mongocrypt_endpoint_parse_opts_t *opts,
                                         mongocrypt_status_t *status) {
    char *endpoint_raw;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    *out = NULL;

    if (!_mongocrypt_parse_optional_utf8(bson, dotkey, &endpoint_raw, status)) {
        return false;
    }

    /* Not found. Not an error. */
    if (!endpoint_raw) {
        return true;
    }

    *out = _mongocrypt_endpoint_new(endpoint_raw, -1, opts, status);
    bson_free(endpoint_raw);
    return (*out) != NULL;
}

bool _mongocrypt_parse_required_endpoint(const bson_t *bson,
                                         const char *dotkey,
                                         _mongocrypt_endpoint_t **out,
                                         _mongocrypt_endpoint_parse_opts_t *opts,
                                         mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_endpoint(bson, dotkey, out, opts, status)) {
        return false;
    }

    if (!*out) {
        CLIENT_ERR("expected endpoint %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_optional_binary(const bson_t *bson,
                                       const char *dotkey,
                                       _mongocrypt_buffer_t *out,
                                       mongocrypt_status_t *status) {
    bson_iter_t iter;
    bson_iter_t child;

    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    _mongocrypt_buffer_init(out);

    if (!bson_iter_init(&iter, bson)) {
        CLIENT_ERR("invalid BSON");
        return false;
    }
    if (!bson_iter_find_descendant(&iter, dotkey, &child)) {
        /* Not found. Not an error. */
        return true;
    }
    if (BSON_ITER_HOLDS_UTF8(&child)) {
        size_t out_len;
        /* Attempt to base64 decode. */
        out->data = kms_message_b64_to_raw(bson_iter_utf8(&child, NULL), &out_len);
        if (!out->data) {
            CLIENT_ERR("unable to parse base64 from UTF-8 field %s", dotkey);
            return false;
        }
        BSON_ASSERT(out_len <= UINT32_MAX);
        out->len = (uint32_t)out_len;
        out->owned = true;
    } else if (BSON_ITER_HOLDS_BINARY(&child)) {
        if (!_mongocrypt_buffer_copy_from_binary_iter(out, &child)) {
            CLIENT_ERR("unable to parse binary from field %s", dotkey);
            return false;
        }
    } else {
        CLIENT_ERR("expected UTF-8 or binary %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_parse_required_binary(const bson_t *bson,
                                       const char *dotkey,
                                       _mongocrypt_buffer_t *out,
                                       mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(bson);
    BSON_ASSERT_PARAM(dotkey);
    BSON_ASSERT_PARAM(out);

    if (!_mongocrypt_parse_optional_binary(bson, dotkey, out, status)) {
        return false;
    }

    if (out->len == 0) {
        CLIENT_ERR("expected UTF-8 or binary %s", dotkey);
        return false;
    }

    return true;
}

bool _mongocrypt_check_allowed_fields_va(const bson_t *bson, const char *dotkey, mongocrypt_status_t *status, ...) {
    va_list args;
    const char *field;
    bson_iter_t iter;

    BSON_ASSERT_PARAM(bson);

    if (dotkey) {
        bson_iter_t parent;

        bson_iter_init(&parent, bson);
        if (!bson_iter_find_descendant(&parent, dotkey, &iter) || !BSON_ITER_HOLDS_DOCUMENT(&iter)) {
            CLIENT_ERR("invalid BSON, expected %s", dotkey);
            return false;
        }
        bson_iter_recurse(&iter, &iter);
    } else {
        bson_iter_init(&iter, bson);
    }

    while (bson_iter_next(&iter)) {
        bool found = false;

        va_start(args, status);
        field = va_arg(args, const char *);
        while (field) {
            if (0 == strcmp(field, bson_iter_key(&iter))) {
                found = true;
                break;
            }
            field = va_arg(args, const char *);
        }
        va_end(args);

        if (!found) {
            CLIENT_ERR("Unexpected field: '%s'", bson_iter_key(&iter));
            return false;
        }
    }
    return true;
}

bool _mongocrypt_parse_kms_providers(mongocrypt_binary_t *kms_providers_definition,
                                     _mongocrypt_opts_kms_providers_t *kms_providers,
                                     mongocrypt_status_t *status,
                                     _mongocrypt_log_t *log) {
    bson_t as_bson;
    bson_iter_t iter;

    BSON_ASSERT_PARAM(kms_providers_definition);
    BSON_ASSERT_PARAM(kms_providers);
    if (!_mongocrypt_binary_to_bson(kms_providers_definition, &as_bson) || !bson_iter_init(&iter, &as_bson)) {
        CLIENT_ERR("invalid BSON");
        return false;
    }

    while (bson_iter_next(&iter)) {
        const char *field_name;
        bson_t field_bson;

        field_name = bson_iter_key(&iter);
        if (!mc_iter_document_as_bson(&iter, &field_bson, status)) {
            return false;
        }

        if (0 == strcmp(field_name, "azure") && bson_empty(&field_bson)) {
            kms_providers->need_credentials |= MONGOCRYPT_KMS_PROVIDER_AZURE;
        } else if (0 == strcmp(field_name, "azure")) {
            if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_AZURE)) {
                CLIENT_ERR("azure KMS provider already set");
                return false;
            }

            if (!_mongocrypt_parse_optional_utf8(&as_bson,
                                                 "azure.accessToken",
                                                 &kms_providers->azure_mut.access_token,
                                                 status)) {
                return false;
            }

            if (kms_providers->azure_mut.access_token) {
                // Caller provides an accessToken directly
                if (!_mongocrypt_check_allowed_fields(&as_bson, "azure", status, "accessToken")) {
                    return false;
                }
                kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
                continue;
            }

            // No accessToken given, so we'll need to look one up on our own later
            // using the Azure API

            if (!_mongocrypt_parse_required_utf8(&as_bson,
                                                 "azure.tenantId",
                                                 &kms_providers->azure_mut.tenant_id,
                                                 status)) {
                return false;
            }

            if (!_mongocrypt_parse_required_utf8(&as_bson,
                                                 "azure.clientId",
                                                 &kms_providers->azure_mut.client_id,
                                                 status)) {
                return false;
            }

            if (!_mongocrypt_parse_required_utf8(&as_bson,
                                                 "azure.clientSecret",
                                                 &kms_providers->azure_mut.client_secret,
                                                 status)) {
                return false;
            }

            if (!_mongocrypt_parse_optional_endpoint(&as_bson,
                                                     "azure.identityPlatformEndpoint",
                                                     &kms_providers->azure_mut.identity_platform_endpoint,
                                                     NULL /* opts */,
                                                     status)) {
                return false;
            }

            if (!_mongocrypt_check_allowed_fields(&as_bson,
                                                  "azure",
                                                  status,
                                                  "tenantId",
                                                  "clientId",
                                                  "clientSecret",
                                                  "identityPlatformEndpoint")) {
                return false;
            }
            kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AZURE;
        } else if (0 == strcmp(field_name, "gcp") && bson_empty(&field_bson)) {
            kms_providers->need_credentials |= MONGOCRYPT_KMS_PROVIDER_GCP;
        } else if (0 == strcmp(field_name, "gcp")) {
            if (0 != (kms_providers->configured_providers & MONGOCRYPT_KMS_PROVIDER_GCP)) {
                CLIENT_ERR("gcp KMS provider already set");
                return false;
            }

            if (!_mongocrypt_parse_optional_utf8(&as_bson,
                                                 "gcp.accessToken",
                                                 &kms_providers->gcp_mut.access_token,
                                                 status)) {
                return false;
            }

            if (NULL != kms_providers->gcp_mut.access_token) {
                /* "gcp" document has form:
                 * {
                 *    "accessToken": <required UTF-8>
                 * }
                 */
                if (!_mongocrypt_check_allowed_fields(&as_bson, "gcp", status, "accessToken")) {
                    return false;
                }
                kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
                continue;
            }

            /* "gcp" document has form:
             * {
             *    "email": <required UTF-8>
             *    "privateKey": <required UTF-8 or Binary>
             * }
             */
            if (!_mongocrypt_parse_required_utf8(&as_bson, "gcp.email", &kms_providers->gcp_mut.email, status)) {
                return false;
            }

            if (!_mongocrypt_parse_required_binary(&as_bson,
                                                   "gcp.privateKey",
                                                   &kms_providers->gcp_mut.private_key,
                                                   status)) {
                return false;
            }

            if (!_mongocrypt_parse_optional_endpoint(&as_bson,
                                                     "gcp.endpoint",
                                                     &kms_providers->gcp_mut.endpoint,
                                                     NULL /* opts */,
                                                     status)) {
                return false;
            }

            if (!_mongocrypt_check_allowed_fields(&as_bson, "gcp", status, "email", "privateKey", "endpoint")) {
                return false;
            }
            kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_GCP;
        } else if (0 == strcmp(field_name, "local") && bson_empty(&field_bson)) {
            kms_providers->need_credentials |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
        } else if (0 == strcmp(field_name, "local")) {
            if (!_mongocrypt_parse_required_binary(&as_bson, "local.key", &kms_providers->local_mut.key, status)) {
                return false;
            }

            if (kms_providers->local_mut.key.len != MONGOCRYPT_KEY_LEN) {
                CLIENT_ERR("local key must be %d bytes", MONGOCRYPT_KEY_LEN);
                return false;
            }

            if (!_mongocrypt_check_allowed_fields(&as_bson, "local", status, "key")) {
                return false;
            }
            kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_LOCAL;
        } else if (0 == strcmp(field_name, "aws") && bson_empty(&field_bson)) {
            kms_providers->need_credentials |= MONGOCRYPT_KMS_PROVIDER_AWS;
        } else if (0 == strcmp(field_name, "aws")) {
            if (!_mongocrypt_parse_required_utf8(&as_bson,
                                                 "aws.accessKeyId",
                                                 &kms_providers->aws_mut.access_key_id,
                                                 status)) {
                return false;
            }
            if (!_mongocrypt_parse_required_utf8(&as_bson,
                                                 "aws.secretAccessKey",
                                                 &kms_providers->aws_mut.secret_access_key,
                                                 status)) {
                return false;
            }

            if (!_mongocrypt_parse_optional_utf8(&as_bson,
                                                 "aws.sessionToken",
                                                 &kms_providers->aws_mut.session_token,
                                                 status)) {
                return false;
            }

            if (!_mongocrypt_check_allowed_fields(&as_bson,
                                                  "aws",
                                                  status,
                                                  "accessKeyId",
                                                  "secretAccessKey",
                                                  "sessionToken")) {
                return false;
            }
            kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_AWS;
        } else if (0 == strcmp(field_name, "kmip") && bson_empty(&field_bson)) {
            kms_providers->need_credentials |= MONGOCRYPT_KMS_PROVIDER_KMIP;
        } else if (0 == strcmp(field_name, "kmip")) {
            _mongocrypt_endpoint_parse_opts_t opts = {0};

            opts.allow_empty_subdomain = true;
            if (!_mongocrypt_parse_required_endpoint(&as_bson,
                                                     "kmip.endpoint",
                                                     &kms_providers->kmip_mut.endpoint,
                                                     &opts,
                                                     status)) {
                return false;
            }

            if (!_mongocrypt_check_allowed_fields(&as_bson, "kmip", status, "endpoint")) {
                return false;
            }
            kms_providers->configured_providers |= MONGOCRYPT_KMS_PROVIDER_KMIP;
        } else {
            CLIENT_ERR("unsupported KMS provider: %s", field_name);
            return false;
        }
    }

    if (log && log->trace_enabled) {
        char *as_str = bson_as_json(&as_bson, NULL);
        _mongocrypt_log(log, MONGOCRYPT_LOG_LEVEL_TRACE, "%s (%s=\"%s\")", BSON_FUNC, "kms_providers", as_str);
        bson_free(as_str);
    }

    return true;
}
