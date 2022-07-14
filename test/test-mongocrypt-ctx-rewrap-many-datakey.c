/*
 * Copyright 2022-present MongoDB, Inc.
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

#include "test-mongocrypt.h"


#define TEST_REWRAP_MASTER_KEY_ID_OLD        \
   "arn:aws:kms:us-east-1:579766882180:key/" \
   "89fcc2c4-08b0-4bd9-9f25-e30687b580d0"

#define TEST_REWRAP_MASTER_KEY_ID_NEW        \
   "arn:aws:kms:us-east-1:579766882180:key/" \
   "061334ae-07a8-4ceb-a813-8135540e837d"


typedef struct {
   _mongocrypt_buffer_t id;
   const char *kek_id;
   _mongocrypt_buffer_t key_material;
   int64_t creation_date;
   int64_t update_date;
   _mongocrypt_key_alt_name_t *key_alt_names;
} _test_datakey_fields_t;

static _test_datakey_fields_t *
_test_datakey_fields_new (void)
{
   return bson_malloc0 (sizeof (_test_datakey_fields_t));
}

static void
_test_datakey_fields_destroy (_test_datakey_fields_t *fields)
{
   if (!fields) {
      return;
   }

   _mongocrypt_key_alt_name_destroy_all (fields->key_alt_names);

   bson_free (fields);
}

static _mongocrypt_buffer_t
_find_key_id (mongocrypt_binary_t *key)
{
   bson_t bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t buf;

   BSON_ASSERT_PARAM (key);

   ASSERT (_mongocrypt_binary_to_bson (key, &bson));
   ASSERT (bson_iter_init (&iter, &bson));
   ASSERT (bson_iter_find_descendant (&iter, "_id", &iter));
   ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, &iter));
   ASSERT (buf.subtype == BSON_SUBTYPE_UUID);
   ASSERT (buf.len > 0u);

   return buf;
}

static _mongocrypt_buffer_t
_find_key_id_from_iter (bson_iter_t *iter)
{
   _mongocrypt_buffer_t buf;

   ASSERT (BSON_ITER_HOLDS_BINARY (iter));
   ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, iter));
   ASSERT (buf.subtype == BSON_SUBTYPE_UUID);
   ASSERT (buf.len > 0u);

   return buf;
}

static const char *
_find_masterkey_id (mongocrypt_binary_t *key)
{
   bson_t bson;
   bson_iter_t iter;
   const char *res;

   BSON_ASSERT_PARAM (key);

   ASSERT (_mongocrypt_binary_to_bson (key, &bson));
   ASSERT (bson_iter_init (&iter, &bson));
   ASSERT (bson_iter_find_descendant (&iter, "masterKey.key", &iter));
   ASSERT ((res = bson_iter_utf8 (&iter, NULL)));

   return res;
}

static _mongocrypt_buffer_t
_find_key_material (mongocrypt_binary_t *key)
{
   bson_t bson;
   bson_iter_t iter;
   _mongocrypt_buffer_t buf;

   BSON_ASSERT_PARAM (key);

   ASSERT (_mongocrypt_binary_to_bson (key, &bson));
   ASSERT (bson_iter_init (&iter, &bson));
   ASSERT (bson_iter_find_descendant (&iter, "keyMaterial", &iter));
   ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, &iter));
   ASSERT (buf.subtype == BSON_SUBTYPE_BINARY);
   ASSERT (buf.len > 0u);

   return buf;
}

static _mongocrypt_buffer_t
_key_material_from_iter (bson_iter_t *iter)
{
   _mongocrypt_buffer_t buf;

   ASSERT (BSON_ITER_HOLDS_BINARY (iter));
   ASSERT (_mongocrypt_buffer_from_binary_iter (&buf, iter));
   ASSERT (buf.subtype == BSON_SUBTYPE_BINARY);
   ASSERT (buf.len > 0u);

   return buf;
}

static bool
_buffer_cmp_equal (const _mongocrypt_buffer_t *lhs,
                   const _mongocrypt_buffer_t *rhs)
{
   BSON_ASSERT_PARAM (lhs);
   BSON_ASSERT_PARAM (rhs);

   return lhs->len == rhs->len && memcmp (lhs->data, rhs->data, lhs->len) == 0;
}

static int64_t
_find_date_field (mongocrypt_binary_t *key, const char *dotkey)
{
   bson_t bson;
   bson_iter_t iter;
   int64_t res;

   BSON_ASSERT_PARAM (key);

   ASSERT (_mongocrypt_binary_to_bson (key, &bson));
   ASSERT (bson_iter_init (&iter, &bson));
   ASSERT (bson_iter_find_descendant (&iter, dotkey, &iter));
   ASSERT (BSON_ITER_HOLDS_DATE_TIME (&iter));
   ASSERT ((res = bson_iter_date_time (&iter)) != 0)

   return res;
}

static int64_t
_find_creation_date (mongocrypt_binary_t *key)
{
   return _find_date_field (key, "creationDate");
}

static int64_t
_find_update_date (mongocrypt_binary_t *key)
{
   return _find_date_field (key, "updateDate");
}

static _mongocrypt_key_alt_name_t *
_find_key_alt_names (mongocrypt_binary_t *key)
{
   bson_t bson;
   bson_iter_t iter;
   _mongocrypt_key_alt_name_t *res;

   BSON_ASSERT_PARAM (key);

   ASSERT (_mongocrypt_binary_to_bson (key, &bson));
   ASSERT (bson_iter_init (&iter, &bson));
   ASSERT (bson_iter_find_descendant (&iter, "keyAltNames", &iter));
   ASSERT (_mongocrypt_key_alt_name_from_iter (&iter, &res, NULL));
   ASSERT (res);

   return res;
}

static _test_datakey_fields_t *
_find_datakey_fields (mongocrypt_binary_t *key)
{
   _test_datakey_fields_t *res = _test_datakey_fields_new ();

   BSON_ASSERT_PARAM (key);

   res->id = _find_key_id (key);
   res->kek_id = _find_masterkey_id (key);
   res->creation_date = _find_creation_date (key);
   res->update_date = _find_update_date (key);
   res->key_material = _find_key_material (key);
   res->key_alt_names = _find_key_alt_names (key);

   return res;
}

static void
_assert_aws_kms_request (mongocrypt_kms_ctx_t *kms)
{
   BSON_ASSERT_PARAM (kms);

   ASSERT_STREQUAL (mongocrypt_kms_ctx_get_kms_provider (kms, NULL), "aws");

   {
      mongocrypt_binary_t bin;
      ASSERT (mongocrypt_kms_ctx_message (kms, &bin));
      ASSERT (bin.len > 0);
   }

   {
      const char *endpoint;
      ASSERT (mongocrypt_kms_ctx_endpoint (kms, &endpoint));
      ASSERT (endpoint);
   }

   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) > 0);
}

static void
_assert_aws_kms_endpoint (mongocrypt_kms_ctx_t *kms, const char *expected)
{
   const char *endpoint = NULL;
   ASSERT ((mongocrypt_kms_ctx_endpoint (kms, &endpoint)));
   ASSERT_STREQUAL (expected, endpoint);
}


static void
_test_rewrap_many_datakey_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = NULL;

   /* No context, nothing to init. */
   ASSERT (!mongocrypt_ctx_rewrap_many_datakey_init (NULL, NULL));

   /* Filter argument required. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_rewrap_many_datakey_init (ctx, NULL),
                 ctx,
                 "filter must not be null");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Irrelevant options should trigger initialization error. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_alt_name (
                 ctx, TEST_BSON ("{'keyAltName': 'test'}")),
              ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")),
      ctx,
      "key id and alt name prohibited");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* rewrapManyDataKeyOpts.newProvider and rewrapManyDataKeyOpts.newMasterKey
    * should be provided via mongocrypt_ctx_setopt_key_encryption_key. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (
                 ctx,
                 TEST_BSON ("{'provider': 'aws',"
                            " 'region': 'us-east-1',"
                            " 'key': '" TEST_REWRAP_MASTER_KEY_ID_NEW "'}")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   /* Not providing rewrapManyDataKeyOpts is OK. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_rewrap_many_datakey_need_mongo_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *const filter =
      TEST_BSON ("{'keyAltName': {'$in': ['keyDocumentA', 'keyDocumentB']}}");

   mongocrypt_t *const crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = NULL;

   /* Filter should be the same as what was provided in call to init. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   {
      mongocrypt_binary_t *const op = mongocrypt_binary_new ();
      ASSERT_OK (mongocrypt_ctx_mongo_op (ctx, op), ctx);
      ASSERT_MONGOCRYPT_BINARY_EQUAL_BSON (filter, op);
      mongocrypt_binary_destroy (op);
   }
   mongocrypt_ctx_destroy (ctx);

   /* No key documents is OK, no work to be done. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);

   /* Any number of key documents can be given. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);

   /* Key documents must not have duplicate key ID or alt names. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/key-document-with-alt-name.json")),
      ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_feed (
         ctx,
         TEST_FILE (
            "./test/data/key-document-with-alt-name-duplicate-id.json")),
      ctx,
      "keys returned have duplicate keyAltNames or _id");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_rewrap_many_datakey_need_kms_decrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *const filter =
      TEST_BSON ("{'keyAltName': {'$in': ['keyDocumentA', 'keyDocumentB']}}");

   mongocrypt_t *crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_kms_ctx_t *kms = NULL;

   /* AWS */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-full.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("aws", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Azure */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-azure.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("azure", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* GCP */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-gcp.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("gcp", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* KMIP */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/key-document-kmip.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("kmip", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Local: no KMS required. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-local.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Number of KMS requests should match number of keys that require it. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("aws", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("aws", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Ensure keys that don't require KMS do not request it. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-local.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("aws", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_STREQUAL ("aws", mongocrypt_kms_ctx_get_kms_provider (kms, NULL));
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Ensure number of KMS requests matches number of keys that require it. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   /* Implementation detail: decryption KMS requests are issued in reverse order
    * of provided key documents. */
   _assert_aws_kms_endpoint (kms, "example.com:443");
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "kms.us-east-1.amazonaws.com:443");
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-a.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Ensure all KMS requests have a corresponding KMS response. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) > 0); /* "Oops." */
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_FAILS (mongocrypt_ctx_kms_done (ctx), ctx, "KMS response unfinished");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Clear key cache. */
   mongocrypt_destroy (crypt);
   crypt = _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);

   /* Skip KMS for keys with cached decrypted key material. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   /* Cache decrypted key material for datakey B. */
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   /* Only datakey A should make a KMS request. */
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "kms.us-east-1.amazonaws.com:443");
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_rewrap_many_datakey_need_kms_encrypt (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *const filter =
      TEST_BSON ("{'keyAltName': {'$in': ['keyDocumentA', 'keyDocumentB']}}");

   mongocrypt_t *const crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *ctx = NULL;
   mongocrypt_kms_ctx_t *kms = NULL;

   /* If no new provider is given, encryption should reuse current KMS provider
    * for each key. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   /* These decrypt replies should cache key material used by later blocks. */
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-a.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   /* Implementation detail: encryption KMS requests are issued in same order as
    * provided key documents. */
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "kms.us-east-1.amazonaws.com:443");
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-a.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "example.com:443");
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   /* If new provider is given, encryption should use new KMS provider for all
    * keys. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (
                 ctx,
                 TEST_BSON ("{'provider': 'aws',"
                            " 'region': 'us-east-2',"
                            " 'key': '" TEST_REWRAP_MASTER_KEY_ID_NEW "'}")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   /* Skip decryption, key material should have been cached. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "kms.us-east-2.amazonaws.com:443");
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_endpoint (kms, "kms.us-east-2.amazonaws.com:443");
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   mongocrypt_ctx_destroy (ctx);

   /* If no encryption KMS required, should skip straight to READY state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (
                 ctx, TEST_BSON ("{'provider': 'local'}")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   /* Skip decryption, key material should have been cached. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);
   mongocrypt_ctx_destroy (ctx);

   /* Ensure all KMS requests have a corresponding KMS response. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (
                 ctx,
                 TEST_BSON ("{'provider': 'aws',"
                            " 'region': 'us-east-1',"
                            " 'key': '" TEST_REWRAP_MASTER_KEY_ID_NEW "'}")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   /* Skip decryption, key material should have been cached. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-a.txt")),
              kms);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) > 0); /* "Oops." */
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_FAILS (mongocrypt_ctx_kms_done (ctx), ctx, "KMS response unfinished");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_rewrap_many_datakey_finalize (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *const crypt =
      _mongocrypt_tester_mongocrypt (TESTER_MONGOCRYPT_DEFAULT);
   mongocrypt_ctx_t *const ctx = mongocrypt_ctx_new (crypt);

   mongocrypt_binary_t *const filter =
      TEST_BSON ("{'keyAltName': {'$in': ['keyDocumentA', 'keyDocumentB']}}");

   mongocrypt_binary_t *const key_doc_a =
      TEST_FILE ("./test/data/rmd/key-document-a.json");
   mongocrypt_binary_t *const key_doc_b =
      TEST_FILE ("./test/data/rmd/key-document-b.json");

   /* Save current key fields for comparison with rewrapped keys. */
   _test_datakey_fields_t *const fields_a = _find_datakey_fields (key_doc_a);
   _test_datakey_fields_t *const fields_b = _find_datakey_fields (key_doc_b);

   mongocrypt_kms_ctx_t *kms = NULL;

   ASSERT_OK (ctx, crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_encryption_key (
                 ctx,
                 TEST_BSON ("{'provider': 'aws',"
                            " 'region': 'us-east-1',"
                            " 'key': '" TEST_REWRAP_MASTER_KEY_ID_NEW "'}")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, filter), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_feed (
                 ctx, TEST_FILE ("./test/data/rmd/key-document-b.json")),
              ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_request (kms);
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);

   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_request (kms);
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-a.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_request (kms);
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-a.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);

   ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
   _assert_aws_kms_request (kms);
   ASSERT_OK (mongocrypt_kms_ctx_feed (
                 kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-b.txt")),
              kms);
   ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);
   ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
   ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);

   {
      mongocrypt_binary_t res;
      bson_t bson;
      bson_iter_t iter;
      bson_iter_t a_iter;
      bson_iter_t b_iter;

      ASSERT_OK (mongocrypt_ctx_finalize (ctx, &res), ctx);
      ASSERT (_mongocrypt_binary_to_bson (&res, &bson));

      /* There should be exactly 2 documents. */
      ASSERT (bson_iter_init (&iter, &bson));
      ASSERT (bson_iter_find_descendant (&iter, "v.1", &iter));
      ASSERT (!bson_iter_find_descendant (&iter, "v.2", &iter));

      /* Both keys should have the same ID as prior to rewrap, but may be
       * returned in a different order from order they were fed. */
      {
         _mongocrypt_buffer_t id;

         ASSERT (bson_iter_init (&a_iter, &bson));
         ASSERT (bson_iter_init (&b_iter, &bson));

         /* Find first keyDocument. */
         ASSERT (bson_iter_init (&iter, &bson));
         ASSERT (bson_iter_find_descendant (&iter, "v.0._id", &iter));
         id = _find_key_id_from_iter (&iter);
         if (_buffer_cmp_equal (&fields_a->id, &id)) {
            ASSERT (bson_iter_init (&iter, &bson));
            ASSERT (bson_iter_find_descendant (&iter, "v.0", &iter));
            ASSERT (bson_iter_recurse (&iter, &a_iter));
         } else if (_buffer_cmp_equal (&fields_b->id, &id)) {
            ASSERT (bson_iter_init (&iter, &bson));
            ASSERT (bson_iter_find_descendant (&iter, "v.0", &iter));
            ASSERT (bson_iter_recurse (&iter, &b_iter));
         }

         /* Find second keyDocument. */
         ASSERT (bson_iter_init (&iter, &bson));
         ASSERT (bson_iter_find_descendant (&iter, "v.1._id", &iter));
         id = _find_key_id_from_iter (&iter);
         if (_buffer_cmp_equal (&fields_a->id, &id)) {
            ASSERT (bson_iter_init (&iter, &bson));
            ASSERT (bson_iter_find_descendant (&iter, "v.1", &iter));
            ASSERT (bson_iter_recurse (&iter, &a_iter));
         } else if (_buffer_cmp_equal (&fields_b->id, &id)) {
            ASSERT (bson_iter_init (&iter, &bson));
            ASSERT (bson_iter_find_descendant (&iter, "v.1", &iter));
            ASSERT (bson_iter_recurse (&iter, &b_iter));
         }

         ASSERT (bson_iter_init (&iter, &bson));
         ASSERT (iter.raw != a_iter.raw || iter.off != a_iter.off);
         ASSERT (iter.raw != b_iter.raw || iter.off != b_iter.off);
      }

      /* Both keys should be rewrapped with new masterKey. */
      iter = a_iter;
      ASSERT (bson_iter_find_descendant (&iter, "masterKey.key", &iter));
      ASSERT_STREQUAL (TEST_REWRAP_MASTER_KEY_ID_NEW,
                       bson_iter_utf8 (&iter, NULL));
      iter = b_iter;
      ASSERT (bson_iter_find_descendant (&iter, "masterKey.key", &iter));
      ASSERT_STREQUAL (TEST_REWRAP_MASTER_KEY_ID_NEW,
                       bson_iter_utf8 (&iter, NULL));

      /* Both keys should have new key material. */
      {
         _mongocrypt_buffer_t key_material_a;
         _mongocrypt_buffer_t key_material_b;

         iter = a_iter;
         ASSERT (bson_iter_find_descendant (&iter, "keyMaterial", &iter));
         key_material_a = _key_material_from_iter (&iter);
         ASSERT (!_buffer_cmp_equal (&fields_a->key_material, &key_material_a));

         iter = b_iter;
         ASSERT (bson_iter_find_descendant (&iter, "keyMaterial", &iter));
         key_material_b = _key_material_from_iter (&iter);
         ASSERT (!_buffer_cmp_equal (&fields_b->key_material, &key_material_b));

         /* Key materials should differ. */
         ASSERT (!_buffer_cmp_equal (&key_material_a, &key_material_b));
      }

      bson_destroy (&bson);
   }

   /* No more work to be done for RewrapManyDatakey. */
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_DONE);

   _test_datakey_fields_destroy (fields_b);
   _test_datakey_fields_destroy (fields_a);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_rewrap_many_datakey_kms_credentials (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt = NULL;
   mongocrypt_ctx_t *ctx = NULL;

   /* Ensure rewrapManyDataKey correctly handles need KMS credentials option. */
   {
      crypt = mongocrypt_new ();
      mongocrypt_setopt_use_need_kms_credentials_state (crypt);
      ASSERT_OK (
         mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}")),
         crypt);
      ASSERT_OK (mongocrypt_init (crypt), crypt);
      ctx = mongocrypt_ctx_new (crypt);

      ASSERT_OK (ctx, crypt);

      ASSERT_OK (
         mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")), ctx);

      /* NEED_KMS_CREDENTIALS comes before NEED_MONGO_KEYS. */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_KMS_CREDENTIALS);
      ASSERT_OK (mongocrypt_ctx_provide_kms_providers (
                    ctx,
                    TEST_BSON ("{'aws': {"
                               "   'accessKeyId': 'example',"
                               "   'secretAccessKey': 'example'}}")),
                 ctx);

      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                          MONGOCRYPT_CTX_NEED_MONGO_KEYS);
      ASSERT_OK (mongocrypt_ctx_mongo_feed (
                    ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
                 ctx);
      ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);

      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
      {
         mongocrypt_kms_ctx_t *kms = NULL;

         ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
         _assert_aws_kms_request (kms);
         ASSERT_OK (
            mongocrypt_kms_ctx_feed (
               kms, TEST_FILE ("./test/data/rmd/kms-decrypt-reply-a.txt")),
            kms);
         ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);

         ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
         ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
      }

      /* KMS credentials provided before decryption should be reused here. */
      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_NEED_KMS);
      {
         mongocrypt_kms_ctx_t *kms = NULL;

         ASSERT ((kms = mongocrypt_ctx_next_kms_ctx (ctx)));
         _assert_aws_kms_request (kms);
         ASSERT_OK (
            mongocrypt_kms_ctx_feed (
               kms, TEST_FILE ("./test/data/rmd/kms-encrypt-reply-a.txt")),
            kms);
         ASSERT (mongocrypt_kms_ctx_bytes_needed (kms) == 0);

         ASSERT_OK (!mongocrypt_ctx_next_kms_ctx (ctx), ctx);
         ASSERT_OK (mongocrypt_ctx_kms_done (ctx), ctx);
      }

      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_READY);

      {
         mongocrypt_binary_t res;
         bson_t bson;
         bson_iter_t iter;

         ASSERT_OK (mongocrypt_ctx_finalize (ctx, &res), ctx);
         ASSERT (_mongocrypt_binary_to_bson (&res, &bson));
         ASSERT (bson_iter_init (&iter, &bson));
         ASSERT (bson_iter_find_descendant (&iter, "v.0.masterKey.key", &iter));
         ASSERT_STREQUAL (TEST_REWRAP_MASTER_KEY_ID_OLD,
                          bson_iter_utf8 (&iter, NULL));
      }

      ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_DONE);

      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }

   /* Should not enter NEED_KMS_CREDENTIALS state if use need KMS credentials
    * option is not set. If required credentials are not provided, should fail
    * on decryption. */
   crypt = mongocrypt_new ();
   ASSERT_OK (
      mongocrypt_setopt_kms_providers (crypt, TEST_BSON ("{'aws': {}}")),
      crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (ctx, crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_feed (
         ctx, TEST_FILE ("./test/data/rmd/key-document-a.json")),
      ctx,
      "client not configured with KMS provider necessary to decrypt");
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx), MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);

   /* Should not enter NEED_KMS_CREDENTIALS state if credentials already
    * provided. */
   crypt = mongocrypt_new ();
   mongocrypt_setopt_use_need_kms_credentials_state (crypt);
   ASSERT_OK (mongocrypt_setopt_kms_providers (
                 crypt,
                 TEST_BSON ("{'aws': {"
                            "   'accessKeyId': 'example',"
                            "   'secretAccessKey': 'example'}}")),
              crypt);
   ASSERT_OK (mongocrypt_init (crypt), crypt);
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (ctx, crypt);
   ASSERT_OK (mongocrypt_ctx_rewrap_many_datakey_init (ctx, TEST_BSON ("{}")),
              ctx);
   ASSERT_STATE_EQUAL (mongocrypt_ctx_state (ctx),
                       MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


void
_mongocrypt_tester_install_ctx_rewrap_many_datakey (
   _mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_rewrap_many_datakey_init);
   INSTALL_TEST (_test_rewrap_many_datakey_need_mongo_keys);
   INSTALL_TEST (_test_rewrap_many_datakey_need_kms_decrypt);
   INSTALL_TEST (_test_rewrap_many_datakey_need_kms_encrypt);
   INSTALL_TEST (_test_rewrap_many_datakey_finalize);
   INSTALL_TEST (_test_rewrap_many_datakey_kms_credentials);
}
