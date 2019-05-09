/*
 * Copyright 2019-present MongoDB, Inc.
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

#include <mongocrypt-marking-private.h>
#include <mongocrypt-crypto-private.h>

#include "test-mongocrypt.h"


static void
_test_explicit_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_binary_t *string_msg;
   mongocrypt_binary_t *no_v_msg;
   mongocrypt_binary_t *msg;
   mongocrypt_binary_t *key_id;
   mongocrypt_binary_t *iv;
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   bson_t *bson_msg;
   bson_t *bson_msg_no_v;

   char *random = "AEAD_AES_256_CBC_HMAC_SHA_512-Randomized";
   char *deterministic = "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic";

   bson_msg = BCON_NEW ("v", "hello");
   msg = mongocrypt_binary_new_from_data ((uint8_t *) bson_get_data (bson_msg),
                                          bson_msg->len);

   bson_msg_no_v = BCON_NEW ("a", "hello");
   no_v_msg = mongocrypt_binary_new_from_data (
      (uint8_t *) bson_get_data (bson_msg_no_v), bson_msg_no_v->len);

   string_msg =
      mongocrypt_binary_new_from_data (MONGOCRYPT_DATA_AND_LEN ("hello"));
   key_id = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("2395340598345034"));
   iv = mongocrypt_binary_new_from_data (
      MONGOCRYPT_DATA_AND_LEN ("77777777777777777"));

   crypt = _mongocrypt_tester_mongocrypt ();

   /* Initting with no options will fail (need key_id). */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "key_id required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with only key_id will not succeed, we also
      need an algorithm. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "algorithm is required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test null msg input. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, NULL),
                 ctx,
                 "msg required for explicit encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test with string msg input (no bson) */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, string_msg),
                 ctx,
                 "msg must be bson");
   mongocrypt_ctx_destroy (ctx);

   /* Test with input bson that has no "v" field */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, no_v_msg),
                 ctx,
                 "invalid msg, must contain 'v'");
   mongocrypt_ctx_destroy (ctx);

   /* Initting with RANDOM without an iv passes */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (ctx->opts.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
   BSON_ASSERT (_mongocrypt_buffer_empty (&ctx->opts.iv));
   mongocrypt_ctx_destroy (ctx);

   /* Initting with RANDOM with an iv fails */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (mongocrypt_ctx_setopt_key_id (ctx, key_id), ctx);
   ASSERT_OK (mongocrypt_ctx_setopt_algorithm (ctx, random, -1), ctx);
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "iv must not be set for random encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test that bad algorithm input fails */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (
      mongocrypt_ctx_setopt_algorithm (ctx, "nonexistent algorithm", -1),
      ctx,
      "unsupported algorithm");
   mongocrypt_ctx_destroy (ctx);

   /* Test that specifying DETERMINISTIC without an iv fails */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_id (ctx, key_id));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   ASSERT_FAILS (mongocrypt_ctx_explicit_encrypt_init (ctx, msg),
                 ctx,
                 "iv is required for deterministic encryption");
   mongocrypt_ctx_destroy (ctx);

   /* Test that specifying DETERMINISTIC with an iv passes */
   ctx = mongocrypt_ctx_new (crypt);
   BSON_ASSERT (mongocrypt_ctx_setopt_key_id (ctx, key_id));
   BSON_ASSERT (mongocrypt_ctx_setopt_algorithm (ctx, deterministic, -1));
   BSON_ASSERT (mongocrypt_ctx_setopt_initialization_vector (ctx, iv));
   ASSERT_OK (mongocrypt_ctx_explicit_encrypt_init (ctx, msg), ctx);
   BSON_ASSERT (!_mongocrypt_buffer_empty (&ctx->opts.iv));
   BSON_ASSERT (memcmp (iv->data, ctx->opts.iv.data, iv->len) == 0);

   /* After initing, we should be at NEED_KEYS */
   BSON_ASSERT (ctx->type == _MONGOCRYPT_TYPE_ENCRYPT);
   BSON_ASSERT (ctx->state == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);

   mongocrypt_binary_destroy (msg);
   mongocrypt_binary_destroy (string_msg);
   mongocrypt_binary_destroy (no_v_msg);
   mongocrypt_binary_destroy (key_id);
   mongocrypt_binary_destroy (iv);
   bson_destroy (bson_msg);
   bson_destroy (bson_msg_no_v);
}

/* Test individual ctx states. */
static void
_test_encrypt_init (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;

   crypt = _mongocrypt_tester_mongocrypt ();


   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   mongocrypt_ctx_destroy (ctx);

   /* Invalid namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (
                    ctx, MONGOCRYPT_STR_AND_LEN ("invalidnamespace")),
                 ctx,
                 "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* NULL namespace. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_FAILS (mongocrypt_ctx_encrypt_init (ctx, NULL, 0), ctx, "invalid ns");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);

   /* Wrong state. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   ASSERT_FAILS (
      mongocrypt_ctx_encrypt_init (ctx, "test.test", 9), ctx, "wrong state");
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with no schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo = _mongocrypt_tester_file (
      tester, "./test/data/collection-info-no-schema.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Coll info with NULL schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx, "wrong state");
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_markings (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No placeholders. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-markings.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* No encryption in schema. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-no-encryption-needed.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NOTHING_TO_DO);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Invalid marking. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings = _mongocrypt_tester_file (
      tester, "./test/data/mongocryptd-reply-invalid.json");
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "no 'v'");
   mongocrypt_binary_destroy (markings);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* NULL markings. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, NULL), ctx, "invalid NULL");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Wrong state. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_KMS);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, markings), ctx, "wrong state");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_encrypt_need_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *key;

   /* Success. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   key = _mongocrypt_tester_file (tester, "./test/example/key-document.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, key), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (key);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_NEED_KMS);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */

   /* Did not provide all keys. */
   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_done (ctx), ctx, "did not provide all keys");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt); /* recreate crypt because of caching. */
}


static void
_test_encrypt_ready (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *encrypted_cmd;
   _mongocrypt_buffer_t ciphertext_buf;
   _mongocrypt_ciphertext_t ciphertext;
   bson_t as_bson;
   bson_iter_t iter;
   bool ret;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   crypt = _mongocrypt_tester_mongocrypt ();
   encrypted_cmd = mongocrypt_binary_new ();

   ASSERT_OR_PRINT (crypt, status);

   /* Success. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_READY);
   ASSERT_OK (mongocrypt_ctx_finalize (ctx, encrypted_cmd), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_DONE);

   /* check that the encrypted command has a valid ciphertext. */
   _mongocrypt_binary_to_bson (encrypted_cmd, &as_bson);
   CRYPT_TRACEF (&crypt->log, "encrypted doc: %s", tmp_json (&as_bson));
   bson_iter_init (&iter, &as_bson);
   bson_iter_find_descendant (&iter, "filter.ssn", &iter);
   BSON_ASSERT (BSON_ITER_HOLDS_BINARY (&iter));
   _mongocrypt_buffer_from_binary_iter (&ciphertext_buf, &iter);
   ret = _mongocrypt_ciphertext_parse_unowned (
      &ciphertext_buf, &ciphertext, status);
   ASSERT_OR_PRINT (ret, status);
   mongocrypt_binary_destroy (encrypted_cmd);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_status_destroy (status);
   mongocrypt_destroy (crypt);
}


static void
_test_key_missing_region (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *key_doc;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   key_doc = _mongocrypt_tester_file (
      tester, "./test/data/key-document-no-region.json");
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_KEYS);
   ASSERT_FAILS (
      mongocrypt_ctx_mongo_feed (ctx, key_doc), ctx, "no key region");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_binary_destroy (key_doc);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


/* Test that attempting to auto encrypt on a view is disallowed. */
static void
_test_view (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/data/collection-info-view.json");
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   ASSERT_FAILS (mongocrypt_ctx_mongo_feed (ctx, collinfo),
                 ctx,
                 "cannot auto encrypt a view");
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_ERROR);

   mongocrypt_binary_destroy (collinfo);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}


static void
_test_local_schema (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *schema, *bin;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   schema = _mongocrypt_tester_file (tester, "./test/data/schema.json");
   ASSERT_OK (mongocrypt_ctx_setopt_schema (ctx, schema), ctx);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   /* Since we supplied a schema, we should jump right to NEED_MONGO_MARKINGS */
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   bin = mongocrypt_binary_new ();
   mongocrypt_ctx_mongo_op (ctx, bin);
   /* We should get back the schema we gave. */
   BSON_ASSERT (0 == memcmp (bin->data, schema->data, schema->len));
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);

   mongocrypt_binary_destroy (bin);
   mongocrypt_binary_destroy (schema);
   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}

static void
_get_bytes (const void *in, char *out, int len)
{
   const unsigned char *src = in;
   char *dest = out;

   for (int i = 0; i < len; i++, dest += 3) {
      sprintf (dest, "%02X ", src[i]);
   }
   dest[-1] = '\0';
}

#define CLEAN                                  \
   do {                                        \
      bson_destroy (&wrapper);                 \
      _mongocrypt_marking_cleanup (&marking);  \
      _mongocrypt_buffer_cleanup (&plaintext); \
   } while (0)

#define ROUNDTRIP(key, wrapped, unwrapped, type)                      \
   do {                                                               \
      bson_iter_init_find (&iter, bson, key);                         \
      memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));          \
                                                                      \
      bson_append_iter (&wrapper, "", 0, &marking.v_iter);            \
      _get_bytes (bson_get_data (&wrapper), actual, wrapper.len);     \
      BSON_ASSERT (0 == strcmp (wrapped, actual));                    \
                                                                      \
      _mongocrypt_buffer_from_iter (&plaintext, &(&marking)->v_iter); \
      _get_bytes (plaintext.data, actual, plaintext.len);             \
      BSON_ASSERT (0 == strcmp (unwrapped, actual));                  \
      _mongocrypt_buffer_to_bson_value (&plaintext, type, &out);      \
   } while (0)

static void
_test_mongocrypt_buffer_from_iter (_mongocrypt_tester_t *tester)
{
   /*
    * This section explains the purpose of each byte in a BSON document. This is
    * used to extract only the value of a BSON document for later storage. Below
    * is an example of the leftmost derivation of one of the BSON documents
    * used for this test.
    *
    * NOTES:
    * - When used as a unary operator, * means that the repetition can occur 0
    *   or more times.
    *
    * - int32     4 bytes (32-bit signed integer, two's complement)
    * - (byte*)   Zero or more modified UTF-8 encoded characters followed by
    *             '\x00'. The (byte*) MUST NOT contain '\x00', hence it is
    *             not full UTF-8.
    *
    * RULES:
    * 1. document ::=  int32 e_list "\x00"     int32 is the total number of
    *                                          bytes comprising the doc.
    * 2. e_list   ::=  element e_list
    *              |   ""
    * 3. element  ::=  "\x02" e_name string    UTF-8 string
    *              |   "\x10" e_name int32 	  32-bit integer
    * 4. e_name   ::=  cstring                 Key name
    * 5. string   ::=  int32 (byte*) "\x00"
    * 6. cstring  ::=  (byte*) "\x00"
    *
    * BELOW IS A LEFTMOST DERIVATION:
    * Let doc = { "" : "?????" }
    *
    * -  doc  ::= int32 e_list "\x00"
    *
    * -- rule2 -> int32 element e_list "\x00"
    * -- rule3 -> int32 "\x02" e_name string e_list "\x00"
    * -- rule4 -> int32 "\x02" cstring string e_list "\x00"
    * -- rule6 -> int32 "\x02" (byte*) "\x00" string e_list "\x00"
    * -- key   -> int32 "\x02" "" "\x00" string e_list "\x00"
    ** The key is an empty string, i.e. 0 bytes **
    * -- rule5 -> int32 "\x02" "" "\x00" int32 (byte*) "\x00" e_list "\x00"
    * -- value -> int32 "\x02" "" "\x00" int32=6 "?????" "\x00" e_list "\x00"
    ** Above, the value is set. The int32 before the value is the size of the **
    ** value in bytes, plus one for the the null char. **
    * -- rule2 -> int32=17 "\x02" "" "\x00" int32=6 "?????" "\x00" "" "\x00"
    *
    * Finally, we have the byte sequence:
    *    "11000000 02 "" 00 06000000 "?????" 00 00"
    *
    * Note, the hexcode for '?' is '3F'. Grouping the sequence by byte for
    * readability, more precisely we have:
    *    "11 00 00 00 02 00 06 00 00 00 3F 3F 3F 3F 3F 00 00"
    *
    * with the value, including its length and null terminator being:
    *    "06 00 00 00 3F 3F 3F 3F 3F 00".
    * This is what we will store.
    */

   _mongocrypt_buffer_t plaintext = {0};
   _mongocrypt_marking_t marking = {0};
   bson_iter_t iter;
   bson_t *bson;
   bson_t wrapper = BSON_INITIALIZER;
   char actual[100] = {0};
   bson_value_t out;
   char *expected_string = "?????"; /* 3F 3F 3F 3F 3F */
   int expected_int = 5555555;      /* 54 C5 63 */

   bson = bson_new ();
   BSON_APPEND_UTF8 (bson, "str_key", expected_string);
   BSON_APPEND_INT32 (bson, "int_key", expected_int);

   //   bson_iter_init_find (&iter, bson, "str_key");
   //   memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));
   //
   //   bson_append_iter (&wrapper, "", 0, &marking.v_iter);
   //   _get_bytes (bson_get_data (&wrapper), actual, wrapper.len);
   //   BSON_ASSERT (
   //      0 ==
   //      strcmp ("11 00 00 00 02 00 06 00 00 00 3F 3F 3F 3F 3F 00 00",
   //      actual));
   //
   //   _mongocrypt_buffer_from_iter (&plaintext, &(&marking)->v_iter);
   //   _get_bytes (plaintext.data, actual, plaintext.len);
   //   BSON_ASSERT (0 == strcmp ("06 00 00 00 3F 3F 3F 3F 3F 00", actual));
   //
   //   _mongocrypt_buffer_to_bson_value (&plaintext, 0x02, &out);
   ROUNDTRIP ("str_key",
              "11 00 00 00 02 00 06 00 00 00 3F 3F 3F 3F 3F 00 00",
              "06 00 00 00 3F 3F 3F 3F 3F 00",
              0x02);
   BSON_ASSERT (0 == strcmp (expected_string, out.value.v_utf8.str));
   BSON_ASSERT (5 == out.value.v_utf8.len);

   bson_value_destroy (&out);
   CLEAN;

   bson_init (&wrapper);
   _mongocrypt_buffer_init (&plaintext);
   _mongocrypt_marking_init (&marking);

   bson_iter_init_find (&iter, bson, "int_key");
   memcpy (&marking.v_iter, &iter, sizeof (bson_iter_t));

   bson_append_iter (&wrapper, "", 0, &marking.v_iter);
   bson_destroy (&wrapper);
   _get_bytes (bson_get_data (&wrapper), actual, wrapper.len);
   BSON_ASSERT (0 == strcmp ("0B 00 00 00 10 00 63 C5 54 00 00", actual));


   _mongocrypt_buffer_from_iter (&plaintext, &(&marking)->v_iter);
   _get_bytes (plaintext.data, actual, plaintext.len);
   BSON_ASSERT (
      0 == strcmp ("63 C5 54 00", actual)); /* length is not needed for int32 */

   _mongocrypt_buffer_to_bson_value (&plaintext, 0x10, &out);
   BSON_ASSERT (expected_int == out.value.v_int32);

   bson_destroy (bson);
   CLEAN;
}
static void
_test_encrypt_caches_collinfo (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *collinfo;
   bson_t *cached_collinfo;
   mongocrypt_status_t *status;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   status = mongocrypt_status_new ();
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
   collinfo =
      _mongocrypt_tester_file (tester, "./test/example/collection-info.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, collinfo), ctx);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   mongocrypt_binary_destroy (collinfo);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);
   /* The next crypt has the schema cached. */
   ASSERT_OR_PRINT (_mongocrypt_cache_get (&crypt->cache_collinfo,
                                           "test.test",
                                           (void **) &cached_collinfo,
                                           status),
                    status);
   bson_destroy (cached_collinfo);

   /* The next context enters the NEED_MONGO_MARKINGS state immediately. */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   mongocrypt_ctx_destroy (ctx);

   mongocrypt_destroy (crypt);
   mongocrypt_status_destroy (status);
}

static void
_test_encrypt_caches_keys (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   mongocrypt_binary_t *markings;

   crypt = _mongocrypt_tester_mongocrypt ();
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
   mongocrypt_ctx_destroy (ctx);
   /* The next context skips needing keys after being supplied mark documents.
    */
   ctx = mongocrypt_ctx_new (crypt);
   ASSERT_OK (
      mongocrypt_ctx_encrypt_init (ctx, MONGOCRYPT_STR_AND_LEN ("test.test")),
      ctx);
   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   markings =
      _mongocrypt_tester_file (tester, "./test/example/mongocryptd-reply.json");
   ASSERT_OK (mongocrypt_ctx_mongo_feed (ctx, markings), ctx);
   mongocrypt_binary_destroy (markings);
   ASSERT_OK (mongocrypt_ctx_mongo_done (ctx), ctx);
   BSON_ASSERT (mongocrypt_ctx_state (ctx) == MONGOCRYPT_CTX_READY);

   mongocrypt_ctx_destroy (ctx);
   mongocrypt_destroy (crypt);
}
void
_mongocrypt_tester_install_ctx_encrypt (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_explicit_encrypt_init);
   INSTALL_TEST (_test_encrypt_init);
   INSTALL_TEST (_test_encrypt_need_collinfo);
   INSTALL_TEST (_test_encrypt_need_markings);
   INSTALL_TEST (_test_encrypt_need_keys);
   INSTALL_TEST (_test_encrypt_ready);
   INSTALL_TEST (_test_key_missing_region);
   INSTALL_TEST (_test_view);
   INSTALL_TEST (_test_local_schema);
   INSTALL_TEST (_test_encrypt_caches_collinfo);
   INSTALL_TEST (_test_encrypt_caches_keys);
   INSTALL_TEST (_test_mongocrypt_buffer_from_iter);
}
