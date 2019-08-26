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

#include "mongocrypt.h"
#include "mongocrypt-cache-key-private.h"
#include "mongocrypt-crypto-private.h"
#include "test-conveniences.h"
#include "test-mongocrypt.h"

typedef struct {
   _mongocrypt_buffer_t bson;
   _mongocrypt_key_doc_t *parsed;
   _mongocrypt_buffer_t kms_reply;
   _mongocrypt_buffer_t uuid;
   _mongocrypt_buffer_t marking;
} gen_key_t;

/* The JSON spec tests refer to key ids by a shorthand integer.
 * This function maps that integer to a UUID buffer. */
void
lookup_key_id (uint32_t index, _mongocrypt_buffer_t *buf)
{
   const char *key_ids[] = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"};

   BSON_ASSERT (index < 3);
   _mongocrypt_buffer_copy_from_hex (buf, key_ids[index]);
   buf->subtype = BSON_SUBTYPE_UUID;
   BSON_ASSERT (_mongocrypt_buffer_is_uuid (buf));
}

/* Generate a realistic key document given a @key_description, which contains an
 * _id
 * and possible keyAltNames. key_out and key_doc_out are NULLable outputs. */
void
gen_key (_mongocrypt_tester_t *tester,
         bson_t *key_description,
         bson_t *key_out,
         _mongocrypt_key_doc_t *key_doc_out)
{
   bson_iter_t iter;
   _mongocrypt_buffer_t key_material;
   _mongocrypt_buffer_t key_id;
   bson_t key, masterkey;
   bool local_kms;

   bson_init (&key);
   BSON_APPEND_INT32 (&key, "status", 1);
   BSON_APPEND_DATE_TIME (&key, "updateDate", 1234567890);
   BSON_APPEND_DATE_TIME (&key, "creationDate", 1234567890);
   BSON_APPEND_DOCUMENT_BEGIN (&key, "masterKey", &masterkey);

   local_kms = bson_iter_init_find (&iter, key_description, "local") &&
               bson_iter_as_bool (&iter);

   if (local_kms) {
      BSON_APPEND_UTF8 (&masterkey, "provider", "local");
   } else {
      BSON_APPEND_UTF8 (&masterkey, "provider", "aws");
      BSON_APPEND_UTF8 (&masterkey, "region", "us-east-1");
      BSON_APPEND_UTF8 (
         &masterkey, "key", "arn:aws:kms:us-east-1:579766882180:key/"
                            "89fcc2c4-08b0-4bd9-9f25-e30687b580d0");
   }
   bson_append_document_end (&key, &masterkey);

   BSON_ASSERT (bson_iter_init_find (&iter, key_description, "_id"));
   lookup_key_id (bson_iter_int32 (&iter), &key_id);
   BSON_ASSERT (_mongocrypt_buffer_append (&key_id, &key, "_id", 3));

   if (bson_iter_init_find (&iter, key_description, "keyAltNames")) {
      bson_t key_alt_name_bson;
      int counter = 0;

      BSON_APPEND_ARRAY_BEGIN (&key, "keyAltNames", &key_alt_name_bson);
      for (bson_iter_recurse (&iter, &iter); bson_iter_next (&iter);) {
         char *field;

         field = bson_strdup_printf ("%d", counter);
         BSON_APPEND_UTF8 (
            &key_alt_name_bson, field, bson_iter_utf8 (&iter, NULL));
         counter++;
         bson_free (field);
      }
      bson_append_array_end (&key, &key_alt_name_bson);
   }

   /* Append a keyMaterial that is decryptable by the local KMS masterkey. For
    * AWS it gets ignored since it is dictated by KMS response. */
   _mongocrypt_buffer_copy_from_hex (
      &key_material, "75bdbbaec862a8ae09aa16f6c67c0ae117dd15bf49b8a7947bac6de5a"
                     "610178a3adad4bbe5bec1e30c55378f7d80d0fd5152d46e954aa32528"
                     "69901e03cf7938434fdf7e5bf27f0ec1c85c4c5a92e38b7e3f7ce686d"
                     "7985102c85905da220a27ee01202de25b6831e64974baffb35b7c30c5"
                     "941dfb37b04fff6871d7208e4cde8d1bff0cd69a70dcb613dc27cfe84"
                     "7d7544b6d0d8b4f6c9a5b6fb9c1565c43ef");
   key_material.subtype = BSON_SUBTYPE_BINARY;
   BSON_ASSERT (
      _mongocrypt_buffer_append (&key_material, &key, "keyMaterial", -1));

   if (key_out) {
      bson_copy_to (&key, key_out);
   }

   if (key_doc_out) {
      mongocrypt_status_t *status;

      status = mongocrypt_status_new ();
      ASSERT_OK_STATUS (_mongocrypt_key_parse_owned (&key, key_doc_out, status),
                        status);
      mongocrypt_status_destroy (status);
   }

   bson_destroy (&key);
   _mongocrypt_buffer_cleanup (&key_id);
   _mongocrypt_buffer_cleanup (&key_material);
}

/* Append a realistic subtype 6 marking to a BSON document given a description
 * of the requested key, which may contain either an _id or single keyAltName.
 */
static void
_append_marking (bson_t *appendee, const char *key, const bson_t *request)
{
   /* Create a marking with a fixed value "v": 1 */
   bson_t marking_bson;
   _mongocrypt_buffer_t marking_buf;
   bson_iter_t iter;

   bson_init (&marking_bson);

   if (bson_iter_init_find (&iter, request, "_id")) {
      _mongocrypt_buffer_t key_id;

      lookup_key_id (bson_iter_int32 (&iter), &key_id);
      BSON_ASSERT (_mongocrypt_buffer_append (&key_id, &marking_bson, "ki", 2));
      _mongocrypt_buffer_cleanup (&key_id);
   } else {
      /* If no _id, then keyAltName must be specified. */
      BSON_ASSERT (bson_iter_init_find (&iter, request, "keyAltName"));
      BSON_APPEND_UTF8 (&marking_bson, "ka", bson_iter_utf8 (&iter, NULL));
   }

   /* Append an arbitrary value and algorithm. It won't be checked in the tests.
    */
   BSON_APPEND_INT32 (&marking_bson, "v", 123);
   BSON_APPEND_INT32 (
      &marking_bson, "a", MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC);

   /* Append the prefix 0 byte, per the marking binary format. */
   _mongocrypt_buffer_init (&marking_buf);
   _mongocrypt_buffer_resize (&marking_buf, marking_bson.len + 1);
   marking_buf.data[0] = 0;
   memcpy (
      marking_buf.data + 1, bson_get_data (&marking_bson), marking_bson.len);
   marking_buf.subtype = 6;
   BSON_ASSERT (_mongocrypt_buffer_append (&marking_buf, appendee, key, -1));

   bson_destroy (&marking_bson);
   _mongocrypt_buffer_cleanup (&marking_buf);
}

/* Manually add a cache entry given a description (_id and possible keyAltNames)
 */
static void
_add_to_cache (_mongocrypt_tester_t *tester,
               mongocrypt_ctx_t *ctx,
               bson_t *cache_entry)
{
   bson_iter_t iter;
   _mongocrypt_buffer_t key_id;
   _mongocrypt_key_alt_name_t *key_alt_names = NULL;
   _mongocrypt_cache_key_attr_t *cache_key_attr;
   _mongocrypt_cache_key_value_t *cache_key_value;
   _mongocrypt_key_doc_t *key_doc;
   _mongocrypt_buffer_t key_material_placeholder;
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   BSON_ASSERT (bson_iter_init_find (&iter, cache_entry, "_id"));
   lookup_key_id (bson_iter_int32 (&iter), &key_id);

   if (bson_iter_init_find (&iter, cache_entry, "keyAltNames")) {
      ASSERT_OK_STATUS (
         _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
         status);
   }

   cache_key_attr = _mongocrypt_cache_key_attr_new (&key_id, key_alt_names);
   /* TODO: consider improving these tests by identifying the decrypted and
    * encrypted key material. That is a little tricky, since it will require
    * parsing the KMS request to know which decrypted key material to respond
    * with. */
   _mongocrypt_buffer_init (&key_material_placeholder);
   _mongocrypt_buffer_resize (&key_material_placeholder, MONGOCRYPT_KEY_LEN);
   memset (key_material_placeholder.data, 0, MONGOCRYPT_KEY_LEN);

   key_doc = _mongocrypt_key_new ();
   gen_key (tester, cache_entry, NULL, key_doc);

   cache_key_value =
      _mongocrypt_cache_key_value_new (key_doc, &key_material_placeholder);

   ASSERT_OK_STATUS (
      _mongocrypt_cache_add_copy (
         &ctx->crypt->cache_key, cache_key_attr, cache_key_value, status),
      status);

   _mongocrypt_key_destroy (key_doc);
   _mongocrypt_buffer_cleanup (&key_material_placeholder);
   _mongocrypt_cache_key_attr_destroy (cache_key_attr);
   _mongocrypt_cache_key_value_destroy (cache_key_value);
   _mongocrypt_key_alt_name_destroy_all (key_alt_names);
   _mongocrypt_buffer_cleanup (&key_id);
   mongocrypt_status_destroy (status);
}

/* Match a single cache entry against an expectation document (containing _id
 * and
 * possible list of keyAltNames)
 */
static bool
_match_one_cache_entry (_mongocrypt_cache_pair_t *pair, bson_t *expected_entry)
{
   bson_iter_t iter;
   _mongocrypt_buffer_t key_id;
   _mongocrypt_key_alt_name_t *key_alt_names = NULL;
   _mongocrypt_cache_key_attr_t *attr;
   mongocrypt_status_t *status;
   bool matched = false;

   _mongocrypt_buffer_init (&key_id);
   attr = pair->attr;
   status = mongocrypt_status_new ();

   bson_iter_init_find (&iter, expected_entry, "_id");
   lookup_key_id (bson_iter_int32 (&iter), &key_id);
   if (0 != _mongocrypt_buffer_cmp (&key_id, &attr->id)) {
      goto done;
   }

   if (bson_iter_init_find (&iter, expected_entry, "keyAltNames")) {
      ASSERT_OK_STATUS (
         _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
         status);
   }

   if (!_mongocrypt_key_alt_name_unique_list_equal (key_alt_names,
                                                    attr->alt_names)) {
      printf ("failed to match key alt names\n");
      goto done;
   }

   matched = true;

done:
   _mongocrypt_buffer_cleanup (&key_id);
   _mongocrypt_key_alt_name_destroy_all (key_alt_names);
   mongocrypt_status_destroy (status);
   return matched;
}

/* Find exactly one cache entry matching expected_entry.
 * TODO: Instead of reaching inside the cache to make these checks, I think a
 * better approach would be to have the cache dump as BSON, then check
 * against that BSON with bson matching functions. Right now, if/when we modify
 * the cache structure, we'll need to update this test logic.
 * Alternatively, another solution would be to move part of this logic inside
 * the key cache and call it from the test.  Maybe then the method would look
 * like a "count" method instead of a "return true iff there is a single match"
 * method.  We could also use a "count" method to assert no matches, etc.
 */
static void
_match_cache_entry (_mongocrypt_tester_t *tester,
                    mongocrypt_ctx_t *ctx,
                    bson_t *expected_entry)
{
   _mongocrypt_cache_pair_t *pair;
   bool matched = false;

   pair = ctx->crypt->cache_key.pair;

   while (pair) {
      if (_match_one_cache_entry (pair, expected_entry)) {
         if (matched) {
            printf ("double matched entry: %s\n",
                    bson_as_json (expected_entry, NULL));
            BSON_ASSERT (false);
         }
         matched = true;
      }

      pair = pair->next;
   }

   if (!matched) {
      printf ("could not match entry: %s\n",
              bson_as_json (expected_entry, NULL));
      BSON_ASSERT (false);
   }
}

static void
_run_one_test (_mongocrypt_tester_t *tester,
               mongocrypt_ctx_t *ctx,
               bson_t *test)
{
   bson_iter_t iter;
   bson_t mongocryptd_reply, tmp;
   _mongocrypt_buffer_t buf;
   int32_t counter;
   mongocrypt_status_t *status;

   if (bson_iter_init_find (&iter, test, "description")) {
      printf ("- %s\n", bson_iter_utf8 (&iter, NULL));
   }

   if (bson_iter_init_find (&iter, test, "skipReason")) {
      printf ("  - skipping: %s\n", bson_iter_utf8 (&iter, NULL));
      return;
   }

   status = mongocrypt_status_new ();


   /* Set up cache */
   if (bson_iter_init_find (&iter, test, "cached")) {
      for (bson_iter_recurse (&iter, &iter); bson_iter_next (&iter);) {
         bson_t cache_entry;

         bson_iter_bson (&iter, &cache_entry);
         _add_to_cache (tester, ctx, &cache_entry);
      }
   }

   /* Supply the requests for keys through the mongocryptd reply */
   BSON_ASSERT (bson_iter_init_find (&iter, test, "requests"));
   counter = 0;
   bson_init (&mongocryptd_reply);
   BSON_APPEND_DOCUMENT_BEGIN (&mongocryptd_reply, "result", &tmp);
   for (bson_iter_recurse (&iter, &iter); bson_iter_next (&iter);) {
      bson_t request;
      char *field;

      bson_iter_bson (&iter, &request);
      field = bson_strdup_printf ("%d", counter);
      _append_marking (&tmp, field, &request);
      bson_free (field);
      counter++;
   }
   bson_append_document_end (&mongocryptd_reply, &tmp);

   _mongocrypt_tester_run_ctx_to (
      tester, ctx, MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
   _mongocrypt_buffer_from_bson (&buf, &mongocryptd_reply);
   ASSERT_OK (
      mongocrypt_ctx_mongo_feed (ctx, _mongocrypt_buffer_as_binary (&buf)),
      ctx);
   BSON_ASSERT (mongocrypt_ctx_mongo_done (ctx));


   /* If we're expected to supply keys back, do so. */
   if (bson_iter_init_find (&iter, test, "replies")) {
      BSON_ASSERT (mongocrypt_ctx_state (ctx) ==
                   MONGOCRYPT_CTX_NEED_MONGO_KEYS);

      for (bson_iter_recurse (&iter, &iter); bson_iter_next (&iter);) {
         bson_t key;
         bson_t key_description;

         bson_iter_bson (&iter, &key_description);
         gen_key (tester, &key_description, &key, NULL);
         _mongocrypt_buffer_from_bson (&buf, &key);
         /* If expectations expect failure, fall through. */
         if (!mongocrypt_ctx_mongo_feed (ctx,
                                         _mongocrypt_buffer_as_binary (&buf))) {
            bson_destroy (&key);
            break;
         }
         bson_destroy (&key);
      }

      /* We might have failed at this point. If so, do not continue so we keep
       * original error message. */
      if (mongocrypt_ctx_status (ctx, status)) {
         (void) mongocrypt_ctx_mongo_done (ctx);
      }
   }

   /* Check expectations */
   if (bson_iter_init_find (&iter, test, "expect")) {
      bson_t expectations;

      mongocrypt_ctx_status (ctx, status);
      bson_iter_bson (&iter, &expectations);
      if (bson_iter_init_find (&iter, &expectations, "errmsg")) {
         _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_ERROR);
         ASSERT_FAILS_STATUS (mongocrypt_status_ok (status),
                              status,
                              bson_iter_utf8 (&iter, NULL));
      } else {
         _mongocrypt_tester_run_ctx_to (tester, ctx, MONGOCRYPT_CTX_DONE);
         ASSERT_OK_STATUS (mongocrypt_status_ok (status), status);
      }

      if (bson_iter_init_find (&iter, &expectations, "cached")) {
         uint32_t count = 0;

         for (bson_iter_recurse (&iter, &iter); bson_iter_next (&iter);) {
            bson_t entry_description;

            bson_iter_bson (&iter, &entry_description);
            _match_cache_entry (tester, ctx, &entry_description);

            count++;
         }
         BSON_ASSERT (count ==
                      _mongocrypt_cache_num_entries (&ctx->crypt->cache_key));
      }
   }

   bson_destroy (&mongocryptd_reply);
   mongocrypt_status_destroy (status);
}

/* Run declarative JSON tests, like driver spec tests. */
static void
_test_key_cache (_mongocrypt_tester_t *tester)
{
   mongocrypt_t *crypt;
   mongocrypt_ctx_t *ctx;
   bson_t test_file;
   bson_iter_t iter;


   _load_json_as_bson ("./test/data/cache-tests.json", &test_file);
   for (bson_iter_init (&iter, &test_file); bson_iter_next (&iter);) {
      bson_t test;
      crypt = _mongocrypt_tester_mongocrypt ();
      ctx = mongocrypt_ctx_new (crypt);

      bson_iter_bson (&iter, &test);

      BSON_ASSERT (mongocrypt_ctx_encrypt_init (
         ctx, "test", -1, TEST_BSON ("{'insert': 'coll'}")));
      _run_one_test (tester, ctx, &test);
      bson_destroy (&test);

      mongocrypt_ctx_destroy (ctx);
      mongocrypt_destroy (crypt);
   }
   bson_destroy (&test_file);
}

void
_mongocrypt_tester_install_key_cache (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_key_cache);
}