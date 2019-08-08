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

#include <bson/bson.h>
#include "mongocrypt-traverse-util-private.h"
#include "test-mongocrypt.h"

static void
_append_marking (bson_t *bson, const char *key, int key_len)
{
   uint8_t *data;
   bson_t *marking_bson;

   marking_bson = BCON_NEW ("a",
                            BCON_INT32 (MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM),
                            "v",
                            BCON_UTF8 ("abc"),
                            "ka",
                            BCON_UTF8 ("Nancy"));

   data = bson_malloc0 (marking_bson->len + 1);
   data[0] = 0;
   memcpy (data + 1, marking_bson, marking_bson->len);

   BSON_ASSERT (bson_append_binary (
      bson, key, key_len, 0x06, data, marking_bson->len + 1));
   bson_free (data);
   bson_destroy (marking_bson);
}

static void
_append_ciphertext_with_subtype (bson_t *bson,
                                 const char *key,
                                 int key_len,
                                 int subtype,
                                 int first_byte,
                                 _mongocrypt_tester_t *tester)
{
   uint8_t *data;
   char *utf8;
   int data_len;
   int key_id_len = 16;

   utf8 = "Mary";
   data_len = (int) (1 + key_id_len + 1 + strlen (utf8));

   data = bson_malloc0 (data_len);
   data[0] = first_byte;
   memcpy (data + 1, (TEST_BIN (16))->data, key_id_len);
   data[1 + key_id_len] = 0x02; /* BSON type UTF8 */
   memcpy (data + key_id_len + 2, utf8, strlen (utf8));

   BSON_ASSERT (
      bson_append_binary (bson, key, key_len, subtype, data, data_len));

   bson_free (data);
}

typedef enum { NEST_IN_NONE, NEST_IN_DOCUMENT, NEST_IN_ARRAY } _nesting_t;

typedef struct {
   _mongocrypt_tester_t *tester;
   _nesting_t parent;
} _util_tester_t;

static void
_reset_nesting (bson_t *parent, bson_t *bson, _nesting_t nesting, char *name)
{
   if (nesting == NEST_IN_DOCUMENT) {
      BSON_ASSERT (bson_append_document_end (parent, bson));
      bson_append_document_begin (parent, name, -1, bson);
   } else if (nesting == NEST_IN_ARRAY) {
      BSON_ASSERT (bson_append_array_end (parent, bson));
      bson_append_array_begin (parent, name, -1, bson);
   }
}

static int
_field_count (bson_iter_t *iter)
{
   int i = 0;

   while (bson_iter_next (iter)) {
      i++;
   }

   return i;
}

static void
_assert_correct_fields (bson_t *bson,
                        int num_markings,
                        int num_deterministic,
                        int num_random,
                        int num_binary,
                        int num_other,
                        _util_tester_t *tester)
{
   char name[36];
   bson_iter_t iter;
   bson_iter_t child;
   int i;

   BSON_ASSERT (num_markings < 10);
   BSON_ASSERT (num_deterministic < 10);
   BSON_ASSERT (num_random < 10);
   BSON_ASSERT (num_binary < 10);
   BSON_ASSERT (num_other < 10);

   memset (name, 0, 36);

   if (tester->parent != NEST_IN_NONE) {
      for (i = 0; i < num_other; i++) {
         snprintf (name, 13, "other.field%d", i);
         bson_iter_init (&iter, bson);
         BSON_ASSERT (bson_iter_find_descendant (&iter, name, &child));
      }

      for (i = 0; i < num_markings; i++) {
         snprintf (name, 18, "markings.marking%d", i);
         bson_iter_init (&iter, bson);
         BSON_ASSERT (bson_iter_find_descendant (&iter, name, &child));
      }
      for (i = 0; i < num_random; i++) {
         snprintf (name, 15, "random.random%d", i);
         bson_iter_init (&iter, bson);
         BSON_ASSERT (bson_iter_find_descendant (&iter, name, &child));
      }
      for (i = 0; i < num_deterministic; i++) {
         snprintf (name, 29, "deterministic.deterministic%d", i);
         bson_iter_init (&iter, bson);
         BSON_ASSERT (bson_iter_find_descendant (&iter, name, &child));
      }
      for (i = 0; i < num_binary; i++) {
         snprintf (name, 15, "binary.binary%d", i);
         bson_iter_init (&iter, bson);
         BSON_ASSERT (bson_iter_find_descendant (&iter, name, &child));
      }

   } else {
      /* When there's no nesting, just count fields. */
      bson_iter_init (&iter, bson);
      BSON_ASSERT (_field_count (&iter) ==
                   (num_other + num_binary + num_markings + num_deterministic +
                    num_random));
   }
}

static bson_t *
_assemble_bson (int num_markings,
                int num_deterministic,
                int num_random,
                int num_binary,
                int num_other,
                _util_tester_t *tester)
{
   char name[24];
   bson_t *parent = NULL;
   bson_t bson;
   int i;

   /* Field names only take single-digit add-ons, for now */
   BSON_ASSERT (num_markings < 10);
   BSON_ASSERT (num_deterministic < 10);
   BSON_ASSERT (num_random < 10);
   BSON_ASSERT (num_binary < 10);
   BSON_ASSERT (num_other < 10);

   memset (name, 0, 24);

   /* If we have a nesting type, nest each kind of field inside one */
   if (tester->parent == NEST_IN_DOCUMENT) {
      parent = bson_new ();
      bson_append_document_begin (parent, "other", -1, &bson);
   } else if (tester->parent == NEST_IN_ARRAY) {
      parent = bson_new ();
      bson_append_array_begin (parent, "other", -1, &bson);
   } else {
      bson_init (&bson);
   }

   /* Append some other filler fields */
   for (i = 0; i < num_other; i++) {
      snprintf (name, 7, "field%d", i);
      BSON_ASSERT (bson_append_utf8 (&bson, name, 6, "hi", -1));
   }

   _reset_nesting (parent, &bson, tester->parent, "markings");

   /* Append some number of markings */
   for (i = 0; i < num_markings; i++) {
      snprintf (name, 9, "marking%d", i);
      _append_marking (&bson, name, 8);
   }

   _reset_nesting (parent, &bson, tester->parent, "random");

   /* Append some number of random ciphertexts */
   for (i = 0; i < num_random; i++) {
      snprintf (name, 8, "random%d", i);
      _append_ciphertext_with_subtype (&bson,
                                       name,
                                       7,
                                       6,
                                       MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM,
                                       tester->tester);
   }

   _reset_nesting (parent, &bson, tester->parent, "deterministic");

   /* Append some number of deterministic ciphertexts */
   for (i = 0; i < num_deterministic; i++) {
      snprintf (name, 15, "deterministic%d", i);
      _append_ciphertext_with_subtype (
         &bson,
         name,
         14,
         6,
         MONGOCRYPT_ENCRYPTION_ALGORITHM_DETERMINISTIC,
         tester->tester);
   }

   _reset_nesting (parent, &bson, tester->parent, "binary");

   /* Append some number of other bson subtype 6 fields */
   for (i = 0; i < num_binary; i++) {
      snprintf (name, 8, "binary%d", i);
      _append_ciphertext_with_subtype (&bson,
                                       name,
                                       7,
                                       5,
                                       MONGOCRYPT_ENCRYPTION_ALGORITHM_NONE,
                                       tester->tester);
   }

   if (tester->parent == NEST_IN_DOCUMENT) {
      BSON_ASSERT (bson_append_document_end (parent, &bson));
      return parent;
   } else if (tester->parent == NEST_IN_ARRAY) {
      BSON_ASSERT (bson_append_array_end (parent, &bson));
      return parent;
   }

   parent = bson_copy (&bson);
   bson_destroy (&bson);
   return parent;
}

static bool
test_traverse_cb (void *ctx,
                  _mongocrypt_buffer_t *in,
                  mongocrypt_status_t *status)
{
   int *matched = (int *) ctx;

   *matched += 1;

   return true;
}

static void
test_traverse (int num_markings,
               int num_deterministic,
               int num_random,
               int num_binary,
               int num_other,
               traversal_match_t match,
               _util_tester_t *tester,
               int num_matches)
{
   mongocrypt_status_t status;
   bson_iter_t iter;
   bson_t *bson;
   int matched = 0;

   /* First, assemble the requested bson document */
   bson = _assemble_bson (num_markings,
                          num_deterministic,
                          num_random,
                          num_binary,
                          num_other,
                          tester);

   /* Traverse */
   BSON_ASSERT (bson_iter_init (&iter, bson));
   BSON_ASSERT (_mongocrypt_traverse_binary_in_bson (
      test_traverse_cb, &matched, match, &iter, &status));

   /* Count matches */
   BSON_ASSERT (matched == num_matches);

   bson_destroy (bson);
}

static void
test_mongocrypt_traverse_util_nesting (_util_tester_t *tester)
{
   /* Empty document */
   test_traverse (0, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (0, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with only non-binary fields */
   test_traverse (0, 0, 0, 0, 2, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (0, 0, 0, 0, 2, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with only binary fields that aren't subtype 0x06 */
   test_traverse (0, 0, 0, 2, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (0, 0, 0, 2, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with a single marking */
   test_traverse (1, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (1, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 1);

   /* Document with multiple markings */
   test_traverse (3, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (3, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 3);

   /* Document with multiple markings and other fields */
   test_traverse (2, 0, 0, 1, 1, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_traverse (2, 0, 0, 1, 1, TRAVERSE_MATCH_MARKING, tester, 2);

   /* Document with a single random ciphertext */
   test_traverse (0, 0, 1, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 1);
   test_traverse (0, 0, 1, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with a single deterministic ciphertext */
   test_traverse (0, 1, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 1);
   test_traverse (0, 1, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with multiple ciphertexts */
   test_traverse (0, 1, 1, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 2);
   test_traverse (0, 1, 1, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with multiple ciphertexts and other fields */
   test_traverse (0, 1, 2, 0, 2, TRAVERSE_MATCH_CIPHERTEXT, tester, 3);
   test_traverse (0, 1, 2, 0, 2, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Documents with all types of fields */
   test_traverse (1, 1, 1, 1, 1, TRAVERSE_MATCH_CIPHERTEXT, tester, 2);
   test_traverse (1, 1, 1, 1, 1, TRAVERSE_MATCH_MARKING, tester, 1);
}

static bool
post_transform_traverse_check (void *ctx,
                               _mongocrypt_buffer_t *in,
                               mongocrypt_status_t *status)
{
   int *matches = (int *) ctx;
   uint8_t *message;

   message = in->data;
   message += 1;
   if (memcmp ("secretmessage", message, 13) == 0) {
      *matches += 1;
   }

   return true;
}

static bool
test_transform_cb (void *ctx,
                   _mongocrypt_buffer_t *in,
                   bson_value_t *out,
                   mongocrypt_status_t *status)
{
   int *matches = (int *) ctx;

   *matches += 1;

   /* When we transform, keep first byte so we get the
      same number of matches in the followup traverse */
   out->value_type = BSON_TYPE_BINARY;
   out->value.v_binary.subtype = 6;
   out->value.v_binary.data = bson_malloc0 (14);
   out->value.v_binary.data[0] = in->data[0];
   memcpy (out->value.v_binary.data + 1, "secretmessage", 13);
   out->value.v_binary.data_len = 14;

   return true;
}

static void
test_transform (int num_markings,
                int num_deterministic,
                int num_random,
                int num_binary,
                int num_other,
                traversal_match_t match,
                _util_tester_t *tester,
                int num_matches)
{
   mongocrypt_status_t status;
   bson_iter_t iter;
   bson_t *bson;
   bson_t out = BSON_INITIALIZER;
   int matches = 0;

   /* First, assemble the requested bson document */
   bson = _assemble_bson (num_markings,
                          num_deterministic,
                          num_random,
                          num_binary,
                          num_other,
                          tester);

   /* Perform a transformation, count matches */
   BSON_ASSERT (bson_iter_init (&iter, bson));
   BSON_ASSERT (_mongocrypt_transform_binary_in_bson (
      test_transform_cb, &matches, match, &iter, &out, &status));

   /* Make sure we had the correct number of matches */
   BSON_ASSERT (matches == num_matches);

   /* Now, traverse through the document again and
      count the actual transformations */
   matches = 0;
   BSON_ASSERT (bson_iter_init (&iter, &out));
   BSON_ASSERT (_mongocrypt_traverse_binary_in_bson (
      post_transform_traverse_check, &matches, match, &iter, &status));

   /* Also, make sure we have the correct number of
      non-matching fields */
   _assert_correct_fields (&out,
                           num_markings,
                           num_deterministic,
                           num_random,
                           num_binary,
                           num_other,
                           tester);


   BSON_ASSERT (matches == num_matches);

   bson_destroy (bson);
   bson_destroy (&out);
}

static void
test_mongocrypt_transform_util_nesting (_util_tester_t *tester)
{
   /* Empty document */
   test_transform (0, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (0, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with only non-binary fields */
   test_transform (0, 0, 0, 0, 2, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (0, 0, 0, 0, 2, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with only binary fields that aren't subtype 0x06 */
   test_transform (0, 0, 0, 2, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (0, 0, 0, 2, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with a single marking */
   test_transform (1, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (1, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 1);

   /* Document with multiple markings */
   test_transform (3, 0, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (3, 0, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 3);

   /* Document with multiple markings and other fields */
   test_transform (2, 0, 0, 1, 1, TRAVERSE_MATCH_CIPHERTEXT, tester, 0);
   test_transform (2, 0, 0, 1, 1, TRAVERSE_MATCH_MARKING, tester, 2);

   /* Document with a single random ciphertext */
   test_transform (0, 0, 1, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 1);
   test_transform (0, 0, 1, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with a single deterministic ciphertext */
   test_transform (0, 1, 0, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 1);
   test_transform (0, 1, 0, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with multiple ciphertexts */
   test_transform (0, 1, 1, 0, 0, TRAVERSE_MATCH_CIPHERTEXT, tester, 2);
   test_transform (0, 1, 1, 0, 0, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Document with multiple ciphertexts and other fields */
   test_transform (0, 1, 2, 0, 2, TRAVERSE_MATCH_CIPHERTEXT, tester, 3);
   test_transform (0, 1, 2, 0, 2, TRAVERSE_MATCH_MARKING, tester, 0);

   /* Documents with all types of fields */
   test_transform (1, 1, 1, 1, 1, TRAVERSE_MATCH_CIPHERTEXT, tester, 2);
   test_transform (1, 1, 1, 1, 1, TRAVERSE_MATCH_MARKING, tester, 1);
}

static void
test_mongocrypt_transform_util (_mongocrypt_tester_t *tester)
{
   _util_tester_t ctx = {0};

   ctx.tester = tester;

   ctx.parent = NEST_IN_NONE;
   test_mongocrypt_transform_util_nesting (&ctx);

   ctx.parent = NEST_IN_DOCUMENT;
   test_mongocrypt_transform_util_nesting (&ctx);

   ctx.parent = NEST_IN_ARRAY;
   test_mongocrypt_transform_util_nesting (&ctx);
}

static void
test_mongocrypt_traverse_util (_mongocrypt_tester_t *tester)
{
   _util_tester_t ctx;

   ctx.tester = tester;

   ctx.parent = NEST_IN_NONE;
   test_mongocrypt_traverse_util_nesting (&ctx);

   ctx.parent = NEST_IN_DOCUMENT;
   test_mongocrypt_traverse_util_nesting (&ctx);

   ctx.parent = NEST_IN_ARRAY;
   test_mongocrypt_traverse_util_nesting (&ctx);
}

void
_mongocrypt_tester_install_traverse_util (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_mongocrypt_traverse_util);
   INSTALL_TEST (test_mongocrypt_transform_util);
}
