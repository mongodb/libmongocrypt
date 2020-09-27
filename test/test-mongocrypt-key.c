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

/* For each field, check a valid value, invalid value, missing value */

#include "bson/bson.h"
#include "test-mongocrypt.h"

/* Create a basis key document, but exclude some fields. */
static void
_recreate_excluding (_mongocrypt_tester_t *tester, bson_t *out, va_list args)
{
   bson_t tmp;

   BSON_ASSERT (_mongocrypt_binary_to_bson (
      TEST_FILE ("./test/data/key-document-full.json"), &tmp));

   /* copy to out */
   bson_destroy (out);
   bson_init (out);
   bson_copy_to_excluding_noinit_va (&tmp, out, "", args);
}

static void
_recreate_and_reset (_mongocrypt_tester_t *tester,
                     bson_t *key_bson,
                     mongocrypt_status_t *status,
                     ...)
{
   va_list args;

   va_start (args, status);
   _recreate_excluding (tester, key_bson, args);
   va_end (args);
   _mongocrypt_status_reset (status);
}


static void
_parse_ok (bson_t *key_bson, mongocrypt_status_t *status)
{
   _mongocrypt_key_doc_t *key_doc = _mongocrypt_key_new ();
   ASSERT_OK_STATUS (_mongocrypt_key_parse_owned (key_bson, key_doc, status),
                     status);
   _mongocrypt_key_destroy (key_doc);
}


static void
_parse_fails (bson_t *key_bson, mongocrypt_status_t *status, const char *msg)
{
   _mongocrypt_key_doc_t *key_doc = _mongocrypt_key_new ();
   ASSERT_FAILS_STATUS (
      _mongocrypt_key_parse_owned (key_bson, key_doc, status), status, msg);
   _mongocrypt_key_destroy (key_doc);
}


static void
test_mongocrypt_key_parsing (_mongocrypt_tester_t *tester)
{
   bson_t key_bson = BSON_INITIALIZER;
   mongocrypt_status_t *status;
   mongocrypt_binary_t *uuid;

   uuid = TEST_BIN (16);
   status = mongocrypt_status_new ();

   /* successful case. */
   _recreate_and_reset (tester, &key_bson, status, NULL);
   _parse_ok (&key_bson, status);

   /* unrecognized fields */
   _recreate_and_reset (tester, &key_bson, status, NULL);
   BSON_APPEND_INT32 (&key_bson, "invalid", 123);
   _parse_fails (&key_bson, status, "unrecognized field 'invalid'");

   /* malformed BSON */
   _recreate_and_reset (tester, &key_bson, status, NULL);
   /* mess with the length to corrupt the BSON. */
   ((uint8_t *) bson_get_data (&key_bson))[4] = 0xFF;
   _parse_fails (&key_bson, status, "invalid BSON");

   /* _id: missing. */
   _recreate_and_reset (tester, &key_bson, status, "_id", NULL);
   _parse_fails (&key_bson, status, "invalid key, no '_id'");
   /* _id: wrong type. */
   _recreate_and_reset (tester, &key_bson, status, "_id", NULL);
   BSON_APPEND_INT32 (&key_bson, "_id", 123);
   _parse_fails (&key_bson, status, "invalid key, '_id' is not a UUID");
   /* _id: invalid binary subtype. */
   _recreate_and_reset (tester, &key_bson, status, "_id", NULL);
   BSON_APPEND_BINARY (
      &key_bson, "_id", BSON_SUBTYPE_BINARY, uuid->data, uuid->len);
   _parse_fails (&key_bson, status, "invalid key, '_id' is not a UUID");
   /* _id: invalid UUID length. */
   _recreate_and_reset (tester, &key_bson, status, "_id", NULL);
   BSON_APPEND_BINARY (&key_bson, "_id", BSON_SUBTYPE_UUID, uuid->data, 5);
   _parse_fails (&key_bson, status, "invalid key, '_id' is not a UUID");

   /* version: missing (ok) */
   _recreate_and_reset (tester, &key_bson, status, "version", NULL);
   _parse_ok (&key_bson, status);
   /* version: wrong type */
   _recreate_and_reset (tester, &key_bson, status, "version", NULL);
   BSON_APPEND_UTF8 (&key_bson, "version", "abc");
   _parse_fails (&key_bson, status, "invalid 'version'");
   /* version: > 0 */
   _recreate_and_reset (tester, &key_bson, status, "version", NULL);
   BSON_APPEND_INT32 (&key_bson, "version", 1);
   _parse_fails (&key_bson, status, "unsupported key document version");

   /* keyMaterial: missing. */
   _recreate_and_reset (tester, &key_bson, status, "keyMaterial", NULL);
   _parse_fails (&key_bson, status, "invalid key, no 'keyMaterial'");
   /* keyMaterial: wrong type. */
   _recreate_and_reset (tester, &key_bson, status, "keyMaterial", NULL);
   BSON_APPEND_INT32 (&key_bson, "keyMaterial", 1);
   _parse_fails (&key_bson, status, "invalid 'keyMaterial', expected binary");
   /* keyMaterial: wrong subtype. */
   _recreate_and_reset (tester, &key_bson, status, "keyMaterial", NULL);
   BSON_APPEND_BINARY (
      &key_bson, "keyMaterial", BSON_SUBTYPE_UUID, uuid->data, uuid->len);
   _parse_fails (
      &key_bson, status, "invalid 'keyMaterial', expected subtype 0");

   /* masterKey: missing. */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   _parse_fails (&key_bson, status, "invalid key, no 'masterKey'");
   /* masterKey: missing provider. */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (&key_bson, TMP_BSON ("{'masterKey': { }}"));
   _parse_fails (&key_bson, status, "invalid 'masterKey', no 'provider'");
   /* masterKey: wrong provider. */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (&key_bson, TMP_BSON ("{'masterKey': { 'provider': 'bad' }}"));
   _parse_fails (&key_bson,
                 status,
                 "invalid 'masterKey.provider', expected 'aws' or 'local' or "
                 "'azure' or 'gcp'");
   /* masterKey: provider=aws, missing key */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (
      &key_bson,
      TMP_BSON ("{'masterKey': { 'provider': 'aws', 'region': 'us-east-1' }}"));
   _parse_fails (&key_bson, status, "invalid 'masterKey', no 'key'");
   /* masterKey: provider=aws, missing region */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (
      &key_bson,
      TMP_BSON ("{'masterKey': { 'provider': 'aws', 'key': 'cmk-string' }}"));
   _parse_fails (&key_bson, status, "invalid 'masterKey', no 'region'");
   /* masterKey: provider=aws, bad region */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (&key_bson,
                TMP_BSON ("{'masterKey': { 'provider': 'aws', "
                          "'key': 'cmk-string', 'region': 1 }}"));
   _parse_fails (
      &key_bson, status, "invalid 'masterKey.region', expected string");
   /* masterKey: unrecognized field */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (&key_bson,
                TMP_BSON ("{'masterKey': { 'provider': 'local', 'bad': 1 }}"));
   _parse_fails (&key_bson, status, "unrecognized provider field");

   /* creationDate: missing */
   _recreate_and_reset (tester, &key_bson, status, "creationDate", NULL);
   _parse_fails (&key_bson, status, "invalid key, no 'creationDate'");
   /* creationDate: wrong type */
   _recreate_and_reset (tester, &key_bson, status, "creationDate", NULL);
   BSON_APPEND_UTF8 (&key_bson, "creationDate", "abc");
   _parse_fails (&key_bson, status, "invalid 'creationDate', expect datetime");

   /* updateDate: missing */
   _recreate_and_reset (tester, &key_bson, status, "updateDate", NULL);
   _parse_fails (&key_bson, status, "invalid key, no 'updateDate'");

   /* updateDate: wrong type */
   _recreate_and_reset (tester, &key_bson, status, "updateDate", NULL);
   BSON_APPEND_UTF8 (&key_bson, "updateDate", "abc");
   _parse_fails (&key_bson, status, "invalid 'updateDate', expect datetime");

   /* status: missing */
   _recreate_and_reset (tester, &key_bson, status, "status", NULL);
   _parse_fails (&key_bson, status, "invalid key, no 'status'");

   /* masterKey: azure */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (
      &key_bson,
      TMP_BSON (
         "{'masterKey': { 'provider': 'azure', 'keyVaultEndpoint': "
         "'abc.example.com', 'keyName': 'test', 'keyVersion': 'abc' }}"));
   _parse_ok (&key_bson, status);

   /* masterKey: gcp */
   _recreate_and_reset (tester, &key_bson, status, "masterKey", NULL);
   bson_concat (
      &key_bson,
      TMP_BSON ("{'masterKey': { 'provider': 'gcp', 'endpoint': "
                "'abc.example.com', 'projectId': 'project', 'location': "
                "'global', 'keyRing': 'ring', 'keyName': 'name' }}"));
   _parse_ok (&key_bson, status);

   mongocrypt_status_destroy (status);
   bson_destroy (&key_bson);
}

static void
test_mongocrypt_key_alt_name_from_iter (_mongocrypt_tester_t *tester)
{
   mongocrypt_status_t *status;
   bson_iter_t iter;
   bson_t *test;
   _mongocrypt_key_alt_name_t *key_alt_names;

   status = mongocrypt_status_new ();

   /* Empty alt names */
   test = TMP_BSON ("{'test': []}");
   bson_iter_init_find (&iter, test, "test");
   ASSERT_OK_STATUS (
      _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
      status);
   BSON_ASSERT (NULL == key_alt_names);

   /* One alt name */
   test = TMP_BSON ("{'test': ['a']}");
   bson_iter_init_find (&iter, test, "test");
   ASSERT_OK_STATUS (
      _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
      status);
   BSON_ASSERT (
      0 == strcmp ("a", _mongocrypt_key_alt_name_get_string (key_alt_names)));
   BSON_ASSERT (NULL == key_alt_names->next);
   _mongocrypt_key_alt_name_destroy_all (key_alt_names);

   /* Two alt names */
   test = TMP_BSON ("{'test': ['a', 'b']}");
   bson_iter_init_find (&iter, test, "test");
   ASSERT_OK_STATUS (
      _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
      status);
   BSON_ASSERT (
      0 == strcmp ("b", _mongocrypt_key_alt_name_get_string (key_alt_names)));
   BSON_ASSERT (
      0 ==
      strcmp ("a", _mongocrypt_key_alt_name_get_string (key_alt_names->next)));
   BSON_ASSERT (NULL == key_alt_names->next->next);
   _mongocrypt_key_alt_name_destroy_all (key_alt_names);

   /* Invalid alt names */
   test = TMP_BSON ("{'test': ['a', 1]}");
   bson_iter_init_find (&iter, test, "test");
   ASSERT_FAILS_STATUS (
      _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
      status,
      "unexpected non-UTF8");

   /* Duplicate alt names */
   test = TMP_BSON ("{'test': ['b', 'a', 'c', 'a']}");
   bson_iter_init_find (&iter, test, "test");
   ASSERT_FAILS_STATUS (
      _mongocrypt_key_alt_name_from_iter (&iter, &key_alt_names, status),
      status,
      "duplicate");

   mongocrypt_status_destroy (status);
}


void
_mongocrypt_tester_install_key (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_mongocrypt_key_parsing);
   INSTALL_TEST (test_mongocrypt_key_alt_name_from_iter);
}
