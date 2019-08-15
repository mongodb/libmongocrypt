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

#include "test-mongocrypt.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-cache-collinfo-private.h"

void
_test_cache (_mongocrypt_tester_t *tester)
{
   _mongocrypt_cache_t cache;
   mongocrypt_status_t *status;
   bson_t *entry = BCON_NEW ("a", "b"), *entry2 = BCON_NEW ("c", "d");
   bson_t *tmp = NULL;

   status = mongocrypt_status_new ();

   _mongocrypt_cache_collinfo_init (&cache);

   /* Test get on an empty cache. */
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "1", (void **) &tmp));
   BSON_ASSERT (!tmp);


   /* Test set + get */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "1", (void **) &tmp));
   /* Assert we get a copy back. */
   BSON_ASSERT (entry != tmp);
   BSON_ASSERT (bson_equal (entry, tmp));
   bson_destroy (tmp);

   /* Test missing find. */
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "2", (void **) &tmp));
   BSON_ASSERT (!tmp);


   /* Test attempting to overwrite an entry. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry2, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "1", (void **) &tmp));
   /* Overwrite is ignored. */
   BSON_ASSERT (bson_equal (entry2, tmp));
   bson_destroy (tmp);

   /* Test with two entries in the cache. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "2", entry2, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "2", (void **) &tmp));
   BSON_ASSERT (bson_equal (entry2, tmp));
   bson_destroy (tmp);

   /* Test stealing an entry. */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_stolen (&cache, "3", entry, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "3", (void **) &tmp));
   BSON_ASSERT (bson_equal (entry, tmp));
   bson_destroy (tmp);

   _mongocrypt_cache_cleanup (&cache);
   mongocrypt_status_destroy (status);
   bson_destroy (entry2);
}

static void
_usleep (int64_t usec)
{
#ifdef _WIN32
   LARGE_INTEGER ft;
   HANDLE timer;

   BSON_ASSERT (usec >= 0);

   ft.QuadPart = -(10 * usec);
   timer = CreateWaitableTimer (NULL, true, NULL);
   SetWaitableTimer (timer, &ft, 0, NULL, NULL, 0);
   WaitForSingleObject (timer, INFINITE);
   CloseHandle (timer);
#else
   BSON_ASSERT (usec >= 0);
   usleep ((useconds_t) usec);
#endif
}

static void
_test_cache_expiration (_mongocrypt_tester_t *tester)
{
   _mongocrypt_cache_t cache;
   mongocrypt_status_t *status;
   bson_t *entry = BCON_NEW ("a", "b");
   bson_t *tmp = NULL;

   status = mongocrypt_status_new ();

   _mongocrypt_cache_collinfo_init (&cache);
   _mongocrypt_cache_set_expiration (&cache, 1);
   /* Test set + get */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, "1", entry, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_get (&cache, "1", (void **) &tmp));
   /* Assert we get a copy back. */
   BSON_ASSERT (entry != tmp);
   BSON_ASSERT (bson_equal (entry, tmp));
   bson_destroy (tmp);

   /* Sleep for 100 milliseconds */
   _usleep (1000 * 100);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, "1", (void **) &tmp));
   BSON_ASSERT (!tmp);

   _mongocrypt_cache_cleanup (&cache);
   mongocrypt_status_destroy (status);
   bson_destroy (entry);
}


static void
_test_cache_duplicates (_mongocrypt_tester_t *tester)
{
   _mongocrypt_cache_t cache;
   mongocrypt_status_t *status;
   _mongocrypt_key_doc_t *placeholder_keydoc;
   _mongocrypt_cache_key_value_t *value1, *value2, *value3, *value4, *tmp;
   _mongocrypt_cache_key_attr_t *attr1, *attr2, *attr3, *attr4;
   _mongocrypt_buffer_t buf1, buf2, buf3,
      buf4; /* distinguished by first byte. */
   _mongocrypt_key_alt_name_t *alt_names1, *alt_names2, *alt_names3,
      *alt_names4;

   status = mongocrypt_status_new ();

   _mongocrypt_buffer_init (&buf1);
   _mongocrypt_buffer_init (&buf2);
   _mongocrypt_buffer_init (&buf3);
   _mongocrypt_buffer_init (&buf4);

   _mongocrypt_buffer_resize (&buf1, MONGOCRYPT_KEY_LEN);
   _mongocrypt_buffer_resize (&buf2, MONGOCRYPT_KEY_LEN);
   _mongocrypt_buffer_resize (&buf3, MONGOCRYPT_KEY_LEN);
   _mongocrypt_buffer_resize (&buf4, MONGOCRYPT_KEY_LEN);

   buf1.data[0] = 1;
   buf2.data[0] = 2;
   buf3.data[0] = 3;
   buf4.data[0] = 4;

   placeholder_keydoc = _mongocrypt_key_new ();

   value1 = _mongocrypt_cache_key_value_new (placeholder_keydoc, &buf1);
   value2 = _mongocrypt_cache_key_value_new (placeholder_keydoc, &buf2);
   value3 = _mongocrypt_cache_key_value_new (placeholder_keydoc, &buf3);
   value4 = _mongocrypt_cache_key_value_new (placeholder_keydoc, &buf4);

   alt_names1 = _MONGOCRYPT_KEY_ALT_NAME_CREATE ("a", "b");
   alt_names2 = _MONGOCRYPT_KEY_ALT_NAME_CREATE ("c", "d");
   alt_names3 = _MONGOCRYPT_KEY_ALT_NAME_CREATE ("e");
   alt_names4 = _MONGOCRYPT_KEY_ALT_NAME_CREATE ("a", "d");

   attr1 = _mongocrypt_cache_key_attr_new (NULL /* id */, alt_names1);
   attr2 = _mongocrypt_cache_key_attr_new (NULL /* id */, alt_names2);
   attr3 = _mongocrypt_cache_key_attr_new (NULL /* id */, alt_names3);
   attr4 = _mongocrypt_cache_key_attr_new (NULL /* id */, alt_names4);

   _mongocrypt_cache_key_init (&cache);

   /* add three non-intersecting entries */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, attr1, value1, status),
                    status);
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, attr2, value2, status),
                    status);
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, attr3, value3, status),
                    status);
   BSON_ASSERT (_mongocrypt_cache_num_entries (&cache) == 3);

   /* all three should be in the cache */
   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr1, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 1);
   _mongocrypt_cache_key_value_destroy (tmp);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr2, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 2);
   _mongocrypt_cache_key_value_destroy (tmp);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr3, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 3);
   _mongocrypt_cache_key_value_destroy (tmp);

   /* add intersecting entry */
   ASSERT_OR_PRINT (_mongocrypt_cache_add_copy (&cache, attr4, value4, status),
                    status);
   /* cache still only has 2 entries since two were deduplicated */
   BSON_ASSERT (_mongocrypt_cache_num_entries (&cache) == 2);

   /* attr1 and attr2 match the overwriting entry */
   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr1, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 4);
   _mongocrypt_cache_key_value_destroy (tmp);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr2, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 4);
   _mongocrypt_cache_key_value_destroy (tmp);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr3, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 3);
   _mongocrypt_cache_key_value_destroy (tmp);

   BSON_ASSERT (_mongocrypt_cache_get (&cache, attr4, (void **) &tmp));
   BSON_ASSERT (tmp);
   BSON_ASSERT (tmp->decrypted_key_material.data[0] == 4);
   _mongocrypt_cache_key_value_destroy (tmp);

   _mongocrypt_cache_key_attr_destroy (attr1);
   _mongocrypt_cache_key_attr_destroy (attr2);
   _mongocrypt_cache_key_attr_destroy (attr3);
   _mongocrypt_cache_key_attr_destroy (attr4);

   _mongocrypt_key_alt_name_destroy_all (alt_names1);
   _mongocrypt_key_alt_name_destroy_all (alt_names2);
   _mongocrypt_key_alt_name_destroy_all (alt_names3);
   _mongocrypt_key_alt_name_destroy_all (alt_names4);

   _mongocrypt_cache_key_value_destroy (value1);
   _mongocrypt_cache_key_value_destroy (value2);
   _mongocrypt_cache_key_value_destroy (value3);
   _mongocrypt_cache_key_value_destroy (value4);

   _mongocrypt_key_destroy (placeholder_keydoc);

   _mongocrypt_buffer_cleanup (&buf1);
   _mongocrypt_buffer_cleanup (&buf2);
   _mongocrypt_buffer_cleanup (&buf3);
   _mongocrypt_buffer_cleanup (&buf4);

   mongocrypt_status_destroy (status);
   _mongocrypt_cache_cleanup (&cache);
}

void
_mongocrypt_tester_install_cache (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_cache);
   INSTALL_TEST (_test_cache_expiration);
   INSTALL_TEST (_test_cache_duplicates);
}