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
#include "mongocrypt-marking-private.h"
#include "test-mongocrypt.h"


/* Create a basis marking buffer with valid values for the given fields. */
static void
_make_marking (bson_t *bson, _mongocrypt_buffer_t *buf)
{
   buf->len = bson->len + 1;
   buf->data = bson_malloc (buf->len);
   BSON_ASSERT (buf->data);

   buf->data[0] = 0;
   buf->owned = true;
   memcpy (buf->data + 1, bson_get_data (bson), bson->len);
}


static void
_parse_ok (_mongocrypt_buffer_t *marking_buf, _mongocrypt_marking_t *out)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   memset (out, 0, sizeof (*out));
   ASSERT_OK_STATUS (
      _mongocrypt_marking_parse_unowned (marking_buf, out, status), status);

   mongocrypt_status_destroy (status);
}


static void
_parse_fails (_mongocrypt_buffer_t *marking_buf,
              const char *msg,
              _mongocrypt_marking_t *out)
{
   mongocrypt_status_t *status;

   status = mongocrypt_status_new ();
   memset (out, 0, sizeof (*out));
   ASSERT_FAILS_STATUS (
      _mongocrypt_marking_parse_unowned (marking_buf, out, status),
      status,
      msg);

   mongocrypt_status_destroy (status);
}

static void
test_mongocrypt_marking_parse (_mongocrypt_tester_t *tester)
{
   bson_t *marking_bson;
   _mongocrypt_buffer_t marking_buf;
   _mongocrypt_marking_t marking;

   /* successful case. */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_ok (&marking_buf, &marking);
   BSON_ASSERT (marking.algorithm == MONGOCRYPT_ENCRYPTION_ALGORITHM_RANDOM);
   BSON_ASSERT (0 == strcmp ("abc", bson_iter_utf8 (&marking.v_iter, NULL)));
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* buffer < 5 bytes */
   marking_buf.data = (uint8_t *) "abc";
   marking_buf.len = 3;
   marking_buf.owned = false;
   _parse_fails (&marking_buf, "invalid marking, length < 5", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* bad first byte */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   marking_buf.data[0] = 1;
   _parse_fails (&marking_buf, "invalid marking", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* unrecognized fields. */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt', 'extra': 1}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "unrecognized field 'extra'", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* malformed BSON. */
   marking_bson = TMP_BSON ("{}");
   ((uint8_t *) bson_get_data (marking_bson))[4] = 0xFF;
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "invalid BSON", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* a: missing */
   marking_bson = TMP_BSON ("{'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "no 'a' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* a: wrong type */
   marking_bson = TMP_BSON ("{'a': 'abc', 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (
      &marking_buf, "invalid marking, 'a' must be an int32", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* a: wrong integer */
   marking_bson = TMP_BSON ("{'a': -1, 'v': 'abc', 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "invalid algorithm value: -1", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* v: missing */
   marking_bson = TMP_BSON ("{'a': 2, 'ka': 'alt'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "no 'v' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* Not testing IV per CDRIVER-3127. TODO: remove this comment. */

   /* ki+ka: missing */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc'}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "neither 'ki' nor 'ka' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
   /* ki+ka: both present */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ka': 'alt' }");
   BSON_APPEND_BINARY (
      marking_bson, "ki", BSON_SUBTYPE_UUID, (TEST_BIN (16))->data, 16);
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "both 'ki' and 'ka' specified", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ki: wrong type */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc', 'ki': 'abc' }");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key id must be a UUID", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ki: wrong subtype */
   marking_bson = TMP_BSON ("{'a': 2, 'v': 'abc' }");
   BSON_APPEND_BINARY (
      marking_bson, "ki", BSON_SUBTYPE_BINARY, (TEST_BIN (16))->data, 16);
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key id must be a UUID", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);

   /* ka: wrong type */
   marking_bson = TMP_BSON ("{'v': 'abc', 'ka': 1}");
   _make_marking (marking_bson, &marking_buf);
   _parse_fails (&marking_buf, "key alt name must be a UTF8", &marking);
   _mongocrypt_buffer_cleanup (&marking_buf);
   _mongocrypt_marking_cleanup (&marking);
}


void
_mongocrypt_tester_install_marking (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (test_mongocrypt_marking_parse);
}