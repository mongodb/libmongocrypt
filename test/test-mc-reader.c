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

#include "mc-reader-private.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

static void
_test_mc_reader (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input_buf;
   _mongocrypt_buffer_copy_from_hex (&input_buf, "ABCD");

   mongocrypt_status_t *status;
   status = mongocrypt_status_new ();

   mc_reader_t reader;
   mc_reader_init_from_buffer (&reader, &input_buf, __FUNCTION__);

   uint8_t value;
   ASSERT_OK_STATUS (mc_reader_read_u8 (&reader, &value, status), status);
   ASSERT_CMPUINT (value, ==, 0xAB);
   ASSERT_CMPUINT64 (mc_reader_get_consumed_length (&reader), ==, 1);
   ASSERT_CMPUINT64 (mc_reader_get_remaining_length (&reader), ==, 1);

   ASSERT_OK_STATUS (mc_reader_read_u8 (&reader, &value, status), status);
   ASSERT_CMPUINT (value, ==, 0xCD);
   ASSERT_CMPUINT64 (mc_reader_get_consumed_length (&reader), ==, 2);
   ASSERT_CMPUINT64 (mc_reader_get_remaining_length (&reader), ==, 0);

   ASSERT_FAILS_STATUS (mc_reader_read_u8 (&reader, &value, status),
                        status,
                        "expected byte length >= 3 got: 2");

   _mongocrypt_buffer_cleanup (&input_buf);
   mongocrypt_status_destroy (status);
}

static void
_test_mc_reader_uuid (_mongocrypt_tester_t *tester)
{
   const uint8_t expected_bytes[] = {0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12};
   uint64_t expected_len = sizeof (expected_bytes);

   _mongocrypt_buffer_t input_buf;
   _mongocrypt_buffer_copy_from_hex (&input_buf,
                                     "12345678901234567890123456789012");

   mongocrypt_status_t *status;
   status = mongocrypt_status_new ();

   mc_reader_t reader;
   mc_reader_init_from_buffer (&reader, &input_buf, __FUNCTION__);

   _mongocrypt_buffer_t value;
   ASSERT_OK_STATUS (mc_reader_read_uuid_buffer (&reader, &value, status),
                     status);
   ASSERT (value.subtype == BSON_SUBTYPE_UUID);

   ASSERT_CMPBYTES (
      expected_bytes, (size_t) expected_len, value.data, value.len);


   uint8_t ui;
   ASSERT_FAILS_STATUS (mc_reader_read_u8 (&reader, &ui, status),
                        status,
                        "expected byte length >= 17 got: 16");

   _mongocrypt_buffer_cleanup (&input_buf);
   _mongocrypt_buffer_cleanup (&value);
   mongocrypt_status_destroy (status);
}

static void
_test_mc_reader_ints (_mongocrypt_tester_t *tester)
{
   _mongocrypt_buffer_t input_buf;
   _mongocrypt_buffer_copy_from_hex (&input_buf, "001122330011223344556677");

   mongocrypt_status_t *status;
   status = mongocrypt_status_new ();

   mc_reader_t reader;
   mc_reader_init_from_buffer (&reader, &input_buf, __FUNCTION__);

   uint32_t u32;
   ASSERT_OK_STATUS (mc_reader_read_u32 (&reader, &u32, status), status);
   ASSERT_CMPUINT32 (u32, ==, 0x33221100);

   uint64_t u64;
   ASSERT_OK_STATUS (mc_reader_read_u64 (&reader, &u64, status), status);
   ASSERT_CMPUINT64 (u64, ==, 0x7766554433221100ULL);

   _mongocrypt_buffer_cleanup (&input_buf);
   mongocrypt_status_destroy (status);
}

static void
_test_mc_reader_bytes (_mongocrypt_tester_t *tester)
{
   const uint8_t expected_bytes[] = {0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12,
                                     0x34,
                                     0x56,
                                     0x78,
                                     0x90,
                                     0x12};
   uint64_t expected_len = sizeof (expected_bytes);

   _mongocrypt_buffer_t input_buf;
   _mongocrypt_buffer_copy_from_hex (&input_buf,
                                     "12345678901234567890123456789012");

   mongocrypt_status_t *status;
   status = mongocrypt_status_new ();

   mc_reader_t reader;
   mc_reader_init_from_buffer (&reader, &input_buf, __FUNCTION__);

   const uint8_t *ptr;
   const uint64_t len = 4;
   ASSERT_OK_STATUS (
      mc_reader_read_bytes (&reader, (const uint8_t **) &ptr, len, status),
      status);
   ASSERT_CMPBYTES (expected_bytes, 4, ptr, (size_t) len);

   _mongocrypt_buffer_t value_buf;
   ASSERT_OK_STATUS (mc_reader_read_buffer_to_end (&reader, &value_buf, status),
                     status);
   ASSERT_CMPBYTES (
      expected_bytes + 4u, expected_len - 4u, value_buf.data, value_buf.len);

   _mongocrypt_buffer_cleanup (&input_buf);
   _mongocrypt_buffer_cleanup (&value_buf);
   mongocrypt_status_destroy (status);
}

void
_mongocrypt_tester_install_mc_reader (_mongocrypt_tester_t *tester)
{
   INSTALL_TEST (_test_mc_reader);
   INSTALL_TEST (_test_mc_reader_uuid);
   INSTALL_TEST (_test_mc_reader_ints);
   INSTALL_TEST (_test_mc_reader_bytes);
}
