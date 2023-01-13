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
#include "mc-writer-private.h"
#include "test-mongocrypt-assert.h"
#include "test-mongocrypt.h"

static void
_test_mc_writer_ints (_mongocrypt_tester_t *tester)
{
    {
        mongocrypt_status_t *status;
        status = mongocrypt_status_new ();

        _mongocrypt_buffer_t write_buffer;
        _mongocrypt_buffer_init_size (&write_buffer, sizeof(uint8_t));
        
        mc_writer_t writer;
        mc_writer_init_from_buffer(&writer, &write_buffer, __FUNCTION__);

        uint8_t num = 4;
        mc_writer_write_u8 (&writer, &num, status);
        
        mc_reader_t reader;
        mc_reader_init_from_buffer (&reader, &write_buffer, __FUNCTION__);

        uint8_t out;
        mc_reader_read_u8 (&reader, &out, status);

        ASSERT_CMPUINT (out, ==, num);

        _mongocrypt_buffer_cleanup (&write_buffer);
        mongocrypt_status_destroy (status);
    }

    {
        mongocrypt_status_t *status;
        status = mongocrypt_status_new ();

        _mongocrypt_buffer_t write_buffer;
        _mongocrypt_buffer_init_size (&write_buffer, sizeof(uint32_t));

        mc_writer_t writer;
        mc_writer_init_from_buffer(&writer, &write_buffer, __FUNCTION__);

        uint32_t num = 23832405;
        mc_writer_write_u32 (&writer, &num, status);

        mc_reader_t reader;
        mc_reader_init_from_buffer (&reader, &write_buffer, __FUNCTION__);

        uint32_t out;
        mc_reader_read_u32 (&reader, &out, status);

        ASSERT_CMPUINT (out, ==, num);

        _mongocrypt_buffer_cleanup (&write_buffer);
        mongocrypt_status_destroy (status);
    }

    {
        mongocrypt_status_t *status;
        status = mongocrypt_status_new ();

        _mongocrypt_buffer_t write_buffer;
        _mongocrypt_buffer_init_size (&write_buffer, sizeof(uint64_t));

        mc_writer_t writer;
        mc_writer_init_from_buffer(&writer, &write_buffer, __FUNCTION__);

        uint64_t num = 23832405;
        mc_writer_write_u64 (&writer, &num, status);

        mc_reader_t reader;
        mc_reader_init_from_buffer (&reader, &write_buffer, __FUNCTION__);

        uint64_t out;
        mc_reader_read_u64 (&reader, &out, status);

        ASSERT_CMPUINT (out, ==, num);

        _mongocrypt_buffer_cleanup (&write_buffer);
        mongocrypt_status_destroy (status);
    }

}

static void
_test_mc_writer_buffer (_mongocrypt_tester_t *tester)
{
    mongocrypt_status_t *status;
    status = mongocrypt_status_new ();

    _mongocrypt_buffer_t input_buffer;

    _mongocrypt_buffer_copy_from_hex (
        &input_buffer,
        "07123456781234987612341234567890120243bba14ddf42da823c33569f4689f465a");

    _mongocrypt_buffer_t write_buffer;
    _mongocrypt_buffer_init_size (&write_buffer, input_buffer.len);

    mc_writer_t writer;
    mc_writer_init_from_buffer(&writer, &write_buffer, __FUNCTION__);

    mc_writer_write_buffer(&writer, &input_buffer, input_buffer.len, status);

    _mongocrypt_buffer_t read_buffer;
    _mongocrypt_buffer_init_size (&read_buffer, input_buffer.len);

    mc_reader_t reader;
    mc_reader_init_from_buffer (&reader, &write_buffer, __FUNCTION__);
    mc_reader_read_buffer (&reader, &read_buffer, read_buffer.len, status);

    ASSERT_CMPBUF(input_buffer, read_buffer);

    _mongocrypt_buffer_cleanup (&input_buffer);
    _mongocrypt_buffer_cleanup (&write_buffer);
    _mongocrypt_buffer_cleanup (&read_buffer);
    mongocrypt_status_destroy (status);
}

static void
_test_mc_writer_prf (_mongocrypt_tester_t *tester)
{
    _mongocrypt_buffer_t write_buffer;
    // _mongocrypt_buffer_copy_from_hex ();



}

static void
_test_mc_writer_uuid (_mongocrypt_tester_t *tester)
{
    _mongocrypt_buffer_t write_buffer;
    // _mongocrypt_buffer_copy_from_hex ();

}

void
_mongocrypt_tester_install_mc_writer (_mongocrypt_tester_t *tester)
{
    INSTALL_TEST (_test_mc_writer_ints);
    INSTALL_TEST (_test_mc_writer_buffer);
}