/*
 * Copyright 2024-present MongoDB, Inc.
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

#include "mc-fle2-tag-and-encrypted-metadata-block-private.h"
#include "mc-reader-private.h"
#include "mc-writer-private.h"
#include "mongocrypt-private.h"

#define CHECK_AND_RETURN(x)                                                                                            \
    if (!(x)) {                                                                                                        \
        return false;                                                                                                  \
    }

void mc_FLE2TagAndEncryptedMetadataBlock_init(mc_FLE2TagAndEncryptedMetadataBlock_t *metadata) {
    memset(metadata, 0, sizeof(mc_FLE2TagAndEncryptedMetadataBlock_t));
}

void mc_FLE2TagAndEncryptedMetadataBlock_cleanup(mc_FLE2TagAndEncryptedMetadataBlock_t *metadata) {
    BSON_ASSERT_PARAM(metadata);

    _mongocrypt_buffer_cleanup(&metadata->encryptedCount);
    _mongocrypt_buffer_cleanup(&metadata->tag);
    _mongocrypt_buffer_cleanup(&metadata->encryptedZeros);
}

bool mc_FLE2TagAndEncryptedMetadataBlock_parse(mc_FLE2TagAndEncryptedMetadataBlock_t *metadata,
                                               mc_reader_t *reader,
                                               mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(reader);

    mc_FLE2TagAndEncryptedMetadataBlock_init(metadata);

    CHECK_AND_RETURN(mc_reader_read_buffer(reader, &metadata->encryptedCount, kFieldLen, status));

    CHECK_AND_RETURN(mc_reader_read_buffer(reader, &metadata->tag, kFieldLen, status));

    CHECK_AND_RETURN(mc_reader_read_buffer(reader, &metadata->encryptedZeros, kFieldLen, status));

    return true;
}

bool mc_FLE2TagAndEncryptedMetadataBlock_serialize(const mc_FLE2TagAndEncryptedMetadataBlock_t *metadata,
                                                   mc_writer_t *writer,
                                                   mongocrypt_status_t *status) {
    BSON_ASSERT_PARAM(metadata);
    BSON_ASSERT_PARAM(writer);

    CHECK_AND_RETURN(mc_writer_write_buffer(writer, &metadata->encryptedCount, kFieldLen, status));

    CHECK_AND_RETURN(mc_writer_write_buffer(writer, &metadata->tag, kFieldLen, status));

    CHECK_AND_RETURN(mc_writer_write_buffer(writer, &metadata->encryptedZeros, kFieldLen, status));

    return true;
}
