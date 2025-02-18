/*
 * Copyright 2018-present MongoDB, Inc.
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

#include "mc-schema-broker-private.h"

#include "test-mongocrypt.h"

static void test_mc_schema_broker_request(_mongocrypt_tester_t *tester) {
    // Can request.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);

        // Check listCollections filter:
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : "coll"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can request two collections.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT(!mc_schema_broker_has_multiple_requests(sb));
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT(!mc_schema_broker_has_multiple_requests(sb));
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_has_multiple_requests(sb));

        // Check listCollections filter:
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : {"$in" : [ "coll1", "coll2" ]}})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Duplicates are ignored.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT(!mc_schema_broker_has_multiple_requests(sb));
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT(!mc_schema_broker_has_multiple_requests(sb));
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT(!mc_schema_broker_has_multiple_requests(sb));

        // Check listCollections filter:
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : "coll1"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if requesting two collections on different databases.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db1", "coll1", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_request(sb, "db2", "coll2", status),
                            status,
                            "Cannot request schemas for different databases");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not include satisfied collections in listCollections filter.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll1", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);

        // Satisfy db.coll1:
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, TMP_BSON(BSON_STR({"db.coll1" : {}})), status),
                         status);

        // Check listCollections filter:
        bson_t filter = BSON_INITIALIZER;
        ASSERT_OK_STATUS(mc_schema_broker_append_listCollections_filter(sb, &filter, status), status);
        ASSERT_EQUAL_BSON(TMP_BSON(BSON_STR({"name" : "coll2"})), &filter);
        bson_destroy(&filter);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_collInfo(_mongocrypt_tester_t *tester) {
    bson_t *collinfo_jsonSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-jsonSchema.json");

    // Can satisfy with collinfo containing $jsonSchema.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        // Check that collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "db.coll", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(collinfo_jsonSchema, cached_collinfo);
            bson_destroy(cached_collinfo);
        }

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with collinfo containing encryptedFields.
    {
        bson_t *collinfo_encryptedFields = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-encryptedFields.json");
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_encryptedFields, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        // Check that collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "db.coll", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(collinfo_encryptedFields, cached_collinfo);
            bson_destroy(cached_collinfo);
        }

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with collinfo containing no schema.
    {
        bson_t *collinfo_noSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-noSchema.json");
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_noSchema, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        // Check that collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "db.coll", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(collinfo_noSchema, cached_collinfo);
            bson_destroy(cached_collinfo);
        }

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy a non-requested collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "different", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status),
                            status,
                            "got unexpected collinfo result");

        // Check that collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "db.coll", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(collinfo_jsonSchema, cached_collinfo);
            bson_destroy(cached_collinfo);
        }

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy an already satisfied collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status),
                            status,
                            "unexpected duplicate");

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy with an empty document.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, TMP_BSON("{}"), &cache, status),
                            status,
                            "failed to find 'name'");
        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if attempting to satisfy with a view.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        bson_t *collinfo_view = TEST_FILE_AS_BSON("./test/data/collection-info-view.json");

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "v", status), status);
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_view, &cache, status),
                            status,
                            "cannot auto encrypt a view");
        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Accepts a collinfo with siblings, like: {"$jsonSchema": {...}, "sibling": {...}}
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        bson_t *collinfo_siblings = TEST_FILE_AS_BSON("./test/data/collinfo-siblings.json");

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "test", "test", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_siblings, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        // Check that collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "test.test", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(collinfo_siblings, cached_collinfo);
            bson_destroy(cached_collinfo);
        }
        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_cache(_mongocrypt_tester_t *tester) {
    bson_t *collinfo = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-jsonSchema.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll", collinfo, status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }

    // Can satisfy with empty entry.
    {
        // An empty entry is cached when there is none on the server (e.g. the collection was not created on the server)
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll", TMP_BSON("{}"), status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }

    // Ignores if no entry.
    {
        // An empty entry is cached when there is none on the server (e.g. the collection was not created on the server)
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll2", TMP_BSON("{}"), status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb)); // db.coll still not satisfied.

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }

    // Ignores already satisfied entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);
        ASSERT_OR_PRINT(_mongocrypt_cache_add_copy(&cache, "db.coll", collinfo, status), status);

        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        // Satisfy again. No error.
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_cache(sb, &cache, status), status);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
        _mongocrypt_cache_cleanup(&cache);
    }
}

static void test_mc_schema_broker_satisfy_from_schemaMap(_mongocrypt_tester_t *tester) {
    bson_t *schemaMap = TEST_FILE_AS_BSON("./test/data/schema-broker/schemaMap.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy multiple.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not satisfy with non-matching entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, TMP_BSON("{'db.foo': {}}"), status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb)); // Still not satisfied.

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy with empty entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, TMP_BSON("{'db.coll': {}}"), status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Ignores already satisfied entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        // Satisfy again. No error.
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_encryptedFieldsMap(_mongocrypt_tester_t *tester) {
    bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Can satisfy multiple.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not satisfy with non-matching entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, TMP_BSON("{'db.foo': {}}"), status),
                         status);
        ASSERT(mc_schema_broker_need_more_schemas(sb)); // Still not satisfied.

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Ignores already satisfied entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        // Satisfy again. No error.
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Fails to satisfy with empty entry.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_FAILS_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, TMP_BSON("{'db.coll': {}}"), status),
                            status,
                            "unable to find 'fields'");

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_remaining_with_empty_schemas(_mongocrypt_tester_t *tester) {
    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        // Check that empty collinfo is cached.
        {
            bson_t *cached_collinfo;
            ASSERT(_mongocrypt_cache_get(&cache, "db.coll", (void **)&cached_collinfo));
            ASSERT(cached_collinfo);
            ASSERT_EQUAL_BSON(TMP_BSON("{}"), cached_collinfo);
            bson_destroy(cached_collinfo);
        }

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_add_schemas_to_cmd(_mongocrypt_tester_t *tester) {
    bson_t *schemaMap = TEST_FILE_AS_BSON("./test/data/schema-broker/schemaMap.json");
    bson_t *jsonSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/jsonSchema.json");
    bson_t *jsonSchema2 = TEST_FILE_AS_BSON("./test/data/schema-broker/jsonSchema2.json");
    bson_t *collinfo_jsonSchema = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-jsonSchema.json");
    bson_t *encryptedFields = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFields.json");
    bson_t *encryptedFields2 = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFields2.json");
    bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");
    bson_t *collinfo_encryptedFields2 = TEST_FILE_AS_BSON("./test/data/schema-broker/collinfo-encryptedFields2.json");

    // Adds one JSON schema as jsonSchema.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect =
            TMP_BSONF(BSON_STR({"find" : "coll", "jsonSchema" : MC_BSON, "isRemoteSchema" : false}), jsonSchema);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds multiple JSON schemas as csfleEncryptionSchemas.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect = TMP_BSONF(BSON_STR({
                                       "find" : "coll",
                                       "csfleEncryptionSchemas" : {
                                           "db.coll" : {"jsonSchema" : MC_BSON, "isRemoteSchema" : false},
                                           "db.coll2" : {"jsonSchema" : MC_BSON, "isRemoteSchema" : false}
                                       }
                                   }),
                                   jsonSchema,
                                   jsonSchema2);

        ASSERT_EQUAL_BSON(expect, cmd);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds an empty 'jsonSchema' when no schema is present.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect = TMP_BSON(BSON_STR({"find" : "coll", "jsonSchema" : {}, "isRemoteSchema" : true}));
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds empty JSON schema in 'csfleEncryptionSchemas' when one collection has a JSON schema and other does not.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        // Satisfy db.coll with a schema:
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status), status);
        // Satisfy db.coll2 with empty schema.
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect = TMP_BSONF(BSON_STR({
                                       "find" : "coll",
                                       "csfleEncryptionSchemas" : {
                                           "db.coll" : {"jsonSchema" : MC_BSON, "isRemoteSchema" : true},
                                           "db.coll2" : {"jsonSchema" : {}, "isRemoteSchema" : false}
                                       }
                                   }),
                                   jsonSchema);
        ASSERT_EQUAL_BSON(expect, cmd);

        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds empty JSON schemas within 'csfleEncryptionSchemas' when no schema is present on any collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect = TMP_BSON(BSON_STR({
            "find" : "coll",
            "csfleEncryptionSchemas" : {
                "db.coll" : {"jsonSchema" : {}, "isRemoteSchema" : false},
                "db.coll2" : {"jsonSchema" : {}, "isRemoteSchema" : false}
            }
        }));
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Errors if mixing JSON schema with QE schema.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();
        _mongocrypt_cache_t cache;
        _mongocrypt_cache_collinfo_init(&cache);

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        // Satisfy db.coll with a JSON schema:
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_jsonSchema, &cache, status), status);
        // Satisfy db.coll2 with an encryptedFields:
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_collinfo(sb, collinfo_encryptedFields2, &cache, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_FAILS_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status),
                            status,
                            "'coll2' has an encryptedFields configured, but collection 'coll' has a JSON schema");
        _mongocrypt_cache_cleanup(&cache);
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds one QE schema with `encryptionInformation`.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSONF(
            BSON_STR({"find" : "coll", "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON}}}),
            encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds multiple QE schemas with `encryptionInformation`.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect =
            TMP_BSONF(BSON_STR({
                          "find" : "coll",
                          "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON, "db.coll2" : MC_BSON}}
                      }),
                      encryptedFields,
                      encryptedFields2);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Does not add CSFLE schemas when command is targeted for mongod/mongos.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_schemaMap(sb, schemaMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds QE schema into nsInfo for bulkWrite.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"bulkWrite" : "coll", "nsInfo" : [ {"ns" : "db.coll"} ]}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSONF(
            BSON_STR({
                "bulkWrite" : "coll",
                "nsInfo" :
                    [ {"ns" : "db.coll", "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON}}} ]
            }),
            encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds empty encryptedFields when no collections have schemas and using the `bulkWrite` command.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"bulkWrite" : "coll", "nsInfo" : [ {"ns" : "db.coll"} ]}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSON(BSON_STR({
            "bulkWrite" : "coll",
            "nsInfo" : [ {
                "ns" : "db.coll",
                "encryptionInformation" : {
                    "type" : {"$numberInt" : "1"},
                    "schema" : {
                        "db.coll" : {
                            "escCollection" : "enxcol_.coll.esc",
                            "ecocCollection" : "enxcol_.coll.ecoc",
                            "fields" : []
                        }
                    }
                }
            } ]
        }));
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds at top-level for "explain" to mongocryptd.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"explain" : {"find" : "coll"}}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_MONGOCRYPTD, status), status);
        bson_t *expect = TMP_BSONF(BSON_STR({
                                       "explain" : {"find" : "coll"},
                                       "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON}}
                                   }),
                                   encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds nested in "explain" for mongod.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"explain" : {"find" : "coll"}}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSONF(
            BSON_STR({
                "explain" : {"find" : "coll", "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON}}}
            }),
            encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds nested in "explain" for crypt_shared.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"explain" : {"find" : "coll"}}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_CRYPT_SHARED, status), status);
        bson_t *expect = TMP_BSONF(
            BSON_STR({
                "explain" : {"find" : "coll", "encryptionInformation" : {"type" : 1, "schema" : {"db.coll" : MC_BSON}}}
            }),
            encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Adds empty QE schema in 'encryptionInformation' when one collection has a QE schema and other does not.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "noschema", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSONF(BSON_STR({
                                       "find" : "coll",
                                       "encryptionInformation" : {
                                           "type" : 1,
                                           "schema" : {
                                               "db.coll" : MC_BSON,
                                               "db.noschema" : {
                                                   "escCollection" : "enxcol_.noschema.esc",
                                                   "ecocCollection" : "enxcol_.noschema.ecoc",
                                                   "fields" : []
                                               }
                                           }
                                       }
                                   }),
                                   encryptedFields);
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Applies default state collections for QE schema passed in encryptedFieldsMap.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(
            mc_schema_broker_satisfy_from_encryptedFieldsMap(sb,
                                                             TMP_BSON(BSON_STR({"db.coll" : {"fields" : []}})),
                                                             status),
            status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        bson_t *cmd = TMP_BSON(BSON_STR({"find" : "coll"}));
        ASSERT_OK_STATUS(mc_schema_broker_add_schemas_to_cmd(sb, cmd, MC_CMD_SCHEMAS_FOR_SERVER, status), status);
        bson_t *expect = TMP_BSONF(BSON_STR({
            "find" : "coll",
            "encryptionInformation" : {
                "type" : 1,
                "schema" : {
                    "db.coll" :
                        {"fields" : [], "escCollection" : "enxcol_.coll.esc", "ecocCollection" : "enxcol_.coll.ecoc"}
                }
            }
        }));
        ASSERT_EQUAL_BSON(expect, cmd);

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    bson_destroy(encryptedFieldsMap);
}

static void test_mc_schema_broker_get_encryptedFields(_mongocrypt_tester_t *tester) {
    bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");

    // Can find.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        const mc_EncryptedFieldConfig_t *efc = mc_schema_broker_get_encryptedFields(sb, "coll", status);
        ASSERT_OK_STATUS(efc, status);
        // Check one field of returned mc_EncryptedFieldConfig_t.
        ASSERT_STREQUAL(efc->fields->path, "encryptedIndexed");
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Reports error if not found.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));

        const mc_EncryptedFieldConfig_t *efc = mc_schema_broker_get_encryptedFields(sb, "does-not-exist", status);
        ASSERT_FAILS_STATUS(efc, status, "Expected encryptedFields");
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_satisfy_from_create_or_collMod(_mongocrypt_tester_t *tester) {
    bson_t *cmd = TEST_FILE_AS_BSON("./test/data/schema-broker/create-with-jsonSchema.json");

    // Can satisfy.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_create_or_collMod(sb, cmd, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Ignores schema for an unrequested collection.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll2", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_create_or_collMod(sb, cmd, status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb)); // Request for db.coll2 is still not satisfied.
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Ignores schema for an already-satisfied collection.
    {
        bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT(mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_create_or_collMod(sb, cmd, status), status);
        ASSERT(!mc_schema_broker_need_more_schemas(sb));
        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

static void test_mc_schema_broker_has_any_qe_schemas(_mongocrypt_tester_t *tester) {
    bson_t *encryptedFieldsMap = TEST_FILE_AS_BSON("./test/data/schema-broker/encryptedFieldsMap.json");

    // Works.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_from_encryptedFieldsMap(sb, encryptedFieldsMap, status), status);
        ASSERT(mc_schema_broker_has_any_qe_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }

    // Returns false if no QE schema.
    {
        mongocrypt_status_t *status = mongocrypt_status_new();
        mc_schema_broker_t *sb = mc_schema_broker_new();

        ASSERT_OK_STATUS(mc_schema_broker_request(sb, "db", "coll", status), status);
        ASSERT_OK_STATUS(mc_schema_broker_satisfy_remaining_with_empty_schemas(sb, NULL, status), status);
        ASSERT(!mc_schema_broker_has_any_qe_schemas(sb));

        mc_schema_broker_destroy(sb);
        mongocrypt_status_destroy(status);
    }
}

void _mongocrypt_tester_install_mc_schema_broker(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(test_mc_schema_broker_request);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_collInfo);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_cache);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_schemaMap);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_encryptedFieldsMap);
    INSTALL_TEST(test_mc_schema_broker_satisfy_remaining_with_empty_schemas);
    INSTALL_TEST(test_mc_schema_broker_add_schemas_to_cmd);
    INSTALL_TEST(test_mc_schema_broker_get_encryptedFields);
    INSTALL_TEST(test_mc_schema_broker_satisfy_from_create_or_collMod);
    INSTALL_TEST(test_mc_schema_broker_has_any_qe_schemas);
}
