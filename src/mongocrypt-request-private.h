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

#ifndef MONGOCRYPT_REQUEST_PRIVATE_H
#define MONGOCRYPT_REQUEST_PRIVATE_H


typedef enum {
   MONGOCRYPT_REQUEST_ENCRYPT,
   MONGOCRYPT_REQUEST_ENCRYPT_VALUE,
   MONGOCRYPT_REQUEST_DECRYPT,
   MONGOCRYPT_REQUEST_DECRYPT_VALUE
} _mongocrypt_request_type_t;


struct _mongocrypt_request_t {
   mongocrypt_t *crypt;
   _mongocrypt_request_type_t type;
   bool has_encryption_placeholders;
   bson_t mongocryptd_reply;
   bson_iter_t result_iter;
   uint32_t num_key_queries;
   /* TODO: do something better for key_query requests.
      Consider copying mongoc_array, vendoring something,
      or just power-of-two growth.
    */
   mongocrypt_key_query_t key_queries[32];
   uint32_t key_query_iter;

   const mongocrypt_binary_t *encrypted_docs;
   uint32_t num_input_docs;
};


#endif /* MONGOCRYPT_REQUEST_PRIVATE_H */
