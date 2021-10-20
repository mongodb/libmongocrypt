/*
 * Copyright 2021-present MongoDB, Inc.
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

#ifndef MONGOCRYPT_UTIL_PRIVATE_H
#define MONGOCRYPT_UTIL_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A utility for safely casting from size_t to uint32_t.
 * Returns false if @in exceeds the maximum value of a uint32_t. */
bool
size_to_uint32 (size_t in, uint32_t *out);

#endif /* MONGOCRYPT_UTIL_PRIVATE_H */
