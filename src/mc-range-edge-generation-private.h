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

#ifndef MC_RANGE_EDGE_GENERATION_PRIVATE_H
#define MC_RANGE_EDGE_GENERATION_PRIVATE_H

#include <stddef.h> // size_t
#include <stdint.h>
#include "mongocrypt-status-private.h"

typedef struct _mc_edges_t mc_edges_t;

/* mc_edges_get returns edge at an index.
 * Returns NULL if `index` is out of range. */
const char *
mc_edges_get (size_t index);

/* mc_edges_len returns the number of represented edges. */
size_t
mc_edges_len (mc_edges_t *edges);

/* mc_edges_destroys frees `edges`. */
void
mc_edges_destroy (mc_edges_t *edges);

typedef struct {
   bool set;
   int32_t value;
} mc_optional_int32_t;

#define OPT_I32(val)            \
   (mc_optional_int32_t)        \
   {                            \
      .set = true, .value = val \
   }

typedef struct {
   int32_t value;
   mc_optional_int32_t min;
   mc_optional_int32_t max;
} mc_getEdgesInt32_args_t;

mc_edges_t *
mc_getEdgesInt32 (mc_getEdgesInt32_args_t args, mongocrypt_status_t *status);

typedef struct {
   bool set;
   int64_t value;
} mc_optional_int64_t;

#define OPT_I64(val)            \
   (mc_optional_int64_t)        \
   {                            \
      .set = true, .value = val \
   }

typedef struct {
   int64_t value;
   mc_optional_int64_t min;
   mc_optional_int64_t max;
} mc_getEdgesInt64_args_t;

mc_edges_t *
mc_getEdgesInt64 (mc_getEdgesInt64_args_t args, mongocrypt_status_t *status);

#endif /* MC_RANGE_EDGE_GENERATION_PRIVATE_H */
