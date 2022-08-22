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

#include "mc-range-edge-generation-private.h"

#include "mc-check-conversions-private.h"
#include "mongocrypt-private.h"

MC_BEGIN_CONVERSION_ERRORS

struct _mc_edges_t {
};

const char *
mc_edges_get (size_t index)
{
   return NULL;
}

size_t
mc_edges_len (mc_edges_t *edges)
{
   return 0;
}

void
mc_edges_destroy (mc_edges_t *edges)
{
}

mc_edges_t *
mc_getEdgesInt32 (mc_getEdgesInt32_args_t args, mongocrypt_status_t *status)
{
   CLIENT_ERR ("mc_getEdgesInt32 is not implemented");
   return false;
}

mc_edges_t *
mc_getEdgesInt64 (mc_getEdgesInt64_args_t args, mongocrypt_status_t *status)
{
   CLIENT_ERR ("mc_getEdgesInt64 is not implemented");
   return false;
}

MC_END_CONVERSION_ERRORS
