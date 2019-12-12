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

#include <bson/bson.h>

#include "../mongocrypt-os-private.h"

#ifdef _WIN32

static INIT_ONCE once_control = INIT_ONCE_STATIC_INIT;

static BOOL WINAPI
_mongocrypt_init_once_callback (_Inout_ PINIT_ONCE InitOnce,
                                                    _Inout_opt_ PVOID Parameter,
                                                    _Out_opt_ PVOID *Context)
{
   void (*init_routine) (void) = Parameter;

   init_routine ();

   return (TRUE);
}

int
_mongocrypt_once (void (*init_routine) (void))
{
   PVOID lpContext = NULL;

   return !InitOnceExecuteOnce (
      &once_control, &_mongocrypt_init_once_callback, init_routine, lpContext);
}

#endif /* _WIN32 */