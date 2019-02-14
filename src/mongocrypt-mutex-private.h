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

#ifndef MONGOCRYPT_MUTEX_PRIVATE_H
#define MONGOCRYPT_MUTEX_PRIVATE_H

#include <bson/bson.h>

#if defined(BSON_OS_UNIX)
#include <pthread.h>
#define mongocrypt_mutex_destroy pthread_mutex_destroy
#define mongocrypt_mutex_init(_n) pthread_mutex_init ((_n), NULL)
#define mongocrypt_mutex_lock pthread_mutex_lock
#define mongocrypt_mutex_t pthread_mutex_t
#define mongocrypt_mutex_unlock pthread_mutex_unlock
#else
#define mongocrypt_mutex_destroy DeleteCriticalSection
#define mongocrypt_mutex_init InitializeCriticalSection
#define mongocrypt_mutex_lock EnterCriticalSection
#define mongocrypt_mutex_t CRITICAL_SECTION
#define mongocrypt_mutex_unlock LeaveCriticalSection
#endif


#endif /* MONGOCRYPT_MUTEX_PRIVATE_H */
