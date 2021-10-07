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

#ifndef KMS_STATUS_PRIVATE_H
#define KMS_STATUS_PRIVATE_H

#include "kms_message/kms_status.h"
#include "kms_message_private.h"

struct _kms_status_t {
   char data[512];
   bool error;
};

#define kms_status_errorf(status, ...)                              \
   do {                                                             \
      status->error = true;                                         \
      set_error (status->data, sizeof (status->data), __VA_ARGS__); \
   } while (0)

#endif /* KMS_STATUS_PRIVATE_H */
