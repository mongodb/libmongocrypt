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

#include "kms_message/kms_status.h"
#include "kms_request_str.h"
#include "kms_status_private.h"

kms_status_t* kms_status_new () {
   kms_status_t *status = calloc (1, sizeof (kms_status_t));
   return status;
}

bool kms_status_ok (kms_status_t *status) {
   return !status->error;
}

const char* kms_status_to_string (kms_status_t *status) {
   if (!status->error) {
      return "ok";
   }
   return (const char*) status->data;
}

void kms_status_destroy (kms_status_t *status) {
   if (!status) {
      return;
   }
   free (status);
}

void kms_status_reset (kms_status_t *status) {
   memset (status->data, 0, 512);
   status->error = false;
}

