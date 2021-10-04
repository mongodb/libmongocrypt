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

struct _kms_status_t {
   kms_request_str_t *data;
   bool error;
};

kms_status_t* kms_status_new () {
   kms_status_t *status = calloc (1, sizeof (kms_status_t));
   return status;
}

bool kms_status_ok (kms_status_t *status) {
   return !status->error;
}

const char* kms_status_to_string (kms_status_t *status) {
   if (!status->data) {
      return "ok";
   }
   return status->data->str;
}

void kms_status_destroy (kms_status_t *status) {
   if (!status) {
      return;
   }
   kms_request_str_destroy (status->data);
   free (status);
}

void kms_status_reset (kms_status_t *status) {
   kms_request_str_destroy (status->data);
   status->data = NULL;
   status->error = false;
}

void kms_status_errorf (kms_status_t *status, const char* format, ...) {
   va_list args;

   va_start (args, format);
   kms_request_str_destroy (status->data);
   status->data = kms_request_str_new ();
   kms_request_str_append_va (status->data, format, args);
   va_end (args);
   status->error = true;
}
