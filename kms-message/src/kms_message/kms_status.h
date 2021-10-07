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

#ifndef KMS_KMIP_STATUS_H
#define KMS_KMIP_STATUS_H

#include <stdbool.h>
#include <stdint.h>

#include "kms_message_defines.h"
#include "kms_status.h"

/* TODO: File a QOL ticket for adding API to expand and use kms_status_t
 * in more of KMS message API.
 * - Identify the source of the error (client, server).
 * - Add an error code.
 * - Remove limit on message size.
 */

/* kms_status_t is used as output parameter to obtain error information. */
typedef struct _kms_status_t kms_status_t;

/* kms_status_new creates a new empty status. */
KMS_MSG_EXPORT (kms_status_t *) kms_status_new (void);

KMS_MSG_EXPORT (void) kms_status_destroy (kms_status_t *status);

/* kms_status_reset resets a status for reuse. */
KMS_MSG_EXPORT (void) kms_status_reset (kms_status_t *status);

/* kms_status_ok returns true if the status does not represent an error. */
KMS_MSG_EXPORT (bool) kms_status_ok (kms_status_t *status);

/* kms_status_to_string returns a message. */
KMS_MSG_EXPORT (const char *) kms_status_to_string (kms_status_t *status);

#endif /* KMS_KMIP_STATUS_H */