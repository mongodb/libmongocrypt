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

#ifndef KMS_KMIP_REQUEST_H
#define KMS_KMIP_REQUEST_H

#include "kms_status.h"
#include "kms_message_defines.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _kms_kmip_request_t kms_kmip_request_t;

KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_register_secretdata_new (void *reserved,
                                          uint8_t *data,
                                          uint32_t len,
                                          kms_status_t *status);

KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_discover_versions_new (void *reserved, kms_status_t *status);

/* uid is a NULL terminated string. */
KMS_MSG_EXPORT (kms_kmip_request_t *)
kms_kmip_request_get_new (void *reserved, char *uid, kms_status_t *status);

KMS_MSG_EXPORT (uint8_t *)
kms_kmip_request_to_bytes (kms_kmip_request_t *req, uint32_t *len);

KMS_MSG_EXPORT (void)
kms_kmip_request_destroy (kms_kmip_request_t *req);


#endif /* KMS_KMIP_REQUEST_H */