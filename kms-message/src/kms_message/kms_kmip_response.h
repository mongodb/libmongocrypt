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

#ifndef KMS_KMIP_RESPONSE_H
#define KMS_KMIP_RESPONSE_H

#include "kms_message_defines.h"
#include "kms_status.h"

#include <stdbool.h>
#include <stdint.h>

/* TODO: consolidate kms_kmip_response_t and kms_kmip_request_t into
 * kms_kmip_msg_t? */
typedef struct _kms_kmip_response_t kms_kmip_response_t;

KMS_MSG_EXPORT (uint8_t *)
kms_kmip_response_to_bytes (kms_kmip_response_t *req, uint32_t *len);

KMS_MSG_EXPORT (void) kms_kmip_response_destroy (kms_kmip_response_t *res);

#endif /* KMS_KMIP_RESPONSE_H */