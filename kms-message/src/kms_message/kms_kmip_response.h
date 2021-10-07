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

#include "kms_response.h"

/* TODO: consolidate kms_response_t and kms_kmip_request_t into
 * kms_kmip_msg_t? */

/* Caveat, reads the UniqueIdentifier in the first BatchItem it sees.
 * Returns a null terminated string for the UniqueIdentifier. */
KMS_MSG_EXPORT (char*)
kms_kmip_response_get_unique_identifier (kms_response_t *res, kms_status_t *status);

KMS_MSG_EXPORT (uint8_t*)
kms_kmip_response_get_secretdata (kms_response_t *res,
                                  uint32_t *secretdatalen,
                                  kms_status_t *status);

KMS_MSG_EXPORT (void) kms_kmip_response_destroy (kms_response_t *res);

#endif /* KMS_KMIP_RESPONSE_H */