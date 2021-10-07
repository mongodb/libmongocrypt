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

#ifndef KMS_KMIP_RESPONSE_PARSER_H
#define KMS_KMIP_RESPONSE_PARSER_H

#include "kms_message_defines.h"
#include "kms_status.h"
#include "kms_kmip_response.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct _kms_kmip_response_parser_t kms_kmip_response_parser_t;

KMS_MSG_EXPORT(kms_kmip_response_parser_t *)
kms_kmip_response_parser_new (void);

KMS_MSG_EXPORT(int32_t)
kms_kmip_response_parser_wants_bytes (kms_kmip_response_parser_t *parser, int32_t max);

KMS_MSG_EXPORT(bool)
kms_kmip_response_parser_feed (kms_kmip_response_parser_t *parser, uint8_t *buf, uint32_t len, kms_status_t *status);

KMS_MSG_EXPORT(kms_kmip_response_t *)
kms_kmip_response_parser_get_response (kms_kmip_response_parser_t *parser, kms_status_t *status);

KMS_MSG_EXPORT(void)
kms_kmip_response_parser_destroy (kms_kmip_response_parser_t *parser);

#endif /* KMS_KMIP_RESPONSE_PARSER_H */