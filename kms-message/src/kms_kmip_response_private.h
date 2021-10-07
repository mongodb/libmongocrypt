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

#ifndef KMS_KMIP_RESPONSE_PRIVATE_H
#define KMS_KMIP_RESPONSE_PRIVATE_H

#include <stdint.h>

/* kms_kmip_response_ok is needed for tests. */
const uint8_t *
kms_response_to_bytes (kms_response_t *res, uint32_t *len);

/* kms_kmip_response_ok is needed for tests. */
bool
kms_kmip_response_ok (kms_response_t *res);

#endif /* KMS_KMIP_RESPONSE_PRIVATE_H */