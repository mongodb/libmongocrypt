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

#ifndef KMS_KMIP_ITEM_TYPE_PRIVATE_H
#define KMS_KMIP_ITEM_TYPE_PRIVATE_H

typedef enum {
   KMIP_ITEM_TYPE_Structure = 0x01,
   KMIP_ITEM_TYPE_Integer = 0x02,
   KMIP_ITEM_TYPE_LongInteger = 0x03,
   KMIP_ITEM_TYPE_BigInteger = 0x04,
   KMIP_ITEM_TYPE_Enumeration = 0x05,
   KMIP_ITEM_TYPE_Boolean = 0x06,
   KMIP_ITEM_TYPE_TextString = 0x07,
   KMIP_ITEM_TYPE_ByteString = 0x08,
   KMIP_ITEM_TYPE_DateTime = 0x09,
   KMIP_ITEM_TYPE_Interval = 0x0A
} kmip_item_type_t;

#endif /* KMS_KMIP_ITEM_TYPE_PRIVATE_H */
