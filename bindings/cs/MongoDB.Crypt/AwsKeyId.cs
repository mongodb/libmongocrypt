/*
 * Copyright 2019–present MongoDB, Inc.
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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace MongoDB.Crypt
{
    /// <summary>Contains all the information needed to find a AWS KMS CMK.</summary>
    public class AwsKeyId : IKmsKeyId, IInternalKmsKeyId
    {

        /// <summary>
        /// Creates an <see cref="AwsKeyId"/> class.
        /// </summary>
        /// <param name="customerMasterKey">The Amazon Resource Name (ARN) of the customer master key.</param>
        /// <param name="region">The region.</param>
        public AwsKeyId(string customerMasterKey, string region)
        {
            Region = region;
            CustomerMasterKey = customerMasterKey;
            AlternateKeyNameBsonDocuments = new List<byte[]>().AsReadOnly();
        }

        /// <summary>
        /// Creates an <see cref="AwsKeyId"/> class.
        /// </summary>
        /// <param name="customerMasterKey">The customerMasterKey.</param>
        /// <param name="region">The region.</param>
        /// <param name="alternateKeyNamesBsonDocuments">The alternate key names.
        /// Each byte array describes an alternative key name via a BsonDocument in the following format:
        ///  { "keyAltName" : [BSON UTF8 value] }</param>
        public AwsKeyId(string customerMasterKey, string region, IEnumerable<byte[]> alternateKeyNamesBsonDocuments)
        {
            Region = region;
            CustomerMasterKey = customerMasterKey;
            AlternateKeyNameBsonDocuments = alternateKeyNamesBsonDocuments.ToList().AsReadOnly();
        }

        /// <inheritdoc />
        public IReadOnlyList<byte[]> AlternateKeyNameBsonDocuments { get; }

        /// <summary>
        /// Gets the Amazon Resource Name (ARN) of the customer master key.
        /// </summary>
        /// <value>
        /// The Amazon Resource Name (ARN) of the customer master key.
        /// </value>
        public string CustomerMasterKey { get; }

        /// <inheritdoc />
        public KmsType KeyType => KmsType.Aws;

        /// <summary>Gets the region.</summary>
        /// <value>The region.</value>
        public string Region { get; }

        /// <inheritdoc />
        void IInternalKmsKeyId.SetCredentials(ContextSafeHandle context, Status status)
        {
            IntPtr regionPointer = (IntPtr)Marshal.StringToHGlobalAnsi(Region);

            try
            {
                IntPtr keyPointer = (IntPtr)Marshal.StringToHGlobalAnsi(CustomerMasterKey);
                try
                {
                    // Let mongocrypt run strlen
                    context.Check(
                        status,
                        Library.mongocrypt_ctx_setopt_masterkey_aws(context, regionPointer, -1, keyPointer, -1));
                    ((IInternalKmsKeyId) this).SetAlternateKeyNames(context, status);
                }
                finally
                {
                    Marshal.FreeHGlobal(keyPointer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(regionPointer);
            }
        }

        /// <inheritdoc />
        void IInternalKmsKeyId.SetAlternateKeyNames(ContextSafeHandle context, Status status)
        {
            this.SetAlternateKeyNames(context, status);
        }
    }
}
