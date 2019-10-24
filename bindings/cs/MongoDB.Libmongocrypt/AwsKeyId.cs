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
using System.Linq;
using System.Runtime.InteropServices;

namespace MongoDB.Libmongocrypt
{
    /// <summary>Contains all the information needed to find a AWS KMS CMK.</summary>
    public class AwsKeyId : IKmsKeyId, IInternalKmsKeyId
    {
        /// <summary>
        /// Creates an <see cref="AwsKeyId"/> class.
        /// </summary>
        /// <param name="customerMasterKey">The customerMasterKey.</param>
        /// <param name="region">The region.</param>
        /// <param name="alternateKeyNamesBsonDocuments">The alternate key names.
        /// Each byte array describes an alternative key name via a BsonDocument in the following format:
        ///  { "keyAltName" : [BSON UTF8 value] }</param>
        /// <param name="endpoint">The endpoint.</param>
        public AwsKeyId(
            string customerMasterKey,
            string region,
            IEnumerable<byte[]> alternateKeyNamesBsonDocuments = null,
            string endpoint = null)
        {
            CustomerMasterKey = customerMasterKey;
            Region = region;
            AlternateKeyNameBsonDocuments = (alternateKeyNamesBsonDocuments ?? Enumerable.Empty<byte[]>()).ToList().AsReadOnly();
            Endpoint = endpoint;
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

        /// <summary>
        /// Gets the alternate host to send KMS requests to. May include port number.
        /// </summary>
        /// <value>
        /// The alternate host to send KMS requests to. May include port number.
        /// </value>
        public string Endpoint { get; }

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
                IntPtr customerMasterKeyPointer = (IntPtr)Marshal.StringToHGlobalAnsi(CustomerMasterKey);
                try
                {
                    // Let mongocrypt run strlen
                    context.Check(
                        status,
                        Library.mongocrypt_ctx_setopt_masterkey_aws(context, regionPointer, -1, customerMasterKeyPointer, -1));
                }
                finally
                {
                    Marshal.FreeHGlobal(customerMasterKeyPointer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(regionPointer);
            }

            if (Endpoint != null)
            {
                IntPtr endPointKeyPointer = (IntPtr)Marshal.StringToHGlobalAnsi(Endpoint);
                try
                {
                    // Let mongocrypt run strlen
                    context.Check(
                        status,
                        Library.mongocrypt_ctx_setopt_masterkey_aws_endpoint(context, endPointKeyPointer, -1));
                }
                finally
                {
                    Marshal.FreeHGlobal(endPointKeyPointer);
                }
            }

            ((IInternalKmsKeyId)this).SetAlternateKeyNames(context, status);
        }

        /// <inheritdoc />
        void IInternalKmsKeyId.SetAlternateKeyNames(ContextSafeHandle context, Status status)
        {
            this.SetAlternateKeyNames(context, status);
        }
    }
}
