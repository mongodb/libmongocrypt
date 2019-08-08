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

namespace MongoDB.Crypt
{
    /// <summary>
    /// AWS KMS Credentials
    /// </summary>
    /// <seealso cref="MongoDB.Crypt.IKmsCredentials" />
    /// <seealso cref="MongoDB.Crypt.IInternalKmsCredentials" />
    public class AwsKmsCredentials : IKmsCredentials, IInternalKmsCredentials
    {
        public KmsType KmsType => KmsType.Aws;

        /// <summary>
        /// Creates an <see cref="AwsKmsCredentials"/> class.
        /// </summary>
        /// <param name="awsSecretAccessKey">The awsSecretAccessKey.</param>
        /// <param name="awsAccessKeyId">The awsAccessKeyId.</param>
        public AwsKmsCredentials(string awsSecretAccessKey, string awsAccessKeyId)
        {
            AwsSecretAccessKey = awsSecretAccessKey;
            AwsAccessKeyId = awsAccessKeyId;
        }
        /// <summary>
        /// Gets the aws secret access key.
        /// </summary>
        /// <value>
        /// The aws secret access key.
        /// </value>
        public string AwsSecretAccessKey { get; }

        /// <summary>
        /// Gets the aws access key identifier.
        /// </summary>
        /// <value>
        /// The aws access key identifier.
        /// </value>
        public string AwsAccessKeyId { get; }

        void IInternalKmsCredentials.SetCredentials(MongoCryptSafeHandle handle, Status status)
        {
            // Let mongocrypt run strlen
            handle.Check(status, Library.mongocrypt_setopt_kms_provider_aws(handle, AwsAccessKeyId, -1, AwsSecretAccessKey, -1));
        }
    }
}
