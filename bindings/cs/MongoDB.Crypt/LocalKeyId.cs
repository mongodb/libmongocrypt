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
    /// <summary>Contains all the information needed to describe a Local KMS CMK.</summary>
    public class LocalKeyId : IKmsKeyId, IInternalKmsKeyId
    {
        /// <summary>
        /// Creates an <see cref="LocalKeyId"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public LocalKeyId()
        {
        }

        public KmsType KeyType => KmsType.Local;

        void IInternalKmsKeyId.SetCredentials(ContextSafeHandle handle, Status status)
        {
            handle.Check(status, Library.mongocrypt_ctx_setopt_masterkey_local(handle));
        }
    }
}
