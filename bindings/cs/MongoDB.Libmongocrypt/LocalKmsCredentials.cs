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

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// Local KMS Credentials.
    /// </summary>
    /// <seealso cref="IKmsCredentials" />
    /// <seealso cref="IInternalKmsCredentials" />
    public class LocalKmsCredentials : IKmsCredentials, IInternalKmsCredentials
    {
        /// <summary>
        /// Creates an <see cref="LocalKmsCredentials"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public LocalKmsCredentials(byte[] key)
        {
            Key = key;
        }
        public KmsType KmsType => KmsType.Local;

        /// <summary>
        /// Gets or sets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public byte[] Key { get; }

        void IInternalKmsCredentials.SetCredentials(MongoCryptSafeHandle handle, Status status)
        {
            unsafe
            {
                fixed (byte* p = Key)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)Key.Length))
                    {
                        handle.Check(status, Library.mongocrypt_setopt_kms_provider_local(handle, pinned.Handle));
                    }
                }
            }
        }
    }
}
