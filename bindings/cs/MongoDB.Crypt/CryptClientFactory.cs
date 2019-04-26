/*
 * Copyright 2019-present MongoDB, Inc.
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

namespace MongoDB.Crypt
{
    /// <summary>
    /// A factory for CryptClients.
    /// </summary>
    public class CryptClientFactory
    {
        /// <summary>Creates the specified options.</summary>
        /// <param name="options">The options.</param>
        /// <returns>A CryptClient</returns>
        public static CryptClient Create(CryptOptions options)
        {
            MongoCryptSafeHandle handle = Library.mongocrypt_new();

            Status status = new Status();

            IInternalKmsCredentials kmsCredentials = (IInternalKmsCredentials)options.KmsCredentials;
            kmsCredentials.SetCredentials(handle,status);

            // TODO - set logger

            Library.mongocrypt_init(handle);

            return new CryptClient(handle, status);
        }
    }
}
