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
    /// A factory for CryptClients.
    /// </summary>
    public class CryptClientFactory
    {
        /// <summary>Creates a CryptClient with the specified options.</summary>
        /// <param name="options">The options.</param>
        /// <returns>A CryptClient</returns>
        public static CryptClient Create(CryptOptions options)
        {
            MongoCryptSafeHandle handle = Library.mongocrypt_new();

            Status status = new Status();

            foreach (var kmsCredentials in options.KmsCredentials)
            {
                kmsCredentials.SetCredentials(handle, status);
            }

            if (options.Schema != null)
            {
                unsafe
                {
                    fixed (byte* schema = options.Schema)
                    {
                        var schemaPtr = (IntPtr)schema;
                        using (var pinnedSchema = new PinnedBinary(schemaPtr, (uint)options.Schema.Length))
                        {
                            handle.Check(status, Library.mongocrypt_setopt_schema_map(handle, schema: pinnedSchema.Handle));
                        }
                    }
                }
            }
            Library.mongocrypt_init(handle);

            return new CryptClient(handle, status);
        }
    }
}
