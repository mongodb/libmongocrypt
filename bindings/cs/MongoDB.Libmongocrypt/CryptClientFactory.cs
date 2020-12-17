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
        // MUST be static fields since otherwise these callbacks can be collected via the garbage collector
        // regardless they're used by mongocrypt level or no
        private static Library.Delegates.CryptoCallback __crypto256DecryptCallback = new Library.Delegates.CryptoCallback(CipherCallbacks.Decrypt);
        private static Library.Delegates.CryptoCallback __crypto256EncryptCallback = new Library.Delegates.CryptoCallback(CipherCallbacks.Encrypt);
        private static Library.Delegates.HashCallback __cryptoHashCallback = new Library.Delegates.HashCallback(HashCallback.Hash);
        private static Library.Delegates.CryptoHmacCallback __cryptoHmacSha256Callback = new Library.Delegates.CryptoHmacCallback(HmacShaCallbacks.HmacSha256);
        private static Library.Delegates.CryptoHmacCallback __cryptoHmacSha512Callback = new Library.Delegates.CryptoHmacCallback(HmacShaCallbacks.HmacSha512);
        private static Library.Delegates.RandomCallback __randomCallback = new Library.Delegates.RandomCallback(SecureRandomCallback.GenerateRandom);
        private static Library.Delegates.CryptoHmacCallback __signRsaesPkcs1HmacCallback = new Library.Delegates.CryptoHmacCallback(SigningRSAESPKCSCallback.RsaSign);

        /// <summary>Creates a CryptClient with the specified options.</summary>
        /// <param name="options">The options.</param>
        /// <returns>A CryptClient</returns>
        public static CryptClient Create(CryptOptions options)
        {
            var handle = Library.mongocrypt_new();

            var status = new Status();

            // The below code can be avoided on Windows. So, we don't call it on this system 
            // to avoid restrictions on target frameworks that present in some of below
            if (OperatingSystemHelper.CurrentOperatingSystem != OperatingSystemPlatform.Windows)
            {
                handle.Check(
                    status,
                    Library.mongocrypt_setopt_crypto_hooks(
                        handle,
                        __crypto256EncryptCallback,
                        __crypto256DecryptCallback,
                        __randomCallback,
                        __cryptoHmacSha512Callback,
                        __cryptoHmacSha256Callback,
                        __cryptoHashCallback,
                        IntPtr.Zero));

                handle.Check(
                    status,
                    Library.mongocrypt_setopt_crypto_hook_sign_rsaes_pkcs1_v1_5(
                        handle,
                        __signRsaesPkcs1HmacCallback, 
                        IntPtr.Zero));
            }

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
