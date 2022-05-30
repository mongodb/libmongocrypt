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
        private static Library.Delegates.CryptoCallback __cryptoAes256EcbEncryptCallback = new Library.Delegates.CryptoCallback(CipherCallbacks.EncryptEcb);
        private static Library.Delegates.CryptoCallback __cryptoAes256CbcDecryptCallback = new Library.Delegates.CryptoCallback(CipherCallbacks.DecryptCbc);
        private static Library.Delegates.CryptoCallback __cryptoAes256CbcEncryptCallback = new Library.Delegates.CryptoCallback(CipherCallbacks.EncryptCbc);
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
            MongoCryptSafeHandle handle = null;
            Status status = null;

            try
            {
                handle = Library.mongocrypt_new();
                status = new Status();

                // The below code can be avoided on Windows. So, we don't call it on this system 
                // to avoid restrictions on target frameworks that present in some of below
                if (OperatingSystemHelper.CurrentOperatingSystem != OperatingSystemPlatform.Windows)
                {
                    handle.Check(
                        status,
                        Library.mongocrypt_setopt_crypto_hooks(
                            handle,
                            __cryptoAes256CbcEncryptCallback,
                            __cryptoAes256CbcDecryptCallback,
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

                    handle.Check(
                        status,
                        Library.mongocrypt_setopt_aes_256_ecb(
                            handle,
                            __cryptoAes256EcbEncryptCallback,
                            IntPtr.Zero));
                }

                foreach (var kmsCredentials in options.KmsCredentials)
                {
                    kmsCredentials.SetCredentials(handle, status);
                }

                if (options.Schema != null)
                {
                    PinnedBinary.HandleAsPinnedBinary(handle, options.Schema, status, (h, pb) => Library.mongocrypt_setopt_schema_map(h, pb));
                }

                if (options.EncryptedFieldsMap != null)
                {
                    PinnedBinary.HandleAsPinnedBinary(handle, options.EncryptedFieldsMap, status, (h, pb) => Library.mongocrypt_setopt_encrypted_field_config_map(h, pb));
                }

                if (options.BypassQueryAnalysis)
                {
                    Library.mongocrypt_setopt_bypass_query_analysis(handle);
                }

                if (options.CsfleLibPath != null)
                {
                    Library.mongocrypt_setopt_set_csfle_lib_path_override(handle, options.CsfleLibPath);
                }

                if (options.CsfleSearchPath != null)
                {
                    Library.mongocrypt_setopt_append_csfle_search_path(handle, options.CsfleSearchPath);
                }

                Library.mongocrypt_init(handle);
            }
            catch (Exception)
            {
                handle?.Dispose();
                status?.Dispose();
                throw;
            }

            return new CryptClient(handle, status);
        }
    }
}
