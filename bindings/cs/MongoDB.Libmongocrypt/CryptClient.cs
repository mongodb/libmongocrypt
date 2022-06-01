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
using System.Runtime.InteropServices;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// CryptClient represents a session with libmongocrypt.
    /// 
    /// It can be used to encrypt and decrypt documents.
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public class CryptClient : IDisposable, IStatus
    {
        private MongoCryptSafeHandle _handle;
        private Status _status;

        internal CryptClient(MongoCryptSafeHandle handle, Status status)
        {
            _handle = handle ?? throw new ArgumentNullException(paramName: nameof(handle)); 
            _status = status ?? throw new ArgumentNullException(paramName: nameof(status));
        }

        /// <summary>
        /// Gets the crypt shared library version.
        /// </summary>
        /// <returns>CSFLE version.</returns>
        public string CryptSharedLibraryVersion
        {
            get
            {
                var versionPtr = Library.mongocrypt_crypt_shared_lib_version_string(_handle, out _);
                var result = Marshal.PtrToStringAnsi(versionPtr);

                return result;
            }
        }

        /// <summary>
        /// Starts the create data key context.
        /// </summary>
        /// <param name="keyId">The key identifier.</param>
        /// <returns>A crypt context for creating a data key</returns>
        public CryptContext StartCreateDataKeyContext(KmsKeyId keyId)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            keyId.SetCredentials(handle, _status);

            handle.Check(_status, Library.mongocrypt_ctx_datakey_init(handle));

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the encryption context.
        /// </summary>
        /// <param name="db">The database of the collection.</param>
        /// <param name="command">The command.</param>
        /// <returns>A encryption context.</returns>
        public CryptContext StartEncryptionContext(string db, byte[] command)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            IntPtr stringPointer = (IntPtr)Marshal.StringToHGlobalAnsi(db);

            try
            {
                unsafe
                {
                    fixed (byte* c = command)
                    {
                        var commandPtr = (IntPtr)c;
                        using (var pinnedCommand = new PinnedBinary(commandPtr, (uint)command.Length))
                        {
                            // Let mongocrypt run strlen
                            handle.Check(_status, Library.mongocrypt_ctx_encrypt_init(handle, stringPointer, -1, pinnedCommand.Handle));
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(stringPointer);
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts an explicit encryption context.
        /// </summary>
        /// <param name="key">The key id.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="message">The BSON message.</param>
        /// <returns>A encryption context. </returns>
        public CryptContext StartExplicitEncryptionContextWithKeyId(byte[] keyId, string encryptionAlgorithm, byte[] message)
        {
            return StartExplicitEncryptionContext(keyId, keyAltName: null, queryType: null, contentionFactor: null, encryptionAlgorithm, message);
        }

        /// <summary>
        /// Starts an explicit encryption context.
        /// </summary>
        /// <param name="keyAltName">The alternative key name.</param>
        /// <param name="encryptionAlgorithm">The algorithm.</param>
        /// <param name="message">The BSON message.</param>
        /// <returns>A encryption context. </returns>
        public CryptContext StartExplicitEncryptionContextWithKeyAltName(byte[] keyAltName, string encryptionAlgorithm, byte[] message)
        {
            return StartExplicitEncryptionContext(keyId: null, keyAltName, queryType: null, contentionFactor: null, encryptionAlgorithm, message);
        }

        /// <summary>
        /// Starts an explicit encryption context.
        /// </summary>
        /// <param name="key">The key id.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="message">The BSON message.</param>
        /// <returns>A encryption context. </returns>
        public CryptContext StartExplicitEncryptionContext(byte[] keyId, byte[] keyAltName, int? queryType, long? contentionFactor, string encryptionAlgorithm, byte[] message)
        {
            var handle = Library.mongocrypt_ctx_new(_handle);

            if (keyId != null)
            {
                PinnedBinary.RunAsPinnedBinary(handle, keyId, _status, (h, pb) => Library.mongocrypt_ctx_setopt_key_id(h, pb));
            }
            else if (keyAltName != null)
            {
                PinnedBinary.RunAsPinnedBinary(handle, keyAltName, _status, (h, pb) => Library.mongocrypt_ctx_setopt_key_alt_name(h, pb));
            }

            switch (encryptionAlgorithm)
            {
                case "Indexed":
                    handle.Check(_status, Library.mongocrypt_ctx_setopt_index_type(handle, Library.mongocrypt_index_type_t.MONGOCRYPT_INDEX_TYPE_EQUALITY));
                    break;
                case "Unindexed":
                    handle.Check(_status, Library.mongocrypt_ctx_setopt_index_type(handle, Library.mongocrypt_index_type_t.MONGOCRYPT_INDEX_TYPE_NONE));
                    break;
                default:
                    handle.Check(_status, Library.mongocrypt_ctx_setopt_algorithm(handle, encryptionAlgorithm, -1));
                    break;
            }

            if (queryType.HasValue)
            {
                handle.Check(_status, Library.mongocrypt_ctx_setopt_query_type(handle, (Library.mongocrypt_query_type_t)queryType.Value));
            }

            if (contentionFactor.HasValue)
            {
                var contentionFactorInt = contentionFactor.Value;
                handle.Check(_status, Library.mongocrypt_ctx_setopt_contention_factor(handle, contentionFactorInt));
            }

            PinnedBinary.RunAsPinnedBinary(handle, message, _status, (h, pb) => Library.mongocrypt_ctx_explicit_encrypt_init(h, pb));

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the decryption context.
        /// </summary>
        /// <param name="buffer">The bson document to decrypt.</param>
        /// <returns>A decryption context</returns>
        public CryptContext StartDecryptionContext(byte[] buffer)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            GCHandle gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);

            unsafe
            {
                fixed (byte* p = buffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)buffer.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_decrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts an explicit decryption context.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>A encryption context</returns>
        public CryptContext StartExplicitDecryptionContext(byte[] buffer)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            unsafe
            {
                fixed (byte* p = buffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)buffer.Length))
                    {
                        // Let mongocrypt run strlen
                        handle.Check(_status, Library.mongocrypt_ctx_explicit_decrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        void IStatus.Check(Status status)
        {
            Library.mongocrypt_status(_handle, status.Handle);
        }

        #region IDisposable
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            // Adapted from: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.safehandle?view=netcore-3.0
            if (_handle != null && !_handle.IsInvalid)
            {
                // Free the handle
                _handle.Dispose();
            }

            // Free the status
            _status.Dispose();
        }
        #endregion

        // private methods
        private void Check(bool success)
        {
            if (!success)
            {
                _status.Check(this);
            }
        }
    }
}
