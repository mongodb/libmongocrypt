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
using System.Runtime.InteropServices;

namespace MongoDB.Crypt
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
            _handle = handle;
            _status = status;
        }

        /// <summary>
        /// Starts the create data key context.
        /// </summary>
        /// <param name="keyId">The key identifier.</param>
        /// <returns>A crypt context for creating a data key</returns>
        public CryptContext StartCreateDataKeyContext(IKmsKeyId keyId)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            IInternalKmsKeyId key = (IInternalKmsKeyId)keyId;
            key.SetCredentials(handle, _status);

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the encryption context.
        /// </summary>
        /// <param name="ns">The namespace of the collection.</param>
        /// <returns>A encryption context</returns>
        public CryptContext StartEncryptionContext(string ns, byte[] schema)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);

            IntPtr stringPointer = (IntPtr)Marshal.StringToHGlobalAnsi(ns);

            if(schema != null)
            {
                unsafe
                {
                    fixed (byte* p = schema)
                    {
                        IntPtr ptr = (IntPtr)p;
                        using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)schema.Length))
                        {
                            handle.Check(_status, Library.mongocrypt_ctx_setopt_schema(handle, pinned.Handle));
                        }
                    }
                }
            }

            try
            {
                // Let mongocrypt run strlen
                handle.Check(_status, Library.mongocrypt_ctx_encrypt_init(handle, stringPointer, -1));
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
        /// <returns>A encryption context</returns>
        public CryptContext StartExplicitEncryptionContext(Guid key, Alogrithm algo, byte[] buffer, byte[] initializationVector)
        {
            ContextSafeHandle handle = Library.mongocrypt_ctx_new(_handle);
            
            byte[] keyBuffer = key.ToByteArray();
            unsafe
            {
                fixed (byte* p = keyBuffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)keyBuffer.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_setopt_key_id(handle, pinned.Handle));
                    }
                }
            }

            handle.Check(_status, Library.mongocrypt_ctx_setopt_algorithm(handle, Helpers.AlgorithmToString(algo), -1));

            if (initializationVector != null)
            {
                unsafe
                {
                    fixed (byte* p = initializationVector)
                    {
                        IntPtr ptr = (IntPtr)p;
                        using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)initializationVector.Length))
                        {
                            handle.Check(_status, Library.mongocrypt_ctx_setopt_initialization_vector(handle, pinned.Handle));
                        }
                    }
                }
            }
            unsafe
            {
                fixed (byte* p = buffer)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)buffer.Length))
                    {
                        handle.Check(_status, Library.mongocrypt_ctx_explicit_encrypt_init(handle, pinned.Handle));
                    }
                }
            }

            return new CryptContext(handle);
        }

        /// <summary>
        /// Starts the decryption context.
        /// </summary>
        /// <param name="buffer">The bson document to decrypt.</param>
        /// <param name="keyId">The key identifier.</param>
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
            if (_handle.IsClosed)
            {
                _handle.Dispose();
            }
        }
        #endregion

        private void Check(bool ret)
        {
            if (!ret)
            {
                _status.Check(this);
            }
        }
    }
}
