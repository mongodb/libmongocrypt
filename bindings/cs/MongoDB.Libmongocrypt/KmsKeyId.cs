/*
 * Copyright 2020–present MongoDB, Inc.
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

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// Represent a kms key.
    /// </summary>
    public class KmsKeyId
    {
        private readonly IReadOnlyList<byte[]> _alternateKeyNameBytes;
        private readonly byte[] _dataKeyOptionsBytes;

        /// <summary>
        /// Creates an <see cref="KmsKeyId"/> class.
        /// </summary>
        /// <param name="dataKeyOptionsBytes">The byte representation of dataOptions bson document.</param>
        /// <param name="alternateKeyNameBytes">The byte representation of alternate keyName.</param>
        public KmsKeyId(
            byte[] dataKeyOptionsBytes,
            IEnumerable<byte[]> alternateKeyNameBytes = null)
        {
            _dataKeyOptionsBytes = dataKeyOptionsBytes ?? throw new ArgumentNullException(nameof(dataKeyOptionsBytes));
            _alternateKeyNameBytes = (alternateKeyNameBytes ?? Enumerable.Empty<byte[]>()).ToList().AsReadOnly();
        }

        /// <inheritdoc />
        public IReadOnlyList<byte[]> AlternateKeyNameBytes => _alternateKeyNameBytes;

        // internal methods
        internal void SetAlternateKeyNames(ContextSafeHandle context, Status status)
        {
            foreach (var alternateKeyNameBytes in _alternateKeyNameBytes)
            {
                unsafe
                {
                    fixed (byte* p = alternateKeyNameBytes)
                    {
                        IntPtr ptr = (IntPtr)p;
                        using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)alternateKeyNameBytes.Length))
                        {
                            context.Check(status, Library.mongocrypt_ctx_setopt_key_alt_name(context, pinned.Handle));
                        }
                    }
                }
            }
        }

        internal void SetCredentials(ContextSafeHandle context, Status status)
        {
            unsafe
            {
                fixed (byte* p = _dataKeyOptionsBytes)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)_dataKeyOptionsBytes.Length))
                    {
                        context.Check(status, Library.mongocrypt_ctx_setopt_key_encryption_key(context, pinned.Handle));
                    }
                }
            }
            SetAlternateKeyNames(context, status);
        }
    }
}
