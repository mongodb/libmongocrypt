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
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MongoDB.Crypt
{
    /// <summary>
    /// A pointer and length pair the contains raw bytes to pass or retrive from libmongocrypt.
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public class Binary : IDisposable
    {
        private BinarySafeHandle _handle;

        internal Binary()
        {
            _handle = Library.mongocrypt_binary_new();
        }

        internal Binary(BinarySafeHandle handle)
        {
            _handle = handle;
        }

        /// <summary>
        /// Gets the data.
        /// </summary>
        /// <value>
        /// The data.
        /// </value>
        public IntPtr Data
        {
            get { return Library.mongocrypt_binary_data(_handle); }
        }

        /// <summary>
        /// Gets the length.
        /// </summary>
        /// <value>
        /// The length.
        /// </value>
        public uint Length
        {
            get { return Library.mongocrypt_binary_len(_handle); }
        }

        internal BinarySafeHandle Handle => _handle;

        /// <summary>
        /// Converts to array.
        /// </summary>
        /// <returns></returns>
        public byte[] ToArray()
        {
            byte[] arr = new byte[Length];
            Marshal.Copy(Data, arr, 0, arr.Length);
            return arr;
        }

        /// <summary>
        /// Converts to string.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return Marshal.PtrToStringAnsi(Data);
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
        }
        #endregion
   }
}
