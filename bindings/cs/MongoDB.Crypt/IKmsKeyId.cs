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
    /// <summary>
    /// Interface for KMS Key Information
    /// </summary>
    public interface IKmsKeyId
    {
        /// <summary>
        /// Gets the type of the KMS key.
        /// </summary>
        /// <value>
        /// The type of the KMS key.
        /// </value>
        KmsType KeyType { get; }
    }

    /// <summary>
    /// An internal interface that all IKmsKeyId must implement
    /// because methods of an interface cannot have access modifiers.
    /// </summary>
    internal interface IInternalKmsKeyId
    {
        void SetCredentials(ContextSafeHandle handle, Status status);
    }
}
