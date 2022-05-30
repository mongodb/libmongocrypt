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
using System.Collections.ObjectModel;
using System.Linq;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// Options to configure mongocrypt with.
    /// </summary>
    public class CryptOptions
    {
        public bool BypassQueryAnalysis { get; }
        public string CsfleLibPath { get; }
        public string CsfleSearchPath { get; }
        public byte[] EncryptedFieldsMap { get; }
        public bool IsCsfleRequired { get; }
        public IReadOnlyList<KmsCredentials> KmsCredentials { get; }
        public byte[] Schema { get; }

        public CryptOptions(IEnumerable<KmsCredentials> credentials) : this(credentials, null)
        {
        }

        public CryptOptions(
            IEnumerable<KmsCredentials> credentials,
            byte[] schema) : this(credentials, null, schema, false, null, null, false)
        {
        }

        public CryptOptions(
            IEnumerable<KmsCredentials> credentials,
            byte[] encryptedFieldsMap,
            byte[] schema,
            bool bypassQueryAnalysis,
            string csfleLibPath,
            string csfleSearchPath,
            bool isCsfleRequired)
        {
            BypassQueryAnalysis = bypassQueryAnalysis;
            CsfleLibPath = csfleLibPath;
            CsfleSearchPath = csfleSearchPath;
            IsCsfleRequired = isCsfleRequired;
            EncryptedFieldsMap = encryptedFieldsMap;
            KmsCredentials = new ReadOnlyCollection<KmsCredentials>((credentials ?? throw new ArgumentNullException(nameof(credentials))).ToList());
            Schema = schema;
        }

        // TODO: - add configurable logging support
    }
}
