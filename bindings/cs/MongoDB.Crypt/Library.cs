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
    /// The low-level interface to libmongocrypt.
    /// </summary>
    public class Library
    {
        static Library()
        {
            LibraryLoader loader = new LibraryLoader();

            mongocrypt_version = loader.GetFunction<Delegates.mongocrypt_version>("mongocrypt_version");

            mongocrypt_new = loader.GetFunction<Delegates.mongocrypt_new>("mongocrypt_new");
            mongocrypt_init = loader.GetFunction<Delegates.mongocrypt_init>("mongocrypt_init");
            mongocrypt_destroy = loader.GetFunction<Delegates.mongocrypt_destroy>("mongocrypt_destroy");
            mongocrypt_status = loader.GetFunction<Delegates.mongocrypt_status>("mongocrypt_status");

            mongocrypt_setopt_kms_provider_aws = loader.GetFunction<Delegates.mongocrypt_setopt_kms_provider_aws>("mongocrypt_setopt_kms_provider_aws");
            mongocrypt_setopt_kms_provider_local = loader.GetFunction<Delegates.mongocrypt_setopt_kms_provider_local>("mongocrypt_setopt_kms_provider_local");
            mongocrypt_setopt_log_handler = loader.GetFunction<Delegates.mongocrypt_setopt_log_handler>("mongocrypt_setopt_log_handler");

            mongocrypt_status_new = loader.GetFunction<Delegates.mongocrypt_status_new>("mongocrypt_status_new");
            mongocrypt_status_destroy = loader.GetFunction<Delegates.mongocrypt_status_destroy>("mongocrypt_status_destroy");
            mongocrypt_status_type = loader.GetFunction<Delegates.mongocrypt_status_type>("mongocrypt_status_type");
            mongocrypt_status_code = loader.GetFunction<Delegates.mongocrypt_status_code>("mongocrypt_status_code");
            mongocrypt_status_message = loader.GetFunction<Delegates.mongocrypt_status_message>("mongocrypt_status_message");
            mongocrypt_status_ok = loader.GetFunction<Delegates.mongocrypt_status_ok>("mongocrypt_status_ok");

            mongocrypt_binary_new = loader.GetFunction<Delegates.mongocrypt_binary_new>("mongocrypt_binary_new");
            mongocrypt_binary_destroy = loader.GetFunction<Delegates.mongocrypt_binary_destroy>("mongocrypt_binary_destroy");
            mongocrypt_binary_new_from_data = loader.GetFunction<Delegates.mongocrypt_binary_new_from_data>("mongocrypt_binary_new_from_data");
            mongocrypt_binary_data = loader.GetFunction<Delegates.mongocrypt_binary_data>("mongocrypt_binary_data");
            mongocrypt_binary_len = loader.GetFunction<Delegates.mongocrypt_binary_len>("mongocrypt_binary_len");

            mongocrypt_ctx_new = loader.GetFunction<Delegates.mongocrypt_ctx_new>("mongocrypt_ctx_new");
            mongocrypt_ctx_setopt_masterkey_aws = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_masterkey_aws>("mongocrypt_ctx_setopt_masterkey_aws");
            mongocrypt_ctx_setopt_schema = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_schema>("mongocrypt_ctx_setopt_schema");
            mongocrypt_ctx_setopt_masterkey_local = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_masterkey_local>("mongocrypt_ctx_setopt_masterkey_local");
            mongocrypt_ctx_setopt_key_id = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_key_id>("mongocrypt_ctx_setopt_key_id");
            mongocrypt_ctx_setopt_algorithm = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_algorithm>("mongocrypt_ctx_setopt_algorithm"); mongocrypt_ctx_status = loader.GetFunction<Delegates.mongocrypt_ctx_status>("mongocrypt_ctx_status");
            mongocrypt_ctx_setopt_initialization_vector = loader.GetFunction<Delegates.mongocrypt_ctx_setopt_initialization_vector>("mongocrypt_ctx_setopt_initialization_vector"); mongocrypt_ctx_status = loader.GetFunction<Delegates.mongocrypt_ctx_status>("mongocrypt_ctx_status");
            mongocrypt_ctx_encrypt_init = loader.GetFunction<Delegates.mongocrypt_ctx_encrypt_init>("mongocrypt_ctx_encrypt_init");
            mongocrypt_ctx_decrypt_init = loader.GetFunction<Delegates.mongocrypt_ctx_decrypt_init>("mongocrypt_ctx_decrypt_init");
            mongocrypt_ctx_explicit_encrypt_init = loader.GetFunction<Delegates.mongocrypt_ctx_explicit_encrypt_init>("mongocrypt_ctx_explicit_encrypt_init");
            mongocrypt_ctx_explicit_decrypt_init = loader.GetFunction<Delegates.mongocrypt_ctx_explicit_decrypt_init>("mongocrypt_ctx_explicit_decrypt_init");
            mongocrypt_ctx_datakey_init = loader.GetFunction<Delegates.mongocrypt_ctx_datakey_init>("mongocrypt_ctx_datakey_init");
            mongocrypt_ctx_state = loader.GetFunction<Delegates.mongocrypt_ctx_state>("mongocrypt_ctx_state");
            mongocrypt_ctx_mongo_op = loader.GetFunction<Delegates.mongocrypt_ctx_mongo_op>("mongocrypt_ctx_mongo_op");
            mongocrypt_ctx_mongo_feed = loader.GetFunction<Delegates.mongocrypt_ctx_mongo_feed>("mongocrypt_ctx_mongo_feed");
            mongocrypt_ctx_mongo_done = loader.GetFunction<Delegates.mongocrypt_ctx_mongo_done>("mongocrypt_ctx_mongo_done");

            mongocrypt_ctx_next_kms_ctx = loader.GetFunction<Delegates.mongocrypt_ctx_next_kms_ctx>("mongocrypt_ctx_next_kms_ctx");
            mongocrypt_kms_ctx_endpoint = loader.GetFunction<Delegates.mongocrypt_kms_ctx_endpoint>("mongocrypt_kms_ctx_endpoint");
            mongocrypt_kms_ctx_message = loader.GetFunction<Delegates.mongocrypt_kms_ctx_message>("mongocrypt_kms_ctx_message");
            mongocrypt_kms_ctx_bytes_needed = loader.GetFunction<Delegates.mongocrypt_kms_ctx_bytes_needed>("mongocrypt_kms_ctx_bytes_needed");
            mongocrypt_kms_ctx_feed = loader.GetFunction<Delegates.mongocrypt_kms_ctx_feed>("mongocrypt_kms_ctx_feed");
            mongocrypt_kms_ctx_status = loader.GetFunction<Delegates.mongocrypt_kms_ctx_status>("mongocrypt_kms_ctx_status");
            mongocrypt_ctx_kms_done = loader.GetFunction<Delegates.mongocrypt_ctx_kms_done>("mongocrypt_ctx_kms_done");

            mongocrypt_ctx_finalize = loader.GetFunction<Delegates.mongocrypt_ctx_finalize>("mongocrypt_ctx_finalize");
            mongocrypt_ctx_destroy = loader.GetFunction<Delegates.mongocrypt_ctx_destroy>("mongocrypt_ctx_destroy");
        }

        /// <summary>
        /// Gets the version of libmongocrypt.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        public static string Version
        {
            get
            {
                uint length;
                IntPtr p = mongocrypt_version(out length);
                return Marshal.PtrToStringAnsi(p);
            }
        }

        internal static readonly Delegates.mongocrypt_version mongocrypt_version;

        internal static readonly Delegates.mongocrypt_new mongocrypt_new;
        internal static readonly Delegates.mongocrypt_setopt_log_handler mongocrypt_setopt_log_handler;
        internal static readonly Delegates.mongocrypt_setopt_kms_provider_aws mongocrypt_setopt_kms_provider_aws;
        internal static readonly Delegates.mongocrypt_setopt_kms_provider_local mongocrypt_setopt_kms_provider_local;

        internal static readonly Delegates.mongocrypt_init mongocrypt_init;
        internal static readonly Delegates.mongocrypt_destroy mongocrypt_destroy;
        internal static readonly Delegates.mongocrypt_status mongocrypt_status;


        internal static readonly Delegates.mongocrypt_status_new mongocrypt_status_new;
        internal static readonly Delegates.mongocrypt_status_destroy mongocrypt_status_destroy;

        internal static readonly Delegates.mongocrypt_status_type mongocrypt_status_type;
        internal static readonly Delegates.mongocrypt_status_code mongocrypt_status_code;
        internal static readonly Delegates.mongocrypt_status_message mongocrypt_status_message;
        internal static readonly Delegates.mongocrypt_status_ok mongocrypt_status_ok;

        internal static readonly Delegates.mongocrypt_binary_new mongocrypt_binary_new;
        internal static readonly Delegates.mongocrypt_binary_destroy mongocrypt_binary_destroy;
        internal static readonly Delegates.mongocrypt_binary_new_from_data mongocrypt_binary_new_from_data;
        internal static readonly Delegates.mongocrypt_binary_data mongocrypt_binary_data;
        internal static readonly Delegates.mongocrypt_binary_len mongocrypt_binary_len;

        internal static readonly Delegates.mongocrypt_ctx_new mongocrypt_ctx_new;
        internal static readonly Delegates.mongocrypt_ctx_setopt_masterkey_aws mongocrypt_ctx_setopt_masterkey_aws;
        internal static readonly Delegates.mongocrypt_ctx_status mongocrypt_ctx_status;
        internal static readonly Delegates.mongocrypt_ctx_encrypt_init mongocrypt_ctx_encrypt_init;
        internal static readonly Delegates.mongocrypt_ctx_decrypt_init mongocrypt_ctx_decrypt_init;
        internal static readonly Delegates.mongocrypt_ctx_explicit_encrypt_init mongocrypt_ctx_explicit_encrypt_init;
        internal static readonly Delegates.mongocrypt_ctx_explicit_decrypt_init mongocrypt_ctx_explicit_decrypt_init;
        internal static readonly Delegates.mongocrypt_ctx_datakey_init mongocrypt_ctx_datakey_init;
        internal static readonly Delegates.mongocrypt_ctx_setopt_schema mongocrypt_ctx_setopt_schema;
        internal static readonly Delegates.mongocrypt_ctx_setopt_masterkey_local mongocrypt_ctx_setopt_masterkey_local;
        internal static readonly Delegates.mongocrypt_ctx_setopt_key_id mongocrypt_ctx_setopt_key_id;
        internal static readonly Delegates.mongocrypt_ctx_setopt_algorithm mongocrypt_ctx_setopt_algorithm;
        internal static readonly Delegates.mongocrypt_ctx_setopt_initialization_vector mongocrypt_ctx_setopt_initialization_vector;

        internal static readonly Delegates.mongocrypt_ctx_state mongocrypt_ctx_state;
        internal static readonly Delegates.mongocrypt_ctx_mongo_op mongocrypt_ctx_mongo_op;
        internal static readonly Delegates.mongocrypt_ctx_mongo_feed mongocrypt_ctx_mongo_feed;
        internal static readonly Delegates.mongocrypt_ctx_mongo_done mongocrypt_ctx_mongo_done;

        internal static readonly Delegates.mongocrypt_ctx_next_kms_ctx mongocrypt_ctx_next_kms_ctx;
        internal static readonly Delegates.mongocrypt_kms_ctx_endpoint mongocrypt_kms_ctx_endpoint;
        internal static readonly Delegates.mongocrypt_kms_ctx_message mongocrypt_kms_ctx_message;
        internal static readonly Delegates.mongocrypt_kms_ctx_bytes_needed mongocrypt_kms_ctx_bytes_needed;
        internal static readonly Delegates.mongocrypt_kms_ctx_feed mongocrypt_kms_ctx_feed;
        internal static readonly Delegates.mongocrypt_kms_ctx_status mongocrypt_kms_ctx_status;
        internal static readonly Delegates.mongocrypt_ctx_kms_done mongocrypt_ctx_kms_done;
        internal static readonly Delegates.mongocrypt_ctx_finalize mongocrypt_ctx_finalize;
        internal static readonly Delegates.mongocrypt_ctx_destroy mongocrypt_ctx_destroy;

        internal enum ErrorType
        {
            MONGOCRYPT_type_NONE = 0,
            MONGOCRYPT_type_MONGOCRYPTD,
            MONGOCRYPT_type_KMS,
            MONGOCRYPT_type_CLIENT
        }

        internal class Delegates
        {
            // NOTE: Bool is expected to be 4 bytes during marshalling so we need to overwite it
            // https://blogs.msdn.microsoft.com/jaredpar/2008/10/14/pinvoke-and-bool-or-should-i-say-bool/
            public delegate IntPtr mongocrypt_version(out uint length);

            public delegate MongoCryptSafeHandle mongocrypt_new();

            public delegate void LogCallback([MarshalAs(UnmanagedType.I4)]LogLevel level, IntPtr messasge, uint message_length, IntPtr context);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_setopt_log_handler(MongoCryptSafeHandle handle, [MarshalAs(UnmanagedType.FunctionPtr)]LogCallback log_fn, IntPtr log_ctx);
            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_setopt_kms_provider_aws(MongoCryptSafeHandle handle, [MarshalAs(UnmanagedType.LPStr)]string aws_access_key_id, int aws_access_key_id_len, [MarshalAs(UnmanagedType.LPStr)] string aws_secret_access_key, int aws_secret_access_key_len);
            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_setopt_kms_provider_local(MongoCryptSafeHandle handle, BinarySafeHandle key);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_init(MongoCryptSafeHandle handle);
            public delegate void mongocrypt_destroy(IntPtr ptr);
            public delegate bool mongocrypt_status(MongoCryptSafeHandle handle, StatusSafeHandle ptr);

            public delegate StatusSafeHandle mongocrypt_status_new();
            public delegate void mongocrypt_status_destroy(IntPtr ptr);
            public delegate ErrorType mongocrypt_status_type(StatusSafeHandle ptr);
            public delegate uint mongocrypt_status_code(StatusSafeHandle ptr);
            public delegate IntPtr mongocrypt_status_message(StatusSafeHandle ptr, out uint length);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_status_ok(StatusSafeHandle ptr);

            public delegate BinarySafeHandle mongocrypt_binary_new();
            public delegate void mongocrypt_binary_destroy(IntPtr ptr);
            public delegate BinarySafeHandle mongocrypt_binary_new_from_data(IntPtr ptr, uint len);
            public delegate IntPtr mongocrypt_binary_data(BinarySafeHandle handle);
            public delegate uint mongocrypt_binary_len(BinarySafeHandle handle);

            public delegate ContextSafeHandle mongocrypt_ctx_new(MongoCryptSafeHandle handle);
            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_ctx_setopt_masterkey_aws(ContextSafeHandle handle, IntPtr region, int region_len, IntPtr cmk, int cmk_len);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_status(ContextSafeHandle handle, StatusSafeHandle status);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_encrypt_init(ContextSafeHandle handle, IntPtr ns, int length);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_decrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_explicit_encrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_explicit_decrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_datakey_init(ContextSafeHandle handle);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_schema(ContextSafeHandle handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_masterkey_local(ContextSafeHandle handle);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_key_id(ContextSafeHandle handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_algorithm(ContextSafeHandle handle, [MarshalAs(UnmanagedType.LPStr)]string algorithm, int length);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_initialization_vector(ContextSafeHandle handle, BinarySafeHandle binary);
            public delegate CryptContext.StateCode mongocrypt_ctx_state(ContextSafeHandle handle);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_mongo_op(ContextSafeHandle handle, BinarySafeHandle bsonOp);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_mongo_feed(ContextSafeHandle handle, BinarySafeHandle reply);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_mongo_done(ContextSafeHandle handle);

            public delegate IntPtr mongocrypt_ctx_next_kms_ctx(ContextSafeHandle handle);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_kms_ctx_endpoint(IntPtr handle, ref IntPtr endpoint);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_kms_ctx_message(IntPtr handle, BinarySafeHandle binary);
            public delegate uint mongocrypt_kms_ctx_bytes_needed(IntPtr handle);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_kms_ctx_feed(IntPtr handle, BinarySafeHandle binary);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_kms_ctx_status(IntPtr handle, StatusSafeHandle status);
            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_kms_done(ContextSafeHandle handle);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_finalize(ContextSafeHandle handle, BinarySafeHandle binary);
            public delegate void mongocrypt_ctx_destroy(IntPtr ptr);
        }
    }
}
