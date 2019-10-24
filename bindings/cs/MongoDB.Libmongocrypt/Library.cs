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
    /// The low-level interface to libmongocrypt.
    /// </summary>
    public class Library
    {
        static Library()
        {
            _mongocrypt_version = new Lazy<Delegates.mongocrypt_version>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_version>("mongocrypt_version"), true);

            _mongocrypt_new = new Lazy<Delegates.mongocrypt_new>(
                    () => __loader.Value.GetFunction<Delegates.mongocrypt_new>(("mongocrypt_new")), true);
            _mongocrypt_init = new Lazy<Delegates.mongocrypt_init>(
                    () => __loader.Value.GetFunction<Delegates.mongocrypt_init>(("mongocrypt_init")), true);
            _mongocrypt_destroy = new Lazy<Delegates.mongocrypt_destroy>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_destroy>(("mongocrypt_destroy")), true);
            _mongocrypt_status = new Lazy<Delegates.mongocrypt_status>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status>(("mongocrypt_status")), true);

            _mongocrypt_setopt_kms_provider_aws = new Lazy<Delegates.mongocrypt_setopt_kms_provider_aws>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_setopt_kms_provider_aws>(
                    ("mongocrypt_setopt_kms_provider_aws")), true);
            _mongocrypt_setopt_kms_provider_local = new Lazy<Delegates.mongocrypt_setopt_kms_provider_local>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_setopt_kms_provider_local>(
                    ("mongocrypt_setopt_kms_provider_local")), true);
            _mongocrypt_setopt_log_handler = new Lazy<Delegates.mongocrypt_setopt_log_handler>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_setopt_log_handler>(
                    ("mongocrypt_setopt_log_handler")), true);
            _mongocrypt_setopt_schema_map = new Lazy<Delegates.mongocrypt_setopt_schema_map>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_setopt_schema_map>(
                    ("mongocrypt_setopt_schema_map")), true);

            _mongocrypt_status_new = new Lazy<Delegates.mongocrypt_status_new>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_new>(("mongocrypt_status_new")), true);
            _mongocrypt_status_destroy = new Lazy<Delegates.mongocrypt_status_destroy>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_destroy>(("mongocrypt_status_destroy")),
                true);
            _mongocrypt_status_type = new Lazy<Delegates.mongocrypt_status_type>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_type>(("mongocrypt_status_type")), true);
            _mongocrypt_status_code = new Lazy<Delegates.mongocrypt_status_code>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_code>(("mongocrypt_status_code")), true);
            _mongocrypt_status_message = new Lazy<Delegates.mongocrypt_status_message>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_message>(("mongocrypt_status_message")),
                true);
            _mongocrypt_status_ok = new Lazy<Delegates.mongocrypt_status_ok>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_status_ok>(("mongocrypt_status_ok")), true);

            _mongocrypt_binary_new = new Lazy<Delegates.mongocrypt_binary_new>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_binary_new>(("mongocrypt_binary_new")), true);
            _mongocrypt_binary_destroy = new Lazy<Delegates.mongocrypt_binary_destroy>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_binary_destroy>(("mongocrypt_binary_destroy")),
                true);
            _mongocrypt_binary_new_from_data = new Lazy<Delegates.mongocrypt_binary_new_from_data>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_binary_new_from_data>(
                    ("mongocrypt_binary_new_from_data")), true);
            _mongocrypt_binary_data = new Lazy<Delegates.mongocrypt_binary_data>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_binary_data>(("mongocrypt_binary_data")), true);
            _mongocrypt_binary_len = new Lazy<Delegates.mongocrypt_binary_len>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_binary_len>(("mongocrypt_binary_len")), true);

            _mongocrypt_ctx_new = new Lazy<Delegates.mongocrypt_ctx_new>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_new>(("mongocrypt_ctx_new")), true);
            _mongocrypt_ctx_setopt_masterkey_aws = new Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_aws>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_masterkey_aws>(
                    ("mongocrypt_ctx_setopt_masterkey_aws")), true);
            _mongocrypt_ctx_setopt_masterkey_aws_endpoint = new Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_aws_endpoint>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_masterkey_aws_endpoint>(
                    ("mongocrypt_ctx_setopt_masterkey_aws_endpoint")), true);
            _mongocrypt_ctx_setopt_masterkey_local = new Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_local>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_masterkey_local>(
                    ("mongocrypt_ctx_setopt_masterkey_local")), true);
            _mongocrypt_ctx_setopt_key_alt_name = new Lazy<Delegates.mongocrypt_ctx_setopt_key_alt_name>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_key_alt_name>(
                    ("mongocrypt_ctx_setopt_key_alt_name")), true);
            _mongocrypt_ctx_setopt_key_id = new Lazy<Delegates.mongocrypt_ctx_setopt_key_id>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_key_id>(
                    ("mongocrypt_ctx_setopt_key_id")), true);

            _mongocrypt_ctx_setopt_algorithm = new Lazy<Delegates.mongocrypt_ctx_setopt_algorithm>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_setopt_algorithm>(
                    ("mongocrypt_ctx_setopt_algorithm")), true);
            _mongocrypt_ctx_status = new Lazy<Delegates.mongocrypt_ctx_status>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_status>(("mongocrypt_ctx_status")), true);
            _mongocrypt_ctx_encrypt_init = new Lazy<Delegates.mongocrypt_ctx_encrypt_init>(
                () => __loader.Value
                    .GetFunction<Delegates.mongocrypt_ctx_encrypt_init>(("mongocrypt_ctx_encrypt_init")), true);
            _mongocrypt_ctx_decrypt_init = new Lazy<Delegates.mongocrypt_ctx_decrypt_init>(
                () => __loader.Value
                    .GetFunction<Delegates.mongocrypt_ctx_decrypt_init>(("mongocrypt_ctx_decrypt_init")), true);
            _mongocrypt_ctx_explicit_encrypt_init = new Lazy<Delegates.mongocrypt_ctx_explicit_encrypt_init>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_explicit_encrypt_init>(
                    ("mongocrypt_ctx_explicit_encrypt_init")), true);
            _mongocrypt_ctx_explicit_decrypt_init = new Lazy<Delegates.mongocrypt_ctx_explicit_decrypt_init>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_explicit_decrypt_init>(
                    ("mongocrypt_ctx_explicit_decrypt_init")), true);
            _mongocrypt_ctx_datakey_init = new Lazy<Delegates.mongocrypt_ctx_datakey_init>(
                () => __loader.Value
                    .GetFunction<Delegates.mongocrypt_ctx_datakey_init>(("mongocrypt_ctx_datakey_init")), true);
            _mongocrypt_ctx_state = new Lazy<Delegates.mongocrypt_ctx_state>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_state>(("mongocrypt_ctx_state")), true);
            _mongocrypt_ctx_mongo_op = new Lazy<Delegates.mongocrypt_ctx_mongo_op>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_mongo_op>(("mongocrypt_ctx_mongo_op")), true);
            _mongocrypt_ctx_mongo_feed = new Lazy<Delegates.mongocrypt_ctx_mongo_feed>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_mongo_feed>(("mongocrypt_ctx_mongo_feed")),
                true);
            _mongocrypt_ctx_mongo_done = new Lazy<Delegates.mongocrypt_ctx_mongo_done>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_mongo_done>(("mongocrypt_ctx_mongo_done")),
                true);

            _mongocrypt_ctx_next_kms_ctx = new Lazy<Delegates.mongocrypt_ctx_next_kms_ctx>(
                () => __loader.Value
                    .GetFunction<Delegates.mongocrypt_ctx_next_kms_ctx>(("mongocrypt_ctx_next_kms_ctx")), true);
            _mongocrypt_kms_ctx_endpoint = new Lazy<Delegates.mongocrypt_kms_ctx_endpoint>(
                () => __loader.Value
                    .GetFunction<Delegates.mongocrypt_kms_ctx_endpoint>(("mongocrypt_kms_ctx_endpoint")), true);
            _mongocrypt_kms_ctx_message = new Lazy<Delegates.mongocrypt_kms_ctx_message>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_kms_ctx_message>(("mongocrypt_kms_ctx_message")),
                true);
            _mongocrypt_kms_ctx_bytes_needed = new Lazy<Delegates.mongocrypt_kms_ctx_bytes_needed>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_kms_ctx_bytes_needed>(
                    ("mongocrypt_kms_ctx_bytes_needed")), true);
            _mongocrypt_kms_ctx_feed = new Lazy<Delegates.mongocrypt_kms_ctx_feed>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_kms_ctx_feed>(("mongocrypt_kms_ctx_feed")), true);
            _mongocrypt_kms_ctx_status = new Lazy<Delegates.mongocrypt_kms_ctx_status>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_kms_ctx_status>(("mongocrypt_kms_ctx_status")),
                true);
            _mongocrypt_ctx_kms_done = new Lazy<Delegates.mongocrypt_ctx_kms_done>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_kms_done>(("mongocrypt_ctx_kms_done")), true);

            _mongocrypt_ctx_finalize = new Lazy<Delegates.mongocrypt_ctx_finalize>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_finalize>(("mongocrypt_ctx_finalize")), true);
            _mongocrypt_ctx_destroy = new Lazy<Delegates.mongocrypt_ctx_destroy>(
                () => __loader.Value.GetFunction<Delegates.mongocrypt_ctx_destroy>(("mongocrypt_ctx_destroy")), true);
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

        internal static Delegates.mongocrypt_version mongocrypt_version => _mongocrypt_version.Value;

        internal static Delegates.mongocrypt_new mongocrypt_new => _mongocrypt_new.Value;
        internal static Delegates.mongocrypt_setopt_log_handler mongocrypt_setopt_log_handler => _mongocrypt_setopt_log_handler.Value;
        internal static Delegates.mongocrypt_setopt_kms_provider_aws mongocrypt_setopt_kms_provider_aws => _mongocrypt_setopt_kms_provider_aws.Value;
        internal static Delegates.mongocrypt_setopt_kms_provider_local mongocrypt_setopt_kms_provider_local => _mongocrypt_setopt_kms_provider_local.Value;
        internal static Delegates.mongocrypt_setopt_schema_map mongocrypt_setopt_schema_map => _mongocrypt_setopt_schema_map.Value;

        internal static Delegates.mongocrypt_init mongocrypt_init => _mongocrypt_init.Value;
        internal static Delegates.mongocrypt_destroy mongocrypt_destroy => _mongocrypt_destroy.Value;
        internal static Delegates.mongocrypt_status mongocrypt_status => _mongocrypt_status.Value;


        internal static Delegates.mongocrypt_status_new mongocrypt_status_new => _mongocrypt_status_new.Value;
        internal static Delegates.mongocrypt_status_destroy mongocrypt_status_destroy => _mongocrypt_status_destroy.Value;

        internal static Delegates.mongocrypt_status_type mongocrypt_status_type => _mongocrypt_status_type.Value;
        internal static Delegates.mongocrypt_status_code mongocrypt_status_code => _mongocrypt_status_code.Value;
        internal static Delegates.mongocrypt_status_message mongocrypt_status_message => _mongocrypt_status_message.Value;
        internal static Delegates.mongocrypt_status_ok mongocrypt_status_ok => _mongocrypt_status_ok.Value;

        internal static Delegates.mongocrypt_binary_new mongocrypt_binary_new => _mongocrypt_binary_new.Value;
        internal static Delegates.mongocrypt_binary_destroy mongocrypt_binary_destroy => _mongocrypt_binary_destroy.Value;
        internal static Delegates.mongocrypt_binary_new_from_data mongocrypt_binary_new_from_data => _mongocrypt_binary_new_from_data.Value;
        internal static Delegates.mongocrypt_binary_data mongocrypt_binary_data => _mongocrypt_binary_data.Value;
        internal static Delegates.mongocrypt_binary_len mongocrypt_binary_len => _mongocrypt_binary_len.Value;

        internal static Delegates.mongocrypt_ctx_new mongocrypt_ctx_new => _mongocrypt_ctx_new.Value;
        internal static Delegates.mongocrypt_ctx_setopt_masterkey_aws mongocrypt_ctx_setopt_masterkey_aws => _mongocrypt_ctx_setopt_masterkey_aws.Value;
        internal static Delegates.mongocrypt_ctx_setopt_masterkey_aws_endpoint mongocrypt_ctx_setopt_masterkey_aws_endpoint => _mongocrypt_ctx_setopt_masterkey_aws_endpoint.Value;
        internal static Delegates.mongocrypt_ctx_status mongocrypt_ctx_status => _mongocrypt_ctx_status.Value;
        internal static Delegates.mongocrypt_ctx_encrypt_init mongocrypt_ctx_encrypt_init => _mongocrypt_ctx_encrypt_init.Value;
        internal static Delegates.mongocrypt_ctx_decrypt_init mongocrypt_ctx_decrypt_init => _mongocrypt_ctx_decrypt_init.Value;
        internal static Delegates.mongocrypt_ctx_explicit_encrypt_init mongocrypt_ctx_explicit_encrypt_init => _mongocrypt_ctx_explicit_encrypt_init.Value;
        internal static Delegates.mongocrypt_ctx_explicit_decrypt_init mongocrypt_ctx_explicit_decrypt_init => _mongocrypt_ctx_explicit_decrypt_init.Value;
        internal static Delegates.mongocrypt_ctx_datakey_init mongocrypt_ctx_datakey_init => _mongocrypt_ctx_datakey_init.Value;
        internal static Delegates.mongocrypt_ctx_setopt_masterkey_local mongocrypt_ctx_setopt_masterkey_local => _mongocrypt_ctx_setopt_masterkey_local.Value;
        internal static Delegates.mongocrypt_ctx_setopt_key_id mongocrypt_ctx_setopt_key_id => _mongocrypt_ctx_setopt_key_id.Value;
        internal static Delegates.mongocrypt_ctx_setopt_key_alt_name mongocrypt_ctx_setopt_key_alt_name => _mongocrypt_ctx_setopt_key_alt_name.Value;
        internal static Delegates.mongocrypt_ctx_setopt_algorithm mongocrypt_ctx_setopt_algorithm => _mongocrypt_ctx_setopt_algorithm.Value;

        internal static Delegates.mongocrypt_ctx_state mongocrypt_ctx_state => _mongocrypt_ctx_state.Value;
        internal static Delegates.mongocrypt_ctx_mongo_op mongocrypt_ctx_mongo_op => _mongocrypt_ctx_mongo_op.Value;
        internal static Delegates.mongocrypt_ctx_mongo_feed mongocrypt_ctx_mongo_feed => _mongocrypt_ctx_mongo_feed.Value;
        internal static Delegates.mongocrypt_ctx_mongo_done mongocrypt_ctx_mongo_done => _mongocrypt_ctx_mongo_done.Value;

        internal static Delegates.mongocrypt_ctx_next_kms_ctx mongocrypt_ctx_next_kms_ctx => _mongocrypt_ctx_next_kms_ctx.Value;
        internal static Delegates.mongocrypt_kms_ctx_endpoint mongocrypt_kms_ctx_endpoint => _mongocrypt_kms_ctx_endpoint.Value;
        internal static Delegates.mongocrypt_kms_ctx_message mongocrypt_kms_ctx_message => _mongocrypt_kms_ctx_message.Value;
        internal static Delegates.mongocrypt_kms_ctx_bytes_needed mongocrypt_kms_ctx_bytes_needed => _mongocrypt_kms_ctx_bytes_needed.Value;
        internal static Delegates.mongocrypt_kms_ctx_feed mongocrypt_kms_ctx_feed => _mongocrypt_kms_ctx_feed.Value;
        internal static Delegates.mongocrypt_kms_ctx_status mongocrypt_kms_ctx_status => _mongocrypt_kms_ctx_status.Value;
        internal static Delegates.mongocrypt_ctx_kms_done mongocrypt_ctx_kms_done => _mongocrypt_ctx_kms_done.Value;
        internal static Delegates.mongocrypt_ctx_finalize mongocrypt_ctx_finalize => _mongocrypt_ctx_finalize.Value;
        internal static Delegates.mongocrypt_ctx_destroy mongocrypt_ctx_destroy => _mongocrypt_ctx_destroy.Value;

        private static readonly Lazy<LibraryLoader> __loader = new Lazy<LibraryLoader>(
            () => new LibraryLoader(), true);
        private static readonly Lazy<Delegates.mongocrypt_version> _mongocrypt_version;
        private static readonly Lazy<Delegates.mongocrypt_new> _mongocrypt_new;
        private static readonly Lazy<Delegates.mongocrypt_setopt_log_handler> _mongocrypt_setopt_log_handler;
        private static readonly Lazy<Delegates.mongocrypt_setopt_kms_provider_aws> _mongocrypt_setopt_kms_provider_aws;

        private static readonly Lazy<Delegates.mongocrypt_setopt_kms_provider_local> _mongocrypt_setopt_kms_provider_local;

        private static readonly Lazy<Delegates.mongocrypt_setopt_schema_map> _mongocrypt_setopt_schema_map;

        private static readonly Lazy<Delegates.mongocrypt_init> _mongocrypt_init;
        private static readonly Lazy<Delegates.mongocrypt_destroy> _mongocrypt_destroy;
        private static readonly Lazy<Delegates.mongocrypt_status> _mongocrypt_status;


        private static readonly Lazy<Delegates.mongocrypt_status_new> _mongocrypt_status_new;
        private static readonly Lazy<Delegates.mongocrypt_status_destroy> _mongocrypt_status_destroy;

        private static readonly Lazy<Delegates.mongocrypt_status_type> _mongocrypt_status_type;
        private static readonly Lazy<Delegates.mongocrypt_status_code> _mongocrypt_status_code;
        private static readonly Lazy<Delegates.mongocrypt_status_message> _mongocrypt_status_message;
        private static readonly Lazy<Delegates.mongocrypt_status_ok> _mongocrypt_status_ok;

        private static readonly Lazy<Delegates.mongocrypt_binary_new> _mongocrypt_binary_new;
        private static readonly Lazy<Delegates.mongocrypt_binary_destroy> _mongocrypt_binary_destroy;
        private static readonly Lazy<Delegates.mongocrypt_binary_new_from_data> _mongocrypt_binary_new_from_data;
        private static readonly Lazy<Delegates.mongocrypt_binary_data> _mongocrypt_binary_data;
        private static readonly Lazy<Delegates.mongocrypt_binary_len> _mongocrypt_binary_len;

        private static readonly Lazy<Delegates.mongocrypt_ctx_new> _mongocrypt_ctx_new;

        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_aws> _mongocrypt_ctx_setopt_masterkey_aws;
        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_aws_endpoint> _mongocrypt_ctx_setopt_masterkey_aws_endpoint;

        private static readonly Lazy<Delegates.mongocrypt_ctx_status> _mongocrypt_ctx_status;
        private static readonly Lazy<Delegates.mongocrypt_ctx_encrypt_init> _mongocrypt_ctx_encrypt_init;
        private static readonly Lazy<Delegates.mongocrypt_ctx_decrypt_init> _mongocrypt_ctx_decrypt_init;

        private static readonly Lazy<Delegates.mongocrypt_ctx_explicit_encrypt_init> _mongocrypt_ctx_explicit_encrypt_init;

        private static readonly Lazy<Delegates.mongocrypt_ctx_explicit_decrypt_init> _mongocrypt_ctx_explicit_decrypt_init;

        private static readonly Lazy<Delegates.mongocrypt_ctx_datakey_init> _mongocrypt_ctx_datakey_init;

        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_masterkey_local> _mongocrypt_ctx_setopt_masterkey_local;

        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_key_id> _mongocrypt_ctx_setopt_key_id;
        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_key_alt_name> _mongocrypt_ctx_setopt_key_alt_name;
        private static readonly Lazy<Delegates.mongocrypt_ctx_setopt_algorithm> _mongocrypt_ctx_setopt_algorithm;

        private static readonly Lazy<Delegates.mongocrypt_ctx_state> _mongocrypt_ctx_state;
        private static readonly Lazy<Delegates.mongocrypt_ctx_mongo_op> _mongocrypt_ctx_mongo_op;
        private static readonly Lazy<Delegates.mongocrypt_ctx_mongo_feed> _mongocrypt_ctx_mongo_feed;
        private static readonly Lazy<Delegates.mongocrypt_ctx_mongo_done> _mongocrypt_ctx_mongo_done;

        private static readonly Lazy<Delegates.mongocrypt_ctx_next_kms_ctx> _mongocrypt_ctx_next_kms_ctx;
        private static readonly Lazy<Delegates.mongocrypt_kms_ctx_endpoint> _mongocrypt_kms_ctx_endpoint;
        private static readonly Lazy<Delegates.mongocrypt_kms_ctx_message> _mongocrypt_kms_ctx_message;
        private static readonly Lazy<Delegates.mongocrypt_kms_ctx_bytes_needed> _mongocrypt_kms_ctx_bytes_needed;
        private static readonly Lazy<Delegates.mongocrypt_kms_ctx_feed> _mongocrypt_kms_ctx_feed;
        private static readonly Lazy<Delegates.mongocrypt_kms_ctx_status> _mongocrypt_kms_ctx_status;
        private static readonly Lazy<Delegates.mongocrypt_ctx_kms_done> _mongocrypt_ctx_kms_done;
        private static readonly Lazy<Delegates.mongocrypt_ctx_finalize> _mongocrypt_ctx_finalize;
        private static readonly Lazy<Delegates.mongocrypt_ctx_destroy> _mongocrypt_ctx_destroy;

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

            public delegate void LogCallback([MarshalAs(UnmanagedType.I4)] LogLevel level, IntPtr messasge,
                uint message_length, IntPtr context);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_setopt_log_handler(MongoCryptSafeHandle handle,
                [MarshalAs(UnmanagedType.FunctionPtr)] LogCallback log_fn, IntPtr log_ctx);

            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_setopt_kms_provider_aws(MongoCryptSafeHandle handle,
                [MarshalAs(UnmanagedType.LPStr)] string aws_access_key_id, int aws_access_key_id_len,
                [MarshalAs(UnmanagedType.LPStr)] string aws_secret_access_key, int aws_secret_access_key_len);

            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool
                mongocrypt_setopt_kms_provider_local(MongoCryptSafeHandle handle, BinarySafeHandle key);

            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_setopt_schema_map(MongoCryptSafeHandle handle, BinarySafeHandle schema);

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
            public delegate bool mongocrypt_ctx_setopt_masterkey_aws(ContextSafeHandle handle, IntPtr region,
                int region_len, IntPtr cmk, int cmk_len);
            [return: MarshalAs(UnmanagedType.I1),]
            public delegate bool mongocrypt_ctx_setopt_masterkey_aws_endpoint(
                ContextSafeHandle handle,
                IntPtr endpoint,
                int endpoint_len);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_status(ContextSafeHandle handle, StatusSafeHandle status);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_encrypt_init(ContextSafeHandle handle, IntPtr ns, int length,
                BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_decrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool
                mongocrypt_ctx_explicit_encrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool
                mongocrypt_ctx_explicit_decrypt_init(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_datakey_init(ContextSafeHandle handle);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_schema_map(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_masterkey_local(ContextSafeHandle handle);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_key_alt_name(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_key_id(ContextSafeHandle handle, BinarySafeHandle binary);

            [return: MarshalAs(UnmanagedType.I1)]
            public delegate bool mongocrypt_ctx_setopt_algorithm(ContextSafeHandle handle,
                [MarshalAs(UnmanagedType.LPStr)] string algorithm, int length);

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
