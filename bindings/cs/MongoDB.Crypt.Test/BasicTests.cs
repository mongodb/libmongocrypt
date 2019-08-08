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

using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;
using System.Text;
using FluentAssertions;
using Xunit.Abstractions;

namespace MongoDB.Crypt.Test
{
    public class BasicTests
    {
        private static ITestOutputHelper _output;

        public BasicTests(ITestOutputHelper output)
        {
            _output = output;
        }
        
        CryptOptions CreateOptions()
        {
            return new CryptOptions(
                new AwsKmsCredentials(
                    awsSecretAccessKey: "us-east-1",
                    awsAccessKeyId: "us-east-1")
            );
        }

        AwsKeyId CreateKey()
        {
            return new AwsKeyId( customerMasterKey: "cmk", region: "us-east-1");
        }

        [Fact]
        public void EncryptQuery()
        {
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context =
                cryptClient.StartEncryptionContext("test", command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {
                var (_, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal((ReadJsonTestFile("encrypted-command.json")));
            }
        }

        [Fact]
        public void EncryptQueryStepwise()
        {
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context = cryptClient.StartEncryptionContext("test", command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {
                var (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO);
                operationSent.Should().Equal((ReadJsonTestFile("list-collections-filter.json")));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
                operationSent.Should().Equal(ReadJsonTestFile("mongocryptd-command.json"));

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationSent.Should().Equal(ReadJsonTestFile("key-filter.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationSent.Should().Equal((ReadJsonTestFile("encrypted-command.json")));
            }
        }

        [Fact]
        public void EncryptQueryWithSchemaStepwise()
        {
            var listCollectionsReply = ReadJsonTestFile("collection-info.json");
            var schema = new BsonDocument("test.test", listCollectionsReply["options"]["validator"]["$jsonSchema"]);

            var options =  new CryptOptions(
                new AwsKmsCredentials(
                    awsSecretAccessKey: "us-east-1",
                    awsAccessKeyId: "us-east-1"),
                BsonUtil.ToBytes(schema)
            );
            using (var cryptClient = CryptClientFactory.Create(options))
            using (var context =
                cryptClient.StartEncryptionContext(
                    db:"test",
                    command: BsonUtil.ToBytes(ReadJsonTestFile("cmd.json"))))
            {

                var (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS);
                var mongoCryptdCommand = ReadJsonTestFile("mongocryptd-command.json");
                mongoCryptdCommand["isRemoteSchema"] = false;
                operationSent.Should().Equal(mongoCryptdCommand);

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationSent.Should().Equal(ReadJsonTestFile("key-filter.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationSent) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationSent.Should().Equal((ReadJsonTestFile("encrypted-command.json")));

            }
        }

        [Fact]
        public void DecryptQuery()
        {
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context =
                cryptClient.StartDecryptionContext(BsonUtil.ToBytes(ReadJsonTestFile("encrypted-command-reply.json"))))
            {
                var (_, bsonCommand) = ProcessContextToCompletion(context);
                bsonCommand.Should().Equal(ReadJsonTestFile("command-reply.json"));
            }
        }

        [Fact]
        public void DecryptQueryStepwise()
        {
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context = cryptClient.StartDecryptionContext(BsonUtil.ToBytes(ReadJsonTestFile("encrypted-command-reply.json"))))
            {
                var (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                operationProduced.Should().Equal(ReadJsonTestFile("key-filter.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                // kms fluent assertions inside ProcessState()

                (state, _, operationProduced) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                operationProduced.Should().Equal(ReadJsonTestFile("command-reply.json"));

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);
            }
        }

        [Fact]
        public void EncryptBadBson()
        {
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            {
                Func<CryptContext> startEncryptionContext = () =>
                    cryptClient.StartEncryptionContext("test",  command: new byte[] {0x1, 0x2, 0x3});

                // Ensure if we encrypt non-sense, it throws an exception demonstrating our exception code is good
                var exception = Record.Exception(startEncryptionContext);

                exception.Should().BeOfType<CryptException>();
            }
        }

        [Fact]
        public void EncryptExplicit()
        {
            var keyDoc = ReadJsonTestFile("key-document.json");
            Guid key = keyDoc["_id"].AsGuid;


            BsonDocument doc = new BsonDocument()
            {
                {  "v" , "hello" },
            };

            var testData = BsonUtil.ToBytes(doc);

            byte[] encryptedBytes;
            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context = cryptClient.StartExplicitEncryptionContext(key, EncryptionAlgorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, testData))
            {
                var (encryptedBinary, encryptedDocument) = ProcessContextToCompletion(context);
                encryptedBytes = encryptedBinary.ToArray(); // need to copy bytes out before the context gets destroyed
            }

            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            using (var context = cryptClient.StartExplicitDecryptionContext(encryptedBytes))
            {
                var (decryptedResult, _) = ProcessContextToCompletion(context);

                decryptedResult.ToArray().Should().Equal(testData);
            }
        }

        [Fact]
        public void EncryptExplicitStepwise()
        {
            var keyDoc = ReadJsonTestFile("key-document.json");
            var key = keyDoc["_id"].AsGuid;

            var doc = new BsonDocument("v", "hello");


            var testData = BsonUtil.ToBytes(doc);

            using (var cryptClient = CryptClientFactory.Create(CreateOptions()))
            {
                byte[] encryptedResult;
                using (var context = cryptClient.StartExplicitEncryptionContext(
                    key: key,
                    encryptionAlgorithm: EncryptionAlgorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    command: testData))
                {
                    var (state, binaryProduced, operationProduced) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS);
                    operationProduced.Should().Equal(ReadJsonTestFile("key-filter.json"));

                    (state, _, _) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS);
                    // kms fluent assertions inside ProcessState()

                    (state, binaryProduced, operationProduced) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                    operationProduced.Should().Equal(ReadJsonTestFile("encrypted-value.json"));
                    encryptedResult = binaryProduced.ToArray(); // need to copy bytes out before the context gets destroyed

                    (state, _, _) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);

                }

                using (var context = cryptClient.StartExplicitDecryptionContext(encryptedResult))
                {
                    var (state, decryptedBinary, _) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                    decryptedBinary.ToArray().Should().Equal(testData);

                    (state, _, _) = ProcessState(context);
                    state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);
                }
            }
        }

        [Fact]
        public void TestLocalKeyCreation()
        {

            var key = new LocalKmsCredentials(new byte[96]);
            var keyId = new LocalKeyId();
            var cryptOptions = new CryptOptions(key);

            using (var cryptClient = CryptClientFactory.Create(cryptOptions))
            using (var context =
                cryptClient.StartCreateDataKeyContext(keyId))
            {
                var (_, dataKeyDocument) = ProcessContextToCompletion(context);
                dataKeyDocument.Should().NotBeNull();
            }
        }


        [Fact]
        public void TestLocalKeyCreationStepwise()
        {

            var key = new LocalKmsCredentials(new byte[96]);
            var keyId = new LocalKeyId();
            var cryptOptions = new CryptOptions(key);

            using (var cryptClient = CryptClientFactory.Create(cryptOptions))
            using (var context =
                cryptClient.StartCreateDataKeyContext(keyId))
            {
                var (state, _, dataKeyDocument) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_READY);
                dataKeyDocument.Should().NotBeNull();

                (state, _, _) = ProcessState(context);
                state.Should().Be(CryptContext.StateCode.MONGOCRYPT_CTX_DONE);
            }
        }

        private (Binary binarySent, BsonDocument document) ProcessContextToCompletion(CryptContext context)
        {
            BsonDocument document = null;
            Binary binary = null;

            while (!context.IsDone)
            {
                (_, binary, document) = ProcessState(context);
            }

            return (binary, document);
        }

        /// <summary>
        /// Processes the current state, simulating the execution the operation/post requests needed to reach the next state
        /// Returns (stateProcessed, binaryOperationProduced, bsonOperationProduced)
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private (CryptContext.StateCode stateProcessed, Binary binaryProduced, BsonDocument bsonOperationProduced) ProcessState(CryptContext context)
        {
            _output.WriteLine("\n----------------------------------\nState:" + context.State);
            switch (context.State)
            {
                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("ListCollections: " + doc);
                    var reply = ReadJsonTestFile("collection-info.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO, binary, doc);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("Markings: " + doc);
                    var reply = ReadJsonTestFile("mongocryptd-reply.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS, binary, doc);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS:
                {
                    var binary = context.GetOperation();
                    var doc = BsonUtil.ToDocument(binary);
                    _output.WriteLine("Key Document: " + doc);
                    var reply = ReadJsonTestFile("key-document.json");
                    _output.WriteLine("Reply:" + reply);
                    context.Feed(BsonUtil.ToBytes(reply));
                    context.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS, binary, doc);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS:
                {
                    var requests = context.GetKmsMessageRequests();
                    foreach (var req in requests)
                    {
                        var binary = req.Message;
                        _output.WriteLine("Key Document: " + binary);
                        var postRequest = binary.ToString();
                        postRequest.Should().Contain("Host:kms.us-east-1.amazonaws.com");

                        var reply = ReadHttpTestFile("kms-decrypt-reply.txt");
                        _output.WriteLine("Reply: " + reply);
                        req.Feed(Encoding.UTF8.GetBytes(reply));
                        req.BytesNeeded.Should().Be(0);
                    }

                    requests.MarkDone();
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_READY:
                {
                    Binary binary = context.FinalizeForEncryption();
                    _output.WriteLine("Buffer:" + binary.ToArray());
                    var document = BsonUtil.ToDocument(binary);
                    _output.WriteLine("Document:" + document);
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_READY, binary, document);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_DONE:
                {
                    _output.WriteLine("DONE!!");
                    return (CryptContext.StateCode.MONGOCRYPT_CTX_DONE, null, null);
                }

                case CryptContext.StateCode.MONGOCRYPT_CTX_ERROR:
                {
                    // We expect exceptions are thrown before we get to this state
                    throw new NotImplementedException();
                }
            }

            throw new NotImplementedException();
        }

        static IEnumerable<string> FindTestDirectories()
        {
            string searchPath = Path.Combine("..", "test", "example");
            var assemblyLocation = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string cwd = Directory.GetCurrentDirectory(); // Assume we are child directory of the repo
            var searchDirectory = assemblyLocation ?? cwd;
            var testDirs = Enumerable.Range(1, 10)
                .Select(i => Enumerable.Repeat("..", i))
                .Select(dotsSeq => dotsSeq.Aggregate(Path.Combine))
                .Select(previousDirectories => Path.Combine(searchDirectory, previousDirectories, searchPath))
                .Where(Directory.Exists)
                .ToArray();

            if (!testDirs.Any())
            {
                throw new DirectoryNotFoundException("test/example");
            }

            return testDirs;
        }


        static string ReadHttpTestFile(string file)
        {
            // The HTTP tests assume \r\n
            // And git strips \r on Unix machines by default so fix up the files

            var text = ReadTestFile(file);

            StringBuilder builder = new StringBuilder(text.Length);
            for(int i = 0; i < text.Length; i++) {
                if(text[i] == '\n' && text[i - 1] != '\r' )
                    builder.Append('\r');
                builder.Append(text[i]);
            }
            return builder.ToString();
        }

        static BsonDocument ReadJsonTestFile(string file)
        {
            var text = ReadTestFile(file);

            if (text == null)
            {
                throw new FileNotFoundException(file);
            }

            // Work around C# drivers and C driver have different extended json support
            text = text.Replace("\"$numberLong\"", "$numberLong");

            return BsonUtil.FromJSON(text);
        }

        static string ReadTestFile(string fileName)
        {
            return FindTestDirectories()
                .Select(directory => Path.Combine(directory, fileName))
                .Where(File.Exists)
                .Select(File.ReadAllText)
                .FirstOrDefault();
        }
    }
}
