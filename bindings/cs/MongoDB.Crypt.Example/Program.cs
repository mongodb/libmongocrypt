/*
 * Copyright 2018-present MongoDB, Inc.
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
using MongoDB.Bson.IO;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Crypt;
using MongoDB.Driver;
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace drivertest
{
    class BsonUtil
    {
        public static BsonDocument ToDocument(Binary bin)
        {
            MemoryStream stream = new MemoryStream(bin.ToArray());
            using (var jsonReader = new BsonBinaryReader(stream))
            {
                var context = BsonDeserializationContext.CreateRoot(jsonReader);
                return BsonDocumentSerializer.Instance.Deserialize(context);
            }
        }

        public static byte[] ToBytes(BsonDocument doc)
        {
            BsonBinaryWriterSettings settings = new BsonBinaryWriterSettings()
            {
                // C# driver "magically" changes UUIDs underneath by default so tell it not to
                GuidRepresentation = GuidRepresentation.Standard
            };
            return doc.ToBson(null, settings);
        }

        public static BsonDocument Concat(BsonDocument doc1, BsonDocument doc2)
        {
            BsonDocument dest = new BsonDocument();
            BsonDocumentWriter writer = new BsonDocumentWriter(dest);
            var context = BsonSerializationContext.CreateRoot(writer);

            writer.WriteStartDocument();

            foreach (var field in doc1)
            {
                writer.WriteName(field.Name);
                BsonValueSerializer.Instance.Serialize(context, field.Value);
            }

            foreach (var field in doc2)
            {
                writer.WriteName(field.Name);
                BsonValueSerializer.Instance.Serialize(context, field.Value);
            }

            writer.WriteEndDocument();
            return writer.Document;
        }


        public static BsonDocument FromJSON(string str)
        {
            using (var jsonReader = new JsonReader(str))
            {
                var context = BsonDeserializationContext.CreateRoot(jsonReader);
                return BsonDocumentSerializer.Instance.Deserialize(context);
            }
        }
    }

    class MongoCryptDController
    {
        MongoClient _clientCryptD;
        IMongoCollection<BsonDocument> _keyVault;
        Uri _kmsEndpoint;

        public MongoCryptDController(MongoUrl urlCryptD, IMongoCollection<BsonDocument> keyVault, Uri kmsEndpoint)
        {
            _clientCryptD = new MongoClient(urlCryptD);
            _keyVault = keyVault;
            _kmsEndpoint = kmsEndpoint;
        }

        public BsonDocument EncryptCommand(IMongoCollection<BsonDocument> coll, BsonDocument cmd)
        {
            CryptOptions options = new CryptOptions();
            options.KmsCredentials = new AwsKmsCredentials()
            {
                AwsSecretAccessKey = "us-east-1",
                AwsAccessKeyId = "us-east-1",
            };

            using (var foo = CryptClientFactory.Create(options))
            using (var context = foo.StartEncryptionContext(coll.CollectionNamespace.FullName, null))
            {
                return ProcessState(context, coll.Database, cmd);

            }
        }

        public BsonDocument DecryptCommand(IMongoDatabase db, BsonDocument doc)
        {
            CryptOptions options = new CryptOptions();
            options.KmsCredentials = new AwsKmsCredentials()
            {
                AwsSecretAccessKey = "us-east-1",
                AwsAccessKeyId = "us-east-1",
            };

            using (var foo = CryptClientFactory.Create(options))
            using (var context = foo.StartDecryptionContext(BsonUtil.ToBytes(doc)))
            {
                return ProcessState(context, db, null);

            }
        }

        public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Ignore certificate errors when testing against localhost
            return true;
        }

        void DoKmsRequest(KmsRequest request)
        {
            TcpClient tcpClient = new TcpClient();
            tcpClient.Connect(_kmsEndpoint.DnsSafeHost, _kmsEndpoint.Port);
            SslStream stream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate));

            stream.AuthenticateAsClient("localhost");

            Binary bin = request.GetMessage();
            stream.Write(bin.ToArray());


            byte[] buffer = new byte[4096];
            while (request.BytesNeeded > 0)
            {
                MemoryStream memBuffer = new MemoryStream();
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read > 0)
                {
                    memBuffer.Write(buffer, 0, read);
                }
                request.Feed(memBuffer.ToArray());
            }
        }

        private BsonDocument ProcessState(CryptContext context, IMongoDatabase db, BsonDocument cmd)
        {
            BsonDocument ret = cmd;

            while (!context.IsDone)
            {
                Console.WriteLine("\n----------------------------------\nState:" + context.State);
                switch (context.State)
                {
                    case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
                        {
                            var binary = context.GetOperation();
                            var doc = BsonUtil.ToDocument(binary);

                            Console.WriteLine("ListCollections Query: " + doc);

                            ListCollectionsOptions opts = new ListCollectionsOptions()
                            {
                                Filter = new BsonDocumentFilterDefinition<BsonDocument>(doc)
                            };

                            var reply = db.ListCollections(opts);
                            //var reply = _db.RunCommand(doc);

                            var replyDocs = reply.ToList<BsonDocument>();
                            Console.WriteLine("ListCollections Reply: " + replyDocs);

                            foreach (var replyDoc in replyDocs)
                            {
                                context.Feed(BsonUtil.ToBytes(replyDoc));
                            }
                            context.MarkDone();

                            break;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
                        {
                            var binary = context.GetOperation();
                            var schema = BsonUtil.ToDocument(binary);

                            Console.WriteLine("MongoCryptD Query: " + schema);

                            var cryptDB = _clientCryptD.GetDatabase(db.DatabaseNamespace.DatabaseName);

                            var doc = BsonUtil.Concat(cmd, new BsonDocument { { "jsonSchema", schema } });

                            Console.WriteLine("MongoCryptD Query: " + doc);

                            var reply = cryptDB.RunCommand(new BsonDocumentCommand<BsonDocument>(doc));

                            Console.WriteLine("MongoCryptD Reply: " + reply);

                            context.Feed(BsonUtil.ToBytes(reply));
                            context.MarkDone();

                            break;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_MONGO_KEYS:
                        {
                            var binary = context.GetOperation();
                            var doc = BsonUtil.ToDocument(binary);

                            Console.WriteLine("GetKeys Query: " + doc);

                            var reply = _keyVault.Find(new BsonDocumentFilterDefinition<BsonDocument>(doc));

                            var replyDocs = reply.ToList<BsonDocument>();
                            Console.WriteLine("GetKeys Reply: " + replyDocs);

                            foreach (var replyDoc in replyDocs)
                            {
                                context.Feed(BsonUtil.ToBytes(replyDoc));
                            }

                            context.MarkDone();

                            break;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_NEED_KMS:
                        {
                            var requests = context.GetKmsMessageRequests();
                            foreach (var req in requests)
                            {
                                DoKmsRequest(req);
                            }
                            requests.MarkDone();
                            break;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_READY:
                        {
                            Binary b = context.FinalizeForEncryption();
                            Console.WriteLine("Buffer:" + b.ToArray());
                            ret = BsonUtil.ToDocument(b);
                            break;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_DONE:
                        {
                            Console.WriteLine("DONE!!");
                            return ret;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_NOTHING_TO_DO:
                        {
                            Console.WriteLine("NOTHING TO DO");
                            return ret;
                        }
                    case CryptContext.StateCode.MONGOCRYPT_CTX_ERROR:
                        {
                            throw new NotImplementedException();
                        }
                }
            }

            return ret;
        }
    }

    class Program
    {
        static IMongoCollection<BsonDocument> SetupKeyStore(MongoClient client, Guid keyID)
        {
            var dbAdmin = client.GetDatabase("admin");
            var collKeyVault = dbAdmin.GetCollection<BsonDocument>("datakeys");

            // Clear the key vault
            collKeyVault.DeleteMany(new BsonDocumentFilterDefinition<BsonDocument>(new BsonDocument()));

            string secretKeyForMockPrefix = "SECRET";

            MemoryStream ms = new MemoryStream();

            var bytes = Encoding.UTF8.GetBytes(secretKeyForMockPrefix);
            ms.Write(bytes, 0, bytes.Length);
            ms.Write(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, 0, 16);
            var secretKeyForMock = ms.GetBuffer();

            // Add a key
            collKeyVault.InsertOne(new BsonDocument
            {
                {"status" , 1 },
                {"_id" , new BsonBinaryData(keyID.ToByteArray(), BsonBinarySubType.UuidStandard) },

                { "masterKey" , new BsonDocument
                {
                    {        "key", "arn:aws:kms:us-east-1:579766882180:key/89fcc2c4-08b0-4bd9-9f25-e30687b580d0" },
                    { "region", "us-east-1"},
                    { "provider", "aws"},

                }
                },
                { "keyMaterial" , new BsonBinaryData( secretKeyForMock, BsonBinarySubType.Binary) },
            });

            return collKeyVault;
        }

        static IMongoCollection<BsonDocument> SetupTestCollection(MongoClient client, Guid keyID)
        {
            var database = client.GetDatabase("test");

            // Reset state
            database.DropCollection("test");

            var s = new BsonDocument
            {
                {  "$jsonSchema" ,
                    new BsonDocument
                    {
                        {  "type", "object" },
                        { "properties" , new BsonDocument
                        {
                            { "ssn" , new BsonDocument
                            {

                                { "encrypt" , new BsonDocument
                                    {
                                    { "keyId" , new BsonArray( new BsonValue[] { new BsonBinaryData(keyID.ToByteArray(), BsonBinarySubType.UuidStandard) } ) },
                                    {  "bsonType" , "string"},
                                    { "algorithm" , "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic" },
                                    { "initializationVector" , new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 } }
                                    }
                                }
                            }
                            }
                        }
                        }

                    }
                }
            };

            database.CreateCollection("test", new CreateCollectionOptions<BsonDocument>() { Validator = new BsonDocumentFilterDefinition<BsonDocument>(s) });

            return database.GetCollection<BsonDocument>("test");

        }

        static void Main(string[] args)
        {
            // The C# driver transmutes data unless you specify this stupid line!
            BsonDefaults.GuidRepresentation = GuidRepresentation.Standard;

            Console.WriteLine("Using url: " + args);
            Uri kmsURL = new Uri("https://localhost:8000");

            var cryptDUrl = new MongoUrl("mongodb://localhost:1234");
            var client = new MongoClient("mongodb://localhost:27017");

            var keyID = Guid.NewGuid();

            IMongoCollection<BsonDocument> collKeyVault = SetupKeyStore(client, keyID);
            IMongoCollection<BsonDocument> collection = SetupTestCollection(client, keyID);
            var database = collection.Database;


            var controller = new MongoCryptDController(cryptDUrl, collKeyVault, kmsURL);

            // Insert a document with SSN
            var insertDoc = new BsonDocument
            {
                {  "ssn" , "123-45-6789" },
            };

            var insertDocCmd = new BsonDocument
            {
                { "insert" , "test" },
                { "documents", new BsonArray(new BsonValue[] { insertDoc }) }
            };

            var insertEncryptedDoc = new BsonDocument(controller.EncryptCommand(collection, insertDocCmd));

            Console.WriteLine("Insert Doc: " + insertEncryptedDoc);

            insertEncryptedDoc.Remove("$db");
            database.RunCommand(new BsonDocumentCommand<BsonDocument>(insertEncryptedDoc));


            var findDoc = BsonUtil.FromJSON(@"{
'find': 'test',
'filter' :  { '$or': [{ '_id': 1},{ 'ssn': '123-45-6789'}]},
        }");


            var findCmd = new BsonDocumentCommand<BsonDocument>(controller.EncryptCommand(collection, findDoc));

            Console.WriteLine("Find CMD: " + findCmd.Document);

            findCmd.Document.Remove("$db");

            var commandResult = database.RunCommand(findCmd);

            Console.WriteLine("Find Result: " + commandResult);

            var decryptedDocument = controller.DecryptCommand(database, commandResult);

            Console.WriteLine("Find Result (DECRYPTED): " + decryptedDocument);

        }
    }
}
