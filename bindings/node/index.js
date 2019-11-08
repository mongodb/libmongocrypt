'use strict';

/**
 * @module mongodbClientEncryption
 * @description An extension that can be installed to enable MongoDB Client-Side Encryption.
 * @example
 * // Using AutoEncryption
 * 
 * const mongodb = require('mongodb');
 * 
 * // Simply create a MongoClient with the option `autoEncryption`. If
 * // mongodb-client-encryption is installed, it will be automatically
 * // loaded. Your encrypted client will automatically encrypt and decrypt
 * // according to the schema provided by the server.
 * const encryptedClient = new mongodb.MongoClient('mongodb://localhost:27017', {
 *   useNewUrlParser: true,
 *   useUnifiedTopology: true,
 *   autoEncryption: {
 *     kmsProviders: {
 *       aws: {
 *         accessKeyId: AWS_ACCESS_KEY,
 *         secretAccessKey: AWS_SECRET_KEY
 *       }
 *     }
 *   }
 * });
 * 
 * main();
 * 
 * async function main() {
 *   try {
 *     await client.connect();
 *     await client.db('db').collection('coll').insertOne({
 *       name: 'Darmok',
 *       // If encryption is defined as an encrypted value in the collection schema,
 *       // it will be automatically encrypted.
 *       ssn: '123-456-7890'
 *     });
 *     // Additionally, when you query documents with encrypted values, they will automatically
 *     // decrypt when they are retrieved. Here, result.ssn will be a decrypted value.
 *     const result = await client.db('db').collection('coll').findOne({ name: 'Darmok' });
 *   } finally {
 *     await client.close();
 *   }
 * }
 * 
 * @example
 * // Using manual ClientEncryption
 * 
 * const mongodb = require('mongodb');
 * 
 * // Unlike autoEncryption, manual Client Encryption requires you to import 
 * // mongodb-client-encrypion, which returns a function. To access the members of the
 * // extension, you must invoke the function while passing in your mongodb instance.
 * // This returns an object with all members of the extension bound to your mongodb
 * // library.
 * const mongodbClientEncryption = require('mongodb-client-encryption')(mongodb);
 * 
 * // Create a new MongoClient connected to your cluster. This is used by your 
 * const client = new mongodb.MongoClient('mongodb://localhost:27017/', {
 *   useNewUrlParser: true,
 *   useUnifiedTopology: true
 * });
 * 
 * main();
 * 
 * async function main() {
 *   try {
 *     await client.connect();
 *     // Create a new ClientEncryption object, passing in your client
 *     const encryption = new ClientEncryption(client, {
 *       keyVaultNamespace: 'client.encryption',
 *       kmsProviders: {
 *         local: {
 *           key: masterKey // The master key used for encryption/decryption. A 96-byte long Buffer
 *         }
 *       }
 *     });
 *     // create a data key for encryption
 *     const keyId = await encryption.createDataKey('local');
 *     const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic';
 *     // Manually encrypt a SSN
 *     const ssn = await encryption.encrypt('123-456-7890', { keyId, algorithm });
 *     // Insert document w/ encrypted value
 *     await client.db('db').coll('coll').insertOne({
 *       name: 'Darmok',
 *       ssn
 *     });
 *     // Retrieve value from collection. result.ssn is still encrypted
 *     const result = await client.db('db').collection('coll').findOne({ name: 'Darmok' });
 *     // Manually decrypt the SSN
 *     const decryptedSsn = await encryption.decrypt(result.ssn);
 *   } finally {
 *     await client.close();
 *   }
 * }
 */

module.exports = function(mongodb) {
  const modules = { mongodb };

  modules.stateMachine = require('./lib/stateMachine')(modules);
  modules.autoEncrypter = require('./lib/autoEncrypter')(modules);
  modules.clientEncryption = require('./lib/clientEncryption')(modules);

  return {
    AutoEncrypter: modules.autoEncrypter.AutoEncrypter,
    ClientEncryption: modules.clientEncryption.ClientEncryption,
    MongoCryptError: require('./lib/common').MongoCryptError
  };
};
