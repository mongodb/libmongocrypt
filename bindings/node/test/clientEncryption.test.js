'use strict';
const fs = require('fs');
const expect = require('chai').expect;
const sinon = require('sinon');
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const stateMachine = require('../lib/stateMachine')({ mongodb });
const StateMachine = stateMachine.StateMachine;
const SegfaultHandler = require('segfault-handler');
SegfaultHandler.registerHandler();

function readHttpResponse(path) {
  let data = fs.readFileSync(path, 'utf8').toString();
  data = data.split('\n').join('\r\n');
  return Buffer.from(data, 'utf8');
}

const ClientEncryption = require('../lib/clientEncryption')({ mongodb, stateMachine })
  .ClientEncryption;
describe('ClientEncryption', function() {
  let client;
  let sandbox = sinon.createSandbox();

  after(() => sandbox.restore());
  before(() => {
    // stubbed out for AWS unit testing below
    const MOCK_KMS_ENCRYPT_REPLY = readHttpResponse(`${__dirname}/data/kms-encrypt-reply.txt`);
    sandbox.stub(StateMachine.prototype, 'kmsRequest').callsFake(request => {
      request.addResponse(MOCK_KMS_ENCRYPT_REPLY);
      return Promise.resolve();
    });
  });

  beforeEach(function() {
    if (process.env.NODE_SKIP_LIVE_TESTS) {
      this.test.skip();
      return;
    }
    client = new MongoClient('mongodb://localhost:27017/test', { useNewUrlParser: true });
    return client.connect().then(() =>
      client
        .db('client')
        .collection('encryption')
        .drop()
        .catch(err => {
          if (err.message.match(/ns not found/)) {
            return;
          }

          throw err;
        })
    );
  });

  afterEach(() => {
    if (process.env.NODE_SKIP_LIVE_TESTS) {
      return;
    }
    return client.close();
  });

  [
    {
      name: 'local',
      kmsProviders: { local: { key: Buffer.alloc(96) } }
    },
    {
      name: 'aws',
      kmsProviders: { aws: { accessKeyId: 'example', secretAccessKey: 'example' } },
      options: { masterKey: { region: 'region', key: 'cmk' } }
    }
  ].forEach(providerTest => {
    it(`should create a data key with the "${providerTest.name}" KMS provider`, function(done) {
      const providerName = providerTest.name;
      const encryption = new ClientEncryption(client, {
        keyVaultNamespace: 'client.encryption',
        kmsProviders: providerTest.kmsProviders
      });

      const dataKeyOptions = providerTest.options || {};
      encryption.createDataKey(providerName, dataKeyOptions, (err, dataKey) => {
        expect(err).to.not.exist;
        expect(dataKey._bsontype).to.equal('Binary');

        client
          .db('client')
          .collection('encryption')
          .findOne({ _id: dataKey }, (err, doc) => {
            expect(err).to.not.exist;
            expect(doc).to.have.property('masterKey');
            expect(doc.masterKey).to.have.property('provider');
            expect(doc.masterKey.provider).to.eql(providerName);
            done();
          });
      });
    });
  });

  it('should explicitly encrypt and decrypt with the "local" KMS provider', function(done) {
    const encryption = new ClientEncryption(client, {
      keyVaultNamespace: 'client.encryption',
      kmsProviders: { local: { key: Buffer.alloc(96) } }
    });

    encryption.createDataKey('local', (err, dataKey) => {
      expect(err).to.not.exist;

      const encryptOptions = {
        keyId: dataKey,
        algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
      };

      encryption.encrypt('hello', encryptOptions, (err, encrypted) => {
        expect(err).to.not.exist;
        expect(encrypted._bsontype).to.equal('Binary');
        expect(encrypted.sub_type).to.equal(6);

        encryption.decrypt(encrypted, (err, decrypted) => {
          expect(err).to.not.exist;
          expect(decrypted).to.equal('hello');
          done();
        });
      });
    });
  });

  it('should explicitly encrypt and decrypt with the "local" KMS provider (promise)', function() {
    const encryption = new ClientEncryption(client, {
      keyVaultNamespace: 'client.encryption',
      kmsProviders: { local: { key: Buffer.alloc(96) } }
    });

    return encryption
      .createDataKey('local')
      .then(dataKey => {
        const encryptOptions = {
          keyId: dataKey,
          algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
        };

        return encryption.encrypt('hello', encryptOptions);
      })
      .then(encrypted => {
        expect(encrypted._bsontype).to.equal('Binary');
        expect(encrypted.sub_type).to.equal(6);

        return encryption.decrypt(encrypted);
      })
      .then(decrypted => {
        expect(decrypted).to.equal('hello');
      });
  });

  it.skip('should explicitly encrypt and decrypt with the "aws" KMS provider', function(done) {
    const encryption = new ClientEncryption(client, {
      keyVaultNamespace: 'client.encryption',
      kmsProviders: { aws: { accessKeyId: 'example', secretAccessKey: 'example' } }
    });

    const dataKeyOptions = {
      masterKey: { region: 'region', key: 'cmk' }
    };

    encryption.createDataKey('aws', dataKeyOptions, (err, dataKey) => {
      expect(err).to.not.exist;

      const encryptOptions = {
        keyId: dataKey,
        algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
      };

      encryption.encrypt('hello', encryptOptions, (err, encrypted) => {
        expect(err).to.not.exist;
        expect(encrypted).to.have.property('v');
        expect(encrypted.v._bsontype).to.equal('Binary');
        expect(encrypted.v.sub_type).to.equal(6);

        encryption.decrypt(encrypted, (err, decrypted) => {
          expect(err).to.not.exist;
          expect(decrypted).to.equal('hello');
          done();
        });
      });
    });
  });

  it('should be able to auto decrypt explicit encryption');
});
