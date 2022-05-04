'use strict';
const fs = require('fs');
const expect = require('chai').expect;
const sinon = require('sinon');
const BSON = require('bson');
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const cryptoCallbacks = require('../lib/cryptoCallbacks');
const stateMachine = require('../lib/stateMachine')({ mongodb });
const StateMachine = stateMachine.StateMachine;
const { Binary, EJSON, deserialize } = BSON;

function readHttpResponse(path) {
  let data = fs.readFileSync(path, 'utf8').toString();
  data = data.split('\n').join('\r\n');
  return Buffer.from(data, 'utf8');
}

const ClientEncryption = require('../lib/clientEncryption')({
  mongodb,
  stateMachine
}).ClientEncryption;

class MockClient {
  constructor() {
    this.topology = {
      bson: BSON
    };
  }
}

const requirements = require('./requirements.helper');

describe('ClientEncryption', function () {
  let client;

  function setup() {
    client = new MongoClient('mongodb://localhost:27017/test', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
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
  }

  function teardown() {
    if (requirements.SKIP_LIVE_TESTS) {
      return Promise.resolve();
    }

    return client.close();
  }

  describe('stubbed stateMachine', function () {
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

    beforeEach(function () {
      if (requirements.SKIP_LIVE_TESTS) {
        this.test.skipReason = `requirements.SKIP_LIVE_TESTS=${requirements.SKIP_LIVE_TESTS}`;
        this.test.skip();
        return;
      }

      return setup();
    });

    afterEach(function () {
      return teardown();
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
      it(`should create a data key with the "${providerTest.name}" KMS provider`, function (done) {
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

    it('should explicitly encrypt and decrypt with the "local" KMS provider', function (done) {
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

    it('should explicitly encrypt and decrypt with the "local" KMS provider (promise)', function () {
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

    it('should explicitly encrypt and decrypt with the "local" KMS provider (FLE2)', function () {
      const encryption = new ClientEncryption(client, {
        keyVaultNamespace: 'client.encryption',
        kmsProviders: { local: { key: Buffer.alloc(96) } }
      });

      return encryption
        .createDataKey('local')
        .then(dataKey => {
          const encryptOptions = {
            keyId: dataKey,
            algorithm: 'Indexed'
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

    // TODO(NODE-3371): resolve KMS JSON response does not include string 'Plaintext'. HTTP status=200 error
    it.skip('should explicitly encrypt and decrypt with the "aws" KMS provider', function (done) {
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
    }).skipReason =
      "TODO(NODE-3371): resolve KMS JSON response does not include string 'Plaintext'. HTTP status=200 error";
  });

  describe('ClientEncryptionKeyAltNames', function () {
    const kmsProviders = requirements.awsKmsProviders;
    const dataKeyOptions = requirements.awsDataKeyOptions;
    beforeEach(function () {
      if (requirements.SKIP_AWS_TESTS) {
        this.currentTest.skipReason = `requirements.SKIP_AWS_TESTS=${requirements.SKIP_AWS_TESTS}`;
        this.skip();
        return;
      }

      return setup().then(() => {
        this.client = client;
        this.collection = client.db('client').collection('encryption');
        this.encryption = new ClientEncryption(this.client, {
          keyVaultNamespace: 'client.encryption',
          kmsProviders
        });
      });
    });

    afterEach(function () {
      return teardown().then(() => {
        this.encryption = undefined;
        this.collection = undefined;
        this.client = undefined;
      });
    });

    function makeOptions(keyAltNames) {
      expect(dataKeyOptions.masterKey).to.be.an('object');
      expect(dataKeyOptions.masterKey.key).to.be.a('string');
      expect(dataKeyOptions.masterKey.region).to.be.a('string');

      return {
        masterKey: {
          key: dataKeyOptions.masterKey.key,
          region: dataKeyOptions.masterKey.region
        },
        keyAltNames
      };
    }

    describe('errors', function () {
      [42, 'hello', { keyAltNames: 'foobar' }, /foobar/].forEach(val => {
        it(`should fail if typeof keyAltNames = ${typeof val}`, function () {
          const options = makeOptions(val);
          expect(() => this.encryption.createDataKey('aws', options, () => undefined)).to.throw(
            TypeError
          );
        });
      });

      [undefined, null, 42, { keyAltNames: 'foobar' }, ['foobar'], /foobar/].forEach(val => {
        it(`should fail if typeof keyAltNames[x] = ${typeof val}`, function () {
          const options = makeOptions([val]);
          expect(() => this.encryption.createDataKey('aws', options, () => undefined)).to.throw(
            TypeError
          );
        });
      });
    });

    it('should create a key with keyAltNames', function () {
      let dataKey;
      const options = makeOptions(['foobar']);
      return this.encryption
        .createDataKey('aws', options)
        .then(_dataKey => (dataKey = _dataKey))
        .then(() => this.collection.findOne({ keyAltNames: 'foobar' }))
        .then(document => {
          expect(document).to.be.an('object');
          expect(document).to.have.property('keyAltNames').that.includes.members(['foobar']);
          expect(document).to.have.property('_id').that.deep.equals(dataKey);
        });
    });

    it('should create a key with multiple keyAltNames', function () {
      let dataKey;
      return this.encryption
        .createDataKey('aws', makeOptions(['foobar', 'fizzbuzz']))
        .then(_dataKey => (dataKey = _dataKey))
        .then(() =>
          Promise.all([
            this.collection.findOne({ keyAltNames: 'foobar' }),
            this.collection.findOne({ keyAltNames: 'fizzbuzz' })
          ])
        )
        .then(docs => {
          expect(docs).to.have.lengthOf(2);
          const doc1 = docs[0];
          const doc2 = docs[1];
          expect(doc1).to.be.an('object');
          expect(doc2).to.be.an('object');
          expect(doc1)
            .to.have.property('keyAltNames')
            .that.includes.members(['foobar', 'fizzbuzz']);
          expect(doc1).to.have.property('_id').that.deep.equals(dataKey);
          expect(doc2)
            .to.have.property('keyAltNames')
            .that.includes.members(['foobar', 'fizzbuzz']);
          expect(doc2).to.have.property('_id').that.deep.equals(dataKey);
        });
    });

    it('should be able to reference a key with `keyAltName` during encryption', function () {
      let keyId;
      const keyAltName = 'mySpecialKey';
      const algorithm = 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic';

      const valueToEncrypt = 'foobar';

      return this.encryption
        .createDataKey('aws', makeOptions([keyAltName]))
        .then(_dataKey => (keyId = _dataKey))
        .then(() => this.encryption.encrypt(valueToEncrypt, { keyId, algorithm }))
        .then(encryptedValue => {
          return this.encryption
            .encrypt(valueToEncrypt, { keyAltName, algorithm })
            .then(encryptedValue2 => {
              expect(encryptedValue).to.deep.equal(encryptedValue2);
            });
        });
    });
  });

  context('with stubbed key material and fixed random source', function () {
    let sandbox = sinon.createSandbox();

    afterEach(() => {
      sandbox.restore();
    });
    beforeEach(() => {
      const rndData = Buffer.from(
        '\x4d\x06\x95\x64\xf5\xa0\x5e\x9e\x35\x23\xb9\x8f\x57\x5a\xcb\x15',
        'latin1'
      );
      let rndPos = 0;
      sandbox.stub(cryptoCallbacks, 'randomHook').callsFake((buffer, count) => {
        if (rndPos + count > rndData) {
          return new Error('Out of fake random data');
        }
        buffer.set(rndData.subarray(rndPos, rndPos + count));
        rndPos += count;
        return count;
      });

      // stubbed out for AWS unit testing below
      sandbox.stub(StateMachine.prototype, 'fetchKeys').callsFake((client, ns, filter, cb) => {
        filter = deserialize(filter);
        const keyIds = filter.$or[0]._id.$in.map(key => key.toString('hex'));
        const fileNames = keyIds.map(
          keyId => `${__dirname}/../../../test/data/keys/${keyId.toUpperCase()}-local-document.json`
        );
        const contents = fileNames.map(filename => EJSON.parse(fs.readFileSync(filename)));
        cb(null, contents);
      });
    });

    // This exactly matches _test_encrypt_fle2_explicit from the C tests
    it.only('should explicitly encrypt and decrypt with the "local" KMS provider (FLE2, exact result)', function () {
      const encryption = new ClientEncryption(new MockClient(), {
        keyVaultNamespace: 'client.encryption',
        kmsProviders: { local: { key: Buffer.alloc(96) } }
      });

      const encryptOptions = {
        keyId: new Binary(Buffer.from('ABCDEFAB123498761234123456789012', 'hex'), 4),
        indexKeyId: new Binary(Buffer.from('12345678123498761234123456789012', 'hex'), 4),
        algorithm: 'Unindexed'
      };

      return encryption
        .encrypt('value123', encryptOptions)
        .then(encrypted => {
          expect(encrypted._bsontype).to.equal('Binary');
          expect(encrypted.sub_type).to.equal(6);
          expect(encrypted.toString('base64')).to.equal(
            'BqvN76sSNJh2EjQSNFZ4kBICTQaVZPWgXp41I7mPV1rLFTtw1tXzjcdSEyxpKKqujlko5TeizkB9hHQ009dVY1+fgIiDcefh+eQrm3CkhQ=='
          );

          return encryption.decrypt(encrypted);
        })
        .then(decrypted => {
          expect(decrypted).to.equal('value123');
        });
    });
  });
});
