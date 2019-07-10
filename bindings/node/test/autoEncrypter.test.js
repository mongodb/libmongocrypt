'use strict';

const fs = require('fs');
const BSON = new (require('bson'))(); // TODO: upgrade to 4.x bson
const EJSON = require('mongodb-extjson');
const sinon = require('sinon');
const StateMachine = require('../lib/stateMachine').StateMachine;

const chai = require('chai');
const expect = chai.expect;
chai.use(require('chai-subset'));

const SegfaultHandler = require('segfault-handler');
SegfaultHandler.registerHandler();

function readExtendedJsonToBuffer(path) {
  const ejson = EJSON.parse(fs.readFileSync(path, 'utf8'));
  return BSON.serialize(ejson);
}

function readHttpResponse(path) {
  let data = fs.readFileSync(path, 'utf8').toString();
  data = data.split('\n').join('\r\n');
  return Buffer.from(data, 'utf8');
}

const TEST_COMMAND = JSON.parse(fs.readFileSync(`${__dirname}/data/cmd.json`));
const MOCK_COLLINFO_RESPONSE = readExtendedJsonToBuffer(`${__dirname}/data/collection-info.json`);
const MOCK_MONGOCRYPTD_RESPONSE = readExtendedJsonToBuffer(
  `${__dirname}/data/mongocryptd-reply.json`
);
const MOCK_KEYDOCUMENT_RESPONSE = readExtendedJsonToBuffer(`${__dirname}/data/key-document.json`);
const MOCK_KMS_DECRYPT_REPLY = readHttpResponse(`${__dirname}/data/kms-decrypt-reply.txt`);

class MockClient {
  constructor() {
    this.topology = {
      bson: BSON
    };
  }
}

const AutoEncrypter = require('../lib/autoEncrypter').AutoEncrypter;
describe('AutoEncrypter', function() {
  let ENABLE_LOG_TEST = false;
  let sandbox = sinon.createSandbox();
  before(() => {
    sandbox.stub(StateMachine.prototype, 'kmsRequest').callsFake(request => {
      request.addResponse(MOCK_KMS_DECRYPT_REPLY);
      return Promise.resolve();
    });

    sandbox
      .stub(StateMachine.prototype, 'fetchCollectionInfo')
      .callsFake((client, ns, filter, callback) => {
        callback(null, MOCK_COLLINFO_RESPONSE);
      });

    sandbox
      .stub(StateMachine.prototype, 'markCommand')
      .callsFake((client, ns, command, callback) => {
        if (ENABLE_LOG_TEST) {
          const response = BSON.deserialize(MOCK_MONGOCRYPTD_RESPONSE);
          response.schemaRequiresEncryption = false;

          ENABLE_LOG_TEST = false; // disable test after run
          callback(null, BSON.serialize(response));
          return;
        }

        callback(null, MOCK_MONGOCRYPTD_RESPONSE);
      });

    sandbox.stub(StateMachine.prototype, 'fetchKeys').callsFake((client, ns, filter, callback) => {
      // mock data is already seriaized, our action deals with the result of a cursor
      const deserializedKey = BSON.deserialize(MOCK_KEYDOCUMENT_RESPONSE);
      callback(null, [deserializedKey]);
    });
  });

  after(() => {
    sandbox.restore();
  });

  describe('state machine', function() {
    it('should decrypt mock data', function(done) {
      const input = readExtendedJsonToBuffer(`${__dirname}/data/encrypted-document.json`);
      const client = new MockClient();
      const mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      mc.decrypt(input, (err, decrypted) => {
        if (err) return done(err);
        expect(decrypted).to.eql({ filter: { find: 'test', ssn: '457-55-5462' } });
        done();
      });
    });

    it('should encrypt mock data', function(done) {
      const client = new MockClient();
      const mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      mc.encrypt('test.test', TEST_COMMAND, (err, encrypted) => {
        if (err) return done(err);
        const expected = EJSON.parse(
          JSON.stringify({
            find: 'test',
            filter: {
              ssn: {
                $binary: {
                  base64:
                    'AWFhYWFhYWFhYWFhYWFhYWECRTOW9yZzNDn5dGwuqsrJQNLtgMEKaujhs9aRWRp+7Yo3JK8N8jC8P0Xjll6C1CwLsE/iP5wjOMhVv1KMMyOCSCrHorXRsb2IKPtzl2lKTqQ=',
                  subType: '6'
                }
              }
            }
          })
        );

        expect(encrypted).to.containSubset(expected);
        done();
      });
    });
  });

  describe('logging', function() {
    it('should allow registration of a log handler', function(done) {
      ENABLE_LOG_TEST = true;

      let loggerCalled = false;
      const logger = (level, message) => {
        if (loggerCalled) return;

        loggerCalled = true;
        expect(level).to.be.oneOf([2, 3]);
        expect(message).to.not.be.empty;
      };

      const client = new MockClient();
      const mc = new AutoEncrypter(client, {
        logger,
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      mc.encrypt('test.test', TEST_COMMAND, (err, encrypted) => {
        if (err) return done(err);
        const expected = EJSON.parse(
          JSON.stringify({
            find: 'test',
            filter: {
              ssn: '457-55-5462'
            }
          })
        );

        expect(encrypted).to.containSubset(expected);
        done();
      });
    });
  });
});
