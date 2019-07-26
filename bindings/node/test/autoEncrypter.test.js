'use strict';

const fs = require('fs');
const BSON = new (require('bson'))(); // TODO: upgrade to 4.x bson
const EJSON = require('mongodb-extjson');
const sinon = require('sinon');
const mongodb = Object.assign({}, require('mongodb'), {
  // TODO: once this is actually defined, use the real one
  MongoTimeoutError: class MongoTimeoutError {}
});
const MongoTimeoutError = mongodb.MongoTimeoutError;
const common = require('../lib/common')({ mongodb });
const stateMachine = require('../lib/stateMachine')({ mongodb, common });
const StateMachine = stateMachine.StateMachine;
const mongocryptdManager = require('../lib/mongocryptdManager')({});

const chai = require('chai');
const expect = chai.expect;
chai.use(require('chai-subset'));
chai.use(require('sinon-chai'));

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

const AutoEncrypter = require('../lib/autoEncrypter')({
  mongodb,
  common,
  stateMachine,
  mongocryptdManager
}).AutoEncrypter;
describe('AutoEncrypter', function() {
  let ENABLE_LOG_TEST = false;
  let sandbox = sinon.createSandbox();
  beforeEach(() => {
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

  afterEach(() => {
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

  describe('autoSpawn', function() {
    it('should autoSpawn a mongocryptd on in it and kill on teardown', function(done) {
      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      sandbox.spy(localMcdm, '_spawn');
      expect(localMcdm._child).to.not.exist;

      this.mc.init(err => {
        if (err) return done(err);
        expect(localMcdm._spawn).to.have.been.calledOnce;
        expect(localMcdm._child).to.exist;

        sandbox.spy(localMcdm, '_kill');

        this.mc.teardown(false, err => {
          if (err) return done(err);
          expect(localMcdm._kill).to.have.been.calledOnce;
          expect(localMcdm._child).to.not.exist;
          done();
        });
      });
    });

    it('should not attempt to kick off mongocryptd on a normal error', function(done) {
      let called = false;
      StateMachine.prototype.markCommand.callsFake((client, ns, filter, callback) => {
        if (!called) {
          called = true;
          callback(new Error('msg'));
          return;
        }

        callback(null, MOCK_MONGOCRYPTD_RESPONSE);
      });

      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      this.mc.init(err => {
        if (err) return done(err);

        sandbox.spy(localMcdm, '_spawn');

        localMcdm.kill(() => {
          this.mc.encrypt('test.test', TEST_COMMAND, err => {
            expect(localMcdm._spawn).to.not.have.been.called;
            expect(localMcdm._child).to.not.exist;
            expect(err).to.be.an.instanceOf(Error);
            done();
          });
        });
      });
    });

    it('should restore the mongocryptd and retry once if a MongoTimeoutError is experienced', function(done) {
      let called = false;
      StateMachine.prototype.markCommand.callsFake((client, ns, filter, callback) => {
        if (!called) {
          called = true;
          callback(new MongoTimeoutError('msg'));
          return;
        }

        callback(null, MOCK_MONGOCRYPTD_RESPONSE);
      });

      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      this.mc.init(err => {
        if (err) return done(err);

        sandbox.spy(localMcdm, '_spawn');

        localMcdm.kill(() => {
          expect(localMcdm._child).to.not.exist;
          this.mc.encrypt('test.test', TEST_COMMAND, err => {
            expect(localMcdm._spawn).to.have.been.calledOnce;
            expect(localMcdm._child).to.exist;
            expect(err).to.not.exist;
            done();
          });
        });
      });
    });

    it('should propagate error if MongoTimeoutError is experienced twice in a row', function(done) {
      let counter = 2;
      StateMachine.prototype.markCommand.callsFake((client, ns, filter, callback) => {
        if (counter) {
          counter -= 1;
          callback(new MongoTimeoutError('msg'));
          return;
        }

        callback(null, MOCK_MONGOCRYPTD_RESPONSE);
      });

      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      this.mc.init(err => {
        if (err) return done(err);

        sandbox.spy(localMcdm, '_spawn');

        localMcdm.kill(() => {
          expect(localMcdm._child).to.not.exist;
          this.mc.encrypt('test.test', TEST_COMMAND, err => {
            expect(localMcdm._spawn).to.have.been.calledOnce;
            expect(localMcdm._child).to.exist;
            expect(err).to.be.an.instanceof(MongoTimeoutError);
            done();
          });
        });
      });
    });

    afterEach(function(done) {
      if (this.mc) {
        this.mc.teardown(false, err => done(err));
      } else {
        done();
      }
    });
  });

  describe('noAutoSpawn', function() {
    beforeEach(function(done) {
      this.mcdm = new mongocryptdManager.MongocryptdManager({});

      this.mcdm.spawn(done);
    });

    it('should not spawn or kill mongocryptd on startup/shutdown', function(done) {
      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        },
        extraOptions: {
          mongocryptdBypassSpawn: true
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      sandbox.spy(localMcdm, '_spawn');
      sandbox.spy(localMcdm, '_kill');

      this.mc.init(err => {
        expect(err).to.not.exist;
        expect(localMcdm._spawn).to.have.a.callCount(0);
        this.mc.teardown(false, err => {
          expect(err).to.not.exist;
          expect(localMcdm._kill).to.have.a.callCount(0);
        });
        done();
      });
    });

    it('should not spawn a mongocryptd or retry on a server selection error', function(done) {
      let called = false;
      const timeoutError = new MongoTimeoutError('msg');
      StateMachine.prototype.markCommand.callsFake((client, ns, filter, callback) => {
        if (!called) {
          called = true;
          callback(timeoutError);
          return;
        }

        callback(null, MOCK_MONGOCRYPTD_RESPONSE);
      });

      const client = new MockClient();
      this.mc = new AutoEncrypter(client, {
        keyVaultNamespace: 'admin.datakeys',
        logger: () => {},
        kmsProviders: {
          aws: { accessKeyId: 'example', secretAccessKey: 'example' },
          local: { key: Buffer.alloc(96) }
        },
        extraOptions: {
          mongocryptdBypassSpawn: true
        }
      });

      const localMcdm = this.mc._mongocryptdManager;
      sandbox.spy(localMcdm, '_spawn');

      this.mc.init(err => {
        expect(err).to.not.exist;
        expect(localMcdm._spawn).to.have.a.callCount(0);
        sandbox.spy(localMcdm, 'spawn');

        this.mc.encrypt('test.test', TEST_COMMAND, (err, response) => {
          expect(localMcdm.spawn).to.not.have.been.called;
          expect(response).to.not.exist;
          expect(err).to.equal(timeoutError);
          done();
        });
      });
    });

    afterEach(function(done) {
      const teardownMC = this.mc
        ? callback => this.mc.teardown(false, callback)
        : callback => callback();

      teardownMC(err => {
        this.mcdm.kill(() => done(err));
      });
    });
  });
});
