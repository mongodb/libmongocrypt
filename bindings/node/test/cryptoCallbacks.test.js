'use strict';

const sinon = require('sinon');
const chai = require('chai');
const expect = chai.expect;
chai.use(require('sinon-chai'));
const mongodb = require('mongodb');
const MongoClient = mongodb.MongoClient;
const stateMachine = require('../lib/stateMachine')({ mongodb });
const cryptoCallbacks = require('../lib/cryptoCallbacks');
const ClientEncryption = require('../lib/clientEncryption')({ mongodb, stateMachine })
  .ClientEncryption;
const SegfaultHandler = require('segfault-handler');
SegfaultHandler.registerHandler();

const requirements = require('./requirements.helper');

// Data Key Stuff
const kmsProviders = Object.assign({}, requirements.awsKmsProviders);
const dataKeyOptions = Object.assign({}, requirements.awsDataKeyOptions);

describe('cryptoCallbacks', function() {
  before(function() {
    if (requirements.SKIP_AWS_TESTS) {
      console.log('Skipping crypto callback tests');
      return;
    }
    this.sinon = sinon.createSandbox();
  });

  beforeEach(function() {
    if (requirements.SKIP_AWS_TESTS) {
      this.test.skip();
      return;
    }
    this.sinon.restore();
    this.client = new MongoClient('mongodb://localhost:27017/', {
      useUnifiedTopology: true,
      useNewUrlParser: true
    });

    return this.client.connect();
  });

  afterEach(function() {
    if (requirements.SKIP_AWS_TESTS) {
      return;
    }
    this.sinon.restore();
    let p = Promise.resolve();
    if (this.client) {
      p = p.then(() => this.client.close()).then(() => (this.client = undefined));
    }

    return p;
  });

  after(function() {
    this.sinon = undefined;
  });

  const hookNames = new Set([
    'aes256CbcEncryptHook',
    'aes256CbcDecryptHook',
    'randomHook',
    'hmacSha512Hook',
    'hmacSha256Hook',
    'sha256Hook'
  ]);

  it('should invoke crypto callbacks when doing encryption', function(done) {
    for (const name of hookNames) {
      this.sinon.spy(cryptoCallbacks, name);
    }

    function assertCertainHooksCalled(expectedSet) {
      expectedSet = expectedSet || new Set([]);
      for (const name of hookNames) {
        const hook = cryptoCallbacks[name];
        if (expectedSet.has(name)) {
          expect(hook).to.have.been.called;
        } else {
          expect(hook).to.not.have.been.called;
        }

        hook.resetHistory();
      }
    }

    const encryption = new ClientEncryption(this.client, {
      keyVaultNamespace: 'test.encryption',
      kmsProviders
    });

    try {
      assertCertainHooksCalled();
    } catch (e) {
      return done(e);
    }

    encryption.createDataKey('aws', dataKeyOptions, (err, dataKey) => {
      try {
        expect(err).to.not.exist;
        assertCertainHooksCalled(new Set(['hmacSha256Hook', 'sha256Hook', 'randomHook']));
      } catch (e) {
        return done(e);
      }

      const encryptOptions = {
        keyId: dataKey,
        algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
      };

      encryption.encrypt('hello', encryptOptions, (err, encryptedValue) => {
        try {
          expect(err).to.not.exist;
          assertCertainHooksCalled(
            new Set(['aes256CbcEncryptHook', 'hmacSha512Hook', 'hmacSha256Hook', 'sha256Hook'])
          );
        } catch (e) {
          return done(e);
        }
        encryption.decrypt(encryptedValue, err => {
          try {
            expect(err).to.not.exist;
            assertCertainHooksCalled(new Set(['aes256CbcDecryptHook', 'hmacSha512Hook']));
          } catch (e) {
            return done(e);
          }
          done();
        });
      });
    });
  });

  describe('error testing', function() {
    ['aes256CbcEncryptHook', 'aes256CbcDecryptHook', 'hmacSha512Hook'].forEach(hookName => {
      it(`should properly propagate an error when ${hookName} fails`, function(done) {
        const error = new Error('some random error text');
        this.sinon.stub(cryptoCallbacks, hookName).returns(error);

        const encryption = new ClientEncryption(this.client, {
          keyVaultNamespace: 'test.encryption',
          kmsProviders
        });

        function finish(err) {
          try {
            expect(err, 'Expected an error to exist').to.exist;
            expect(err).to.have.property('message', error.message);
            done();
          } catch (e) {
            done(e);
          }
        }

        try {
          encryption.createDataKey('aws', dataKeyOptions, (err, dataKey) => {
            if (err) return finish(err);

            const encryptOptions = {
              keyId: dataKey,
              algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
            };

            encryption.encrypt('hello', encryptOptions, (err, encryptedValue) => {
              if (err) return finish(err);
              encryption.decrypt(encryptedValue, err => finish(err));
            });
          });
        } catch (e) {
          done(new Error('We should not be here'));
        }
      });
    });

    // These ones will fail with an error, but that error will get overridden
    // with "failed to create KMS message" in mongocrypt-kms-ctx.c
    ['hmacSha256Hook', 'sha256Hook'].forEach(hookName => {
      it(`should error with a specific kms erro when ${hookName} fails`, function(done) {
        const error = new Error('some random error text');
        this.sinon.stub(cryptoCallbacks, hookName).returns(error);

        const encryption = new ClientEncryption(this.client, {
          keyVaultNamespace: 'test.encryption',
          kmsProviders
        });

        try {
          encryption.createDataKey('aws', dataKeyOptions, () => {
            done(new Error('We should not be here'));
          });
        } catch (err) {
          try {
            expect(err).to.have.property('message', 'failed to create KMS message');
            done();
          } catch (e) {
            done(e);
          }
        }
      });
    });
  });
});
