'use strict';

const { expect } = require('chai');
const requirements = require('./requirements.helper');
const { loadCredentials, isEmptyCredentials } = require('../lib/credentialsProvider');

const originalAccessKeyId = process.env.AWS_ACCESS_KEY_ID;
const originalSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
const originalSessionToken = process.env.AWS_SESSION_TOKEN;

describe('#loadCredentials', function () {
  context('isEmptyCredentials()', () => {
    it('returns true for an empty object', () => {
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: {} })).to.be.true;
    });

    it('returns false for an object with keys', () => {
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: { password: 'secret' } })).to.be.false;
    });

    it('returns false for an nullish credentials', () => {
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: null })).to.be.false;
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: undefined })).to.be.false;
      expect(isEmptyCredentials('rainyCloud', {})).to.be.false;
    });

    it('returns false for non object credentials', () => {
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: 0 })).to.be.false;
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: false })).to.be.false;
      expect(isEmptyCredentials('rainyCloud', { rainyCloud: Symbol('secret') })).to.be.false;
    });
  });

  context('when using aws', () => {
    const accessKey = 'example';
    const secretKey = 'example';
    const sessionToken = 'example';

    after(function () {
      // After the entire suite runs, set the env back for the rest of the test run.
      process.env.AWS_ACCESS_KEY_ID = originalAccessKeyId;
      process.env.AWS_SECRET_ACCESS_KEY = originalSecretAccessKey;
      process.env.AWS_SESSION_TOKEN = originalSessionToken;
    });

    context('when the credential provider finds credentials', function () {
      before(function () {
        process.env.AWS_ACCESS_KEY_ID = accessKey;
        process.env.AWS_SECRET_ACCESS_KEY = secretKey;
        process.env.AWS_SESSION_TOKEN = sessionToken;
      });

      context('when the credentials are empty', function () {
        const kmsProviders = { aws: {} };

        before(function () {
          if (!requirements.credentialProvidersInstalled.aws) {
            this.currentTest.skipReason = 'Cannot refresh credentials without sdk provider';
            this.currentTest.skip();
            return;
          }
        });

        it('refreshes the aws credentials', async function () {
          const providers = await loadCredentials(kmsProviders);
          expect(providers).to.deep.equal({
            aws: {
              accessKeyId: accessKey,
              secretAccessKey: secretKey,
              sessionToken: sessionToken
            }
          });
        });
      });

      context('when the credentials are not empty', function () {
        context('when aws is empty', function () {
          const kmsProviders = {
            local: {
              key: Buffer.alloc(96)
            },
            aws: {}
          };

          before(function () {
            if (!requirements.credentialProvidersInstalled.aws) {
              this.currentTest.skipReason = 'Cannot refresh credentials without sdk provider';
              this.currentTest.skip();
              return;
            }
          });

          it('refreshes only the aws credentials', async function () {
            const providers = await loadCredentials(kmsProviders);
            expect(providers).to.deep.equal({
              local: {
                key: Buffer.alloc(96)
              },
              aws: {
                accessKeyId: accessKey,
                secretAccessKey: secretKey,
                sessionToken: sessionToken
              }
            });
          });
        });

        context('when aws is not empty', function () {
          const kmsProviders = {
            local: {
              key: Buffer.alloc(96)
            },
            aws: {
              accessKeyId: 'example'
            }
          };

          before(function () {
            if (!requirements.credentialProvidersInstalled.aws) {
              this.currentTest.skipReason = 'Cannot refresh credentials without sdk provider';
              this.currentTest.skip();
              return;
            }
          });

          it('does not refresh credentials', async function () {
            const providers = await loadCredentials(kmsProviders);
            expect(providers).to.deep.equal(kmsProviders);
          });
        });
      });
    });

    context('when the sdk is not installed', function () {
      const kmsProviders = {
        local: {
          key: Buffer.alloc(96)
        },
        aws: {}
      };

      before(function () {
        if (requirements.credentialProvidersInstalled.aws) {
          this.currentTest.skipReason = 'Credentials will be loaded when sdk present';
          this.currentTest.skip();
          return;
        }
      });

      it('does not refresh credentials', async function () {
        const providers = await loadCredentials(kmsProviders);
        expect(providers).to.deep.equal(kmsProviders);
      });
    });
  });
});
