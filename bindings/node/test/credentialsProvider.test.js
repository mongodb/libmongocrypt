'use strict';

const chai = require('chai');
const expect = chai.expect;

const { loadCredentials } = require('../lib/credentialsProvider');

const originalAccessKeyId = process.env.AWS_ACCESS_KEY_ID;
const originalSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
const originalSessionToken = process.env.AWS_SESSION_TOKEN;

describe('#loadCredentials', function () {
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
      const kmsProviders = {};

      before(function () {
        if (process.env.NPM_OPTIONS === '--no-optional') {
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
          if (process.env.NPM_OPTIONS === '--no-optional') {
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
          if (process.env.NPM_OPTIONS === '--no-optional') {
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

      context('when aws does not exist', function () {
        const kmsProviders = {
          local: {
            key: Buffer.alloc(96)
          }
        };

        before(function () {
          if (process.env.NPM_OPTIONS === '--no-optional') {
            this.currentTest.skipReason = 'Cannot refresh credentials without sdk provider';
            this.currentTest.skip();
            return;
          }
        });

        it('refreshes ony the aws credentials', async function () {
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
      if (!process.env.NPM_OPTIONS) {
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
