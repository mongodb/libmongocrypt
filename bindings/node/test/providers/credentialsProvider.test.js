'use strict';

const { expect } = require('chai');
const http = require('http');
const requirements = require('../requirements.helper');
const { loadCredentials, isEmptyCredentials } = require('../../lib/providers');
const { CredentialCacheProvider } = require('../../lib/providers/azure');

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

  context('when using gcp', () => {
    const setupHttpServer = status => {
      let httpServer;
      before(() => {
        httpServer = http
          .createServer((_, res) => {
            if (status === 200) {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.writeHead(200, { 'Metadata-Flavor': 'Google' });
              res.end(JSON.stringify({ access_token: 'abc' }));
            } else {
              res.writeHead(401, { 'Content-Type': 'application/json' });
              res.writeHead(401, { 'Metadata-Flavor': 'Google' });
              res.end('{}');
            }
          })
          .listen(5001);
        process.env.GCE_METADATA_HOST = 'http://127.0.0.1:5001';
      });

      after(() => {
        httpServer.close();
        delete process.env.GCE_METADATA_HOST;
      });
    };

    context('and gcp-metadata is installed', () => {
      beforeEach(function () {
        if (!requirements.credentialProvidersInstalled.gcp) {
          this.currentTest.skipReason = 'Tests require gcp-metadata to be installed';
          this.currentTest.skip();
          return;
        }
      });

      context('when metadata http response is 200 ok', () => {
        setupHttpServer(200);
        context('when the credentials are empty', function () {
          const kmsProviders = { gcp: {} };

          it('refreshes the gcp credentials', async function () {
            const providers = await loadCredentials(kmsProviders);
            expect(providers).to.deep.equal({
              gcp: {
                accessToken: 'abc'
              }
            });
          });
        });
      });

      context('when metadata http response is 401 bad', () => {
        setupHttpServer(401);
        context('when the credentials are empty', function () {
          const kmsProviders = { gcp: {} };

          it('surfaces error from server', async function () {
            const error = await loadCredentials(kmsProviders).catch(error => error);
            expect(error).to.be.instanceOf(Error);
          });
        });
      });
    });

    context('and gcp-metadata is not installed', () => {
      beforeEach(function () {
        if (requirements.credentialProvidersInstalled.gcp) {
          this.currentTest.skipReason = 'Tests require gcp-metadata to be installed';
          this.currentTest.skip();
          return;
        }
      });

      context('when the credentials are empty', function () {
        const kmsProviders = { gcp: {} };

        it('does not modify the gcp credentials', async function () {
          const providers = await loadCredentials(kmsProviders);
          expect(providers).to.deep.equal({ gcp: {} });
        });
      });
    });
  });

  context('when using azure', () => {
    context('credential caching', () => {
      class MockTokenProvider {
        constructor() {
          this.mockToken = null;
          this.getTokenCount = 0;
        }

        async getToken() {
          this.getTokenCount++;
          return this.mockToken;
        }
      }

      /**
       * @type{MockTokenProvider}
       */
      let mockTokenProvider;

      /**
       * @type{CredentialCacheProvider}
       */
      let credentialCacheProvider;

      beforeEach(() => {
        mockTokenProvider = new MockTokenProvider();
        credentialCacheProvider = new CredentialCacheProvider(mockTokenProvider);
      });

      context('when there is no cached token', () => {
        let mockToken = {
          token: 'mock token',
          expiresOnTimestamp: Date.now()
        };

        let token;

        beforeEach(async () => {
          mockTokenProvider.mockToken = mockToken;
          token = await credentialCacheProvider.getToken();
        });
        it('fetches a token', async () => {
          expect(token).to.equal(mockToken);
        });
        it('caches the token on the class', async () => {
          expect(credentialCacheProvider.cachedToken).to.equal(mockToken);
        });
      });

      context('when there is a cached token', () => {
        context('when the cached token expires <= 1 minute from the current time', () => {
          let mockToken = {
            token: 'mock token',
            expiresOnTimestamp: Date.now()
          };

          let token;

          beforeEach(async () => {
            credentialCacheProvider.cachedToken = {
              ...mockToken,
              expiresOnTimestamp: Date.now() + 3000
            };
            mockTokenProvider.mockToken = mockToken;
            token = await credentialCacheProvider.getToken();
          });
          it('fetches a token', () => {
            expect(token).to.equal(mockToken);
          });
          it('caches the token on the class', () => {
            expect(credentialCacheProvider.cachedToken).to.equal(mockToken);
          });
        });

        context('when the cached token expires > 1 minute from the current time', () => {
          let mockToken = {
            token: 'mock token',
            expiresOnTimestamp: Date.now()
          };

          let expectedMockToken = {
            ...mockToken,
            expiresOnTimestamp: Date.now() + 10000
          };

          let token;

          beforeEach(async () => {
            credentialCacheProvider.cachedToken = expectedMockToken;
            mockTokenProvider.mockToken = mockToken;
            token = await credentialCacheProvider.getToken();
          });
          it('returns the cached token', () => {
            expect(token).to.equal(expectedMockToken);
          });
        });
      });
    });
  });
});
