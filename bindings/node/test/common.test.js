'use strict';

const { askForKMSCredentials } = require('../lib/common');
const chai = require('chai');
const expect = chai.expect;

describe('common', function () {
  describe('#askForKMSCredentials', function () {
    const userCreds = { aws: { accessKeyId: 'example1', secretAccessKey: 'example1' } };
    const defaultCreds = { aws: { accessKeyId: 'example2', secretAccessKey: 'example2' } };
    const validUserRefresh = () => {
      return userCreds;
    };
    const emptyUserRefresh = () => ({});
    const validDefaultRefresh = () => {
      return new Promise(resolve => {
        resolve(defaultCreds);
      });
    };
    const emptyDefaultRefresh = () => {
      return new Promise(resolve => {
        resolve({});
      });
    };

    context('when _onKmsProviderRefresh exists', function () {
      context('when it returns credentials', function () {
        const encrypter = {
          _onKmsProviderRefresh: validUserRefresh
        };

        it('returns the user provided credentials', async function () {
          expect(await askForKMSCredentials(encrypter)).to.deep.equal(userCreds);
        });
      });

      context('when it does not return credentials', function () {
        context('when _onEmptyKmsProviders exists', function () {
          context('when it returns credentials', function () {
            const encrypter = {
              _onKmsProviderRefresh: emptyUserRefresh,
              _onEmptyKmsProviders: validDefaultRefresh
            };

            it('returns the default credentials', async function () {
              expect(await askForKMSCredentials(encrypter)).to.deep.equal(defaultCreds);
            });
          });

          context('when it does not return credentials', function () {
            const encrypter = {
              _onKmsProviderRefresh: emptyUserRefresh,
              _onEmptyKmsProviders: emptyDefaultRefresh
            };

            it('returns an empty object', async function () {
              expect(await askForKMSCredentials(encrypter)).to.deep.equal({});
            });
          });
        });

        context('when _onEmptyKmsProviders does not exist', function () {
          const encrypter = {};

          it('returns an empty object', async function () {
            expect(await askForKMSCredentials(encrypter)).to.deep.equal({});
          });
        });
      });
    });

    context('when _onKmsProviderRefresh does not exist', function () {
      context('when _onEmptyKmsProviders exists', function () {
        context('when it returns credentials', function () {
          const encrypter = {
            _onEmptyKmsProviders: validDefaultRefresh
          };

          it('returns the default credentials', async function () {
            expect(await askForKMSCredentials(encrypter)).to.deep.equal(defaultCreds);
          });
        });

        context('when it does not return credentials', function () {
          const encrypter = {
            _onEmptyKmsProviders: emptyDefaultRefresh
          };

          it('returns an empty object', async function () {
            expect(await askForKMSCredentials(encrypter)).to.deep.equal({});
          });
        });
      });

      context('when _onEmptyKmsProviders does not exist', function () {
        const encrypter = {};

        it('returns an empty object', async function () {
          expect(await askForKMSCredentials(encrypter)).to.deep.equal({});
        });
      });
    });
  });
});
