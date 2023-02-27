'use strict';

const http = require('http');
const { MongoCryptAzureKMSRequestError } = require('../errors');

const MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS = 6000;
/**
 * @type{import('@azure/identity')}
 */
let azureIdentityModule = null;

/**
 * @type{AzureCredentialCache}
 */
let tokenCacheProvider = null;

/**
 * @ignore
 */
class AzureCredentialCache {
  constructor() {
    this.cachedToken = null;
  }

  async getToken() {
    if (this._tokenNeedsRefresh()) {
      this.cachedToken = await fetchAzureKMSToken();
    }

    return { accessToken: this.cachedToken.accessToken };
  }

  /**
   * Returns true if the cached token should be refreshed, false otherwise.
   */
  _tokenNeedsRefresh() {
    if (this.cachedToken == null) {
      return true;
    }
    const timeUntilExpirationMS = this.cachedToken.expiresOnTimestamp - Date.now();
    return timeUntilExpirationMS <= MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS;
  }

  reset() {
    this.cachedToken = null;
  }
}

/**
 * @param {URL | string} url
 * @param {http.RequestOptions} options
 */
function executeTokenRequest(url, options) {
  return new Promise((resolve, reject) => {
    function processBody(body, response) {
      if (response.statusCode !== 200) {
        try {
          const response = JSON.parse(body);
          reject(
            new MongoCryptAzureKMSRequestError(
              'Unable to complete request.',
              response.statusCode,
              response
            )
          );
        } catch {
          reject(
            new MongoCryptAzureKMSRequestError(
              'Unable to complete request - unknown error.',
              response.statusCode
            )
          );
        }
      } else {
        try {
          const response = JSON.parse(body);
          resolve(response);
        } catch {
          reject(
            new MongoCryptAzureKMSRequestError(
              'Unable to complete request - malformed JSON response.',
              response.statusCode
            )
          );
        }
      }
    }
    const request = http
      .get(url, options, response => {
        let body = '';
        response.on('data', chunk => (body += chunk));
        response.on('end', () => processBody(body, response));
      })
      .on('error', error => reject(error))
      .on('timeout', () =>
        request.destroy(new MongoCryptAzureKMSRequestError(`request timed out after 10000ms`))
      )
      .end();
  });
}

/**
 * @ignore
 * exported only for testing purposes in the driver
 *
 * @param {http.RequestOptions} options
 * @returns {Promise<any>}
 */
async function fetchAzureKMSToken(options) {
  const url = new URL('http://169.254.169.254/metadata/identity/oauth2/token');

  url.searchParams.append('api-version', '2018-02-01');
  url.searchParams.append('resource', 'https://vault.azure.net/');
  url.searchParams.append('Metadata', 'true');

  const token = await executeTokenRequest(url, options);

  if (!token.access_token) {
    throw new MongoCryptAzureKMSRequestError(
      'Malformed response body - missing field `access_token`.'
    );
  }

  if (!token.expires_in) {
    throw new MongoCryptAzureKMSRequestError(
      'Malformed response body - missing field `expires_in`.'
    );
  }

  const expiresInMilliseconds = (() => {
    try {
      const expiresInSeconds = Number.parseInt(token.expires_in);
      return expiresInSeconds * 1000;
    } catch {
      throw new MongoCryptAzureKMSRequestError(
        'Malformed response body - unable to parse int from `expires_in` field.'
      );
    }
  })();

  return {
    accessToken: token.access_token,
    expiresInMilliseconds,
    expiresOnTimestamp: Date.now() + expiresInMilliseconds
  };
}

/**
 * @param {import('../../index').KMSProviders} kmsProviders
 * @ignore
 */
async function loadAzureCredentials(kmsProviders) {
  if (azureIdentityModule == null) {
    try {
      // Ensure you always wrap an optional require in the try block NODE-3199
      azureIdentityModule = require('@azure/identity');
      // eslint-disable-next-line no-empty
    } catch {}
  }

  if (azureIdentityModule == null) {
    return kmsProviders;
  }

  if (tokenCacheProvider == null) {
    tokenCacheProvider = new AzureCredentialCache();
  }

  const token = await tokenCacheProvider.getToken();
  return { ...kmsProviders, azure: { accessToken: token.token } };
}

module.exports = { loadAzureCredentials, AzureCredentialCache, fetchAzureKMSToken };
