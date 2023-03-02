'use strict';

const {
  MongoCryptAzureKMSRequestError,
  MongoCryptKMSRequestNetworkTimeoutError
} = require('../errors');
const utils = require('./utils');

const MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS = 6000;

/**
 * @ignore
 */
class AzureCredentialCache {
  constructor() {
    /**
     * @type { { accessToken: string, expiresOnTimestamp: number } | null}
     */
    this.cachedToken = null;
  }

  async getToken() {
    if (this.needsRefresh(this.cachedToken)) {
      this.cachedToken = await this._getToken();
    }

    return { accessToken: this.cachedToken.accessToken };
  }

  needsRefresh(token) {
    if (token == null) {
      return true;
    }
    const timeUntilExpirationMS = token.expiresOnTimestamp - Date.now();
    return timeUntilExpirationMS <= MINIMUM_TOKEN_REFRESH_IN_MILLISECONDS;
  }

  /**
   * @ignore
   * exposed for testing
   */
  resetCache() {
    this.cachedToken = null;
  }

  /**
   * @ignore
   * exposed for testing
   */
  _getToken() {
    return fetchAzureKMSToken();
  }
}
/**
 * @type{AzureCredentialCache}
 */
let tokenCache = new AzureCredentialCache();

/**
 * @param { {body: string, status: number }} response
 * @returns { Promise<{ accessToken: string, expiresOnTimestamp: number } >}
 */
async function parseResponse(response) {
  const { status, body: rawBody } = response;

  /**
   * @type { { access_token?: string, expires_in?: string} }
   */
  const body = (() => {
    try {
      return JSON.parse(rawBody);
    } catch {
      throw new MongoCryptAzureKMSRequestError('Malformed JSON body in GET request.');
    }
  })();

  if (status !== 200) {
    throw new MongoCryptAzureKMSRequestError('Unable to complete request.', body);
  }

  if (!body.access_token) {
    throw new MongoCryptAzureKMSRequestError(
      'Malformed response body - missing field `access_token`.'
    );
  }

  if (!body.expires_in) {
    throw new MongoCryptAzureKMSRequestError(
      'Malformed response body - missing field `expires_in`.'
    );
  }

  const expiresInMS = Number(body.expires_in) * 1000;
  if (Number.isNaN(expiresInMS)) {
    throw new MongoCryptAzureKMSRequestError(
      'Malformed response body - unable to parse int from `expires_in` field.'
    );
  }

  return {
    accessToken: body.access_token,
    expiresOnTimestamp: Date.now() + expiresInMS
  };
}

/**
 * @param {object} options
 * @param {object | undefined} [options.headers]
 * @param {URL | undefined} [options.url]
 */
function prepareRequest(options) {
  const url =
    options.url == null
      ? new URL('http://169.254.169.254/metadata/identity/oauth2/token')
      : new URL(options.url);

  url.searchParams.append('api-version', '2018-02-01');
  url.searchParams.append('resource', 'https://vault.azure.net');

  const headers = { ...options.headers, 'Content-Type': 'application/json', Metadata: true };
  return { headers, url };
}

/**
 * @ignore
 * exported only for testing purposes in the driver
 *
 * @param {object} options
 * @param {object | undefined} [options.headers]
 * @param {URL | undefined} [options.url]
 * @returns {Promise<{ accessToken: string, expiresOnTimestamp: number }>}
 */
async function fetchAzureKMSToken(options = {}) {
  const { headers, url } = prepareRequest(options);
  try {
    const response = await utils.get(url, { headers });
    return parseResponse(response);
  } catch (error) {
    if (error instanceof MongoCryptKMSRequestNetworkTimeoutError) {
      throw new MongoCryptAzureKMSRequestError('Azure KMS request timed out after 10s');
    }
    throw error;
  }
}

/**
 * @param {import('../../index').KMSProviders} kmsProviders
 * @ignore
 */
async function loadAzureCredentials(kmsProviders) {
  const azure = await tokenCache.getToken();
  return { ...kmsProviders, azure };
}

module.exports = { loadAzureCredentials, AzureCredentialCache, fetchAzureKMSToken, tokenCache };
