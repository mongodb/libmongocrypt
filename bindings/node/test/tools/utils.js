'use strict';

module.exports = Object.create(null);

function awsCredentialProvidersIsInstalled() {
  try {
    require.resolve('@aws-sdk/credential-providers');
    return true;
  } catch {
    return false;
  }
}

module.exports.awsCredentialProvidersIsInstalled = awsCredentialProvidersIsInstalled;
