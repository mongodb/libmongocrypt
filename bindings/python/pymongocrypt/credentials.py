# Copyright 2022-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
from collections import namedtuple
from datetime import datetime, timedelta

try:
    from pymongo_auth_aws.auth import aws_temp_credentials
    _HAVE_AUTH_AWS = True
except ImportError:
    _HAVE_AUTH_AWS = False

from pymongocrypt.errors import MongoCryptError

import requests


_azure_creds = namedtuple("_azure_creds", ["access_token", "expires_in"])
_azure_creds_cache = None


def _get_gcp_credentials():
    """Get on-demand GCP credentials"""
    metadata_host = os.getenv("GCE_METADATA_HOST") or "metadata.google.internal"
    url = "http://%s/computeMetadata/v1/instance/service-accounts/default/token" % metadata_host

    headers = {"Metadata-Flavor": "Google"}
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        msg = "unable to retrieve GCP credentials: %s" % e
        raise MongoCryptError(msg)

    if response.status_code != 200:
        msg = "Unable to retrieve GCP credentials: expected StatusCode 200, got StatusCode: %s. Response body:\n%s" % (response.status_code, response.content)
        raise MongoCryptError(msg)
    try:
        data = response.json()
    except Exception:
        raise MongoCryptError("unable to retrieve GCP credentials: error reading response body\n%s" % response.content)

    if not data.get("access_token"):
        msg = "unable to retrieve GCP credentials: got unexpected empty accessToken from GCP Metadata Server. Response body: %s" % response.content
        raise MongoCryptError(msg)

    return {'accessToken': data['access_token']}


def _get_azure_credentials():
    """Get on-demand Azure credentials"""
    global _azure_creds_cache
    # Credentials are considered expired when: Expiration - now < 1 mins.
    creds = _azure_creds_cache
    if creds:
        if creds.expires_in - datetime.utcnow() < timedelta(seconds=60):
            _azure_creds_cache = None
        else:
            return { 'accessToken': creds.access_token }

    url = "http://169.254.169.254/metadata/identity/oauth2/token"
    url += "?api-version=2018-02-01"
    url += "&resource=https://vault.azure.net"
    headers = { "Metadata": "true", "Accept": "application/json" }
    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        msg = "Failed to acquire IMDS access token: %s" % e
        raise MongoCryptError(msg)

    if response.status_code != 200:
        msg = "Failed to acquire IMDS access token."
        raise MongoCryptError(msg)
    try:
        data = response.json()
    except Exception:
        raise MongoCryptError("Azure IMDS response must be in JSON format.")

    for key in ["access_token", "expires_in"]:
        if not data.get(key):
            msg = "Azure IMDS response must contain %s, but was %s."
            msg = msg % (key, response.content)
            raise MongoCryptError(msg)

    try:
        expires_in = int(data["expires_in"])
    except ValueError:
        raise MongoCryptError('Azure IMDS response must contain "expires_in" integer, but was %s.' % response.content)

    expiration_time = datetime.utcnow() + timedelta(seconds=expires_in)
    _azure_creds_cache = _azure_creds(data['access_token'], expiration_time)
    return { 'accessToken': data['access_token'] }


def _ask_for_kms_credentials(kms_providers):
    """Get on-demand kms credentials.

    This is a separate function so it can be overridden in unit tests."""
    global _azure_creds_cache
    on_demand_aws = 'aws' in kms_providers and not len(kms_providers['aws'])
    on_demand_gcp = 'gcp' in kms_providers and not len(kms_providers['gcp'])
    on_demand_azure = 'azure' in kms_providers and not len(kms_providers['azure'])

    if not any([on_demand_aws, on_demand_gcp, on_demand_azure]):
        return {}
    creds = {}
    if on_demand_aws:
        if not _HAVE_AUTH_AWS:
            raise RuntimeError(
                "On-demand AWS credentials require pymongo-auth-aws: "
                "install with: python -m pip install 'pymongo[aws]'"
            )
        aws_creds = aws_temp_credentials()
        creds_dict = {"accessKeyId": aws_creds.username, "secretAccessKey": aws_creds.password}
        if aws_creds.token:
            creds_dict["sessionToken"] = aws_creds.token
        creds['aws'] = creds_dict
    if on_demand_gcp:
        creds['gcp'] = _get_gcp_credentials()
    if on_demand_azure:
        try:
            creds['azure'] = _get_azure_credentials()
        except Exception:
            _azure_creds_cache = None
            raise
    return creds
