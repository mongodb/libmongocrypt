/*
 * Copyright 2020-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mongocrypt-endpoint-private.h>

#include "test-mongocrypt.h"

static void _test_mongocrypt_endpoint(_mongocrypt_tester_t *tester) {
    _mongocrypt_endpoint_t *endpoint;
    mongocrypt_status_t *status;
    _mongocrypt_endpoint_parse_opts_t opts;

    status = mongocrypt_status_new();

    endpoint = _mongocrypt_endpoint_new("https://kevin.keyvault.azure.net:443/some/path/?query=value",
                                        -1,
                                        NULL /* opts */,
                                        status);
    ASSERT_STREQUAL(endpoint->host, "kevin.keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->domain, "keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->subdomain, "kevin");
    ASSERT_STREQUAL(endpoint->protocol, "https");
    ASSERT_STREQUAL(endpoint->port, "443");
    ASSERT_STREQUAL(endpoint->path, "some/path");
    ASSERT_STREQUAL(endpoint->query, "query=value");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    endpoint = _mongocrypt_endpoint_new("kevin.keyvault.azure.net:443", -1, NULL /* opts */, status);
    ASSERT_STREQUAL(endpoint->host, "kevin.keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->domain, "keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->subdomain, "kevin");
    BSON_ASSERT(!endpoint->protocol);
    ASSERT_STREQUAL(endpoint->port, "443");
    BSON_ASSERT(!endpoint->path);
    BSON_ASSERT(!endpoint->query);
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    endpoint = _mongocrypt_endpoint_new("kevin.keyvault.azure.net", -1, NULL /* opts */, status);
    ASSERT_STREQUAL(endpoint->host, "kevin.keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->domain, "keyvault.azure.net");
    ASSERT_STREQUAL(endpoint->subdomain, "kevin");
    BSON_ASSERT(!endpoint->protocol);
    BSON_ASSERT(!endpoint->port);
    BSON_ASSERT(!endpoint->path);
    BSON_ASSERT(!endpoint->query);
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    endpoint = _mongocrypt_endpoint_new("malformed", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid endpoint, expected dot separator in host, but got: malformed");
    _mongocrypt_endpoint_destroy(endpoint);

    /* Test a colon in the path does not parse as a port. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com/path:8080", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->host, "vault.example.com");
    ASSERT_STREQUAL(endpoint->domain, "example.com");
    BSON_ASSERT(!endpoint->port);
    ASSERT_STREQUAL(endpoint->path, "path:8080");
    ASSERT_STREQUAL(endpoint->host_and_port, "vault.example.com");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* Test a colon in the query does not parse as a port. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com?query=a:b", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->host, "vault.example.com");
    BSON_ASSERT(!endpoint->port);
    ASSERT_STREQUAL(endpoint->query, "query=a:b");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* Test a port followed by a query, with no path. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com:443?query=value", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->host, "vault.example.com");
    ASSERT_STREQUAL(endpoint->port, "443");
    ASSERT_STREQUAL(endpoint->query, "query=value");
    ASSERT_STREQUAL(endpoint->host_and_port, "vault.example.com:443");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* An endpoint may contain only the characters RFC 3986 permits in a URI. This is defense in depth:
     * each context an endpoint reaches is validated where it is used. */
    const char *const invalid[] = {
        "a\r\nX-Injected: injected.example.com",        /* forges a header */
        "a\r\n\r\nGET /evil.example.com",               /* ends the header section */
        "example.com\", \"sub\": \"victim@example.com", /* injects a JWT claim */
        "example.com\\x.example.com",                   /* backslash */
        "example .com",                                 /* space */
        "example.com\x7f",                              /* DEL */
        "exampl\xc3\xa9.com",                           /* non-ASCII */
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        endpoint = _mongocrypt_endpoint_new(invalid[i], -1, NULL /* opts */, status);
        BSON_ASSERT(!endpoint);
        ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint");
    }

    /* The offending byte is reported by offset and hex value. The endpoint itself is not echoed: it is
     * not yet validated here, and may contain a CR or LF that would forge a line in a consumer's log. */
    endpoint = _mongocrypt_endpoint_new("example .com", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint at offset 7: 0x20");

    endpoint = _mongocrypt_endpoint_new("a\r\nX-Injected: injected.example.com", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint at offset 1: 0x0d");

    /* An IPv6 literal is rejected. The parse has no bracket handling, so such an endpoint was never
     * usable. Without a dot it is rejected earlier still, for
     * lacking a subdomain separator. */
    memset(&opts, 0, sizeof(opts));
    opts.allow_empty_subdomain = true;
    endpoint = _mongocrypt_endpoint_new("[2001:db8::1]:443", -1, &opts, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint host");

    /* One with an embedded dot reaches the host check without the option. */
    endpoint = _mongocrypt_endpoint_new("[::ffff:192.0.2.1]", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint host");

    /* An IPv4 literal is accepted, as before. */
    endpoint = _mongocrypt_endpoint_new("192.0.2.1:443", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->host, "192.0.2.1");
    ASSERT_STREQUAL(endpoint->port, "443");
    ASSERT_STREQUAL(endpoint->host_and_port, "192.0.2.1:443");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* Percent-encoding must be well formed. */
    endpoint = _mongocrypt_endpoint_new("example.com/%zz", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid percent-encoding in endpoint at offset 13: 0x7a");

    /* A '%' at the end of the string: the second hex digit is the NUL terminator. */
    endpoint = _mongocrypt_endpoint_new("example.com/%2", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid percent-encoding in endpoint at offset 14: 0x00");

    endpoint = _mongocrypt_endpoint_new("example.com/a%2Fb", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->path, "a%2Fb");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* A host must be an RFC 3986 `reg-name`. The gen-delims are rejected; the parse already ends the host
     * at ':', '/', and '?', so this covers '#', '@', and the brackets of an IP-literal. */
    const char *const invalid_hosts[] = {
        "vault.example.com@evil.example.com", /* userinfo separator */
        "vault.example.com#frag",
        "[2001:db8::1]",
    };
    memset(&opts, 0, sizeof(opts));
    opts.allow_empty_subdomain = true;
    for (size_t i = 0; i < sizeof(invalid_hosts) / sizeof(invalid_hosts[0]); i++) {
        endpoint = _mongocrypt_endpoint_new(invalid_hosts[i], -1, &opts, status);
        BSON_ASSERT(!endpoint);
        ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint host");
    }

    endpoint = _mongocrypt_endpoint_new("vault.example.com@evil.example.com", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint host: 0x40");

    /* The sub-delims are permitted in a reg-name, so they are permitted here. An '&' reaching the Azure
     * OAuth request body is prevented by percent-encoding it into the scope, not by this check. */
    const char *const valid_hosts[] = {
        "vault.example.com&x",
        "vault.example.com=x",
        "vault.example.com;x",
        "vault.example.com,x",
        "vault.example.com~x",
        "vault.example.com%41",
    };
    for (size_t i = 0; i < sizeof(valid_hosts) / sizeof(valid_hosts[0]); i++) {
        endpoint = _mongocrypt_endpoint_new(valid_hosts[i], -1, NULL /* opts */, status);
        BSON_ASSERT(endpoint);
        ASSERT_STREQUAL(endpoint->host, valid_hosts[i]);
        BSON_ASSERT(mongocrypt_status_ok(status));
        _mongocrypt_endpoint_destroy(endpoint);
    }

    /* The host check does not apply to the path or query, which may contain reserved characters. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com/p&q?a=b&c=d", -1, NULL /* opts */, status);
    BSON_ASSERT(endpoint);
    ASSERT_STREQUAL(endpoint->host, "vault.example.com");
    ASSERT_STREQUAL(endpoint->path, "p&q");
    ASSERT_STREQUAL(endpoint->query, "a=b&c=d");
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* A port may contain only digits. The port is appended to host_and_port, which is used as the Host
     * header and as the address to connect to. */
    const char *const invalid_ports[] = {
        "vault.example.com:44&3",
        "vault.example.com:443x",
        "vault.example.com:-1",
        "vault.example.com:44.3",
    };
    for (size_t i = 0; i < sizeof(invalid_ports) / sizeof(invalid_ports[0]); i++) {
        endpoint = _mongocrypt_endpoint_new(invalid_ports[i], -1, NULL /* opts */, status);
        BSON_ASSERT(!endpoint);
        ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint port");
    }

    /* The offset is relative to the start of the port. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com:44&3", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid character in endpoint port: 0x26");

    /* A colon with no port is rejected. */
    endpoint = _mongocrypt_endpoint_new("vault.example.com:", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid endpoint, expected a port after the colon");

    endpoint = _mongocrypt_endpoint_new("vault.example.com:/path", -1, NULL /* opts */, status);
    BSON_ASSERT(!endpoint);
    ASSERT_STATUS_CONTAINS(status, "Invalid endpoint, expected a port after the colon");

    /* A host without a dot separator is valid if the "allow_empty_subdomain"
     * option is true. */
    memset(&opts, 0, sizeof(opts));
    opts.allow_empty_subdomain = true;
    endpoint = _mongocrypt_endpoint_new("localhost", -1, &opts, status);
    ASSERT_STREQUAL(endpoint->host, "localhost");
    ASSERT_STREQUAL(endpoint->domain, "localhost");
    BSON_ASSERT(!endpoint->subdomain);
    BSON_ASSERT(!endpoint->protocol);
    BSON_ASSERT(!endpoint->port);
    BSON_ASSERT(!endpoint->path);
    BSON_ASSERT(!endpoint->query);
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    memset(&opts, 0, sizeof(opts));
    opts.allow_empty_subdomain = true;
    endpoint = _mongocrypt_endpoint_new("localhost:1234", -1, &opts, status);
    ASSERT_STREQUAL(endpoint->host, "localhost");
    ASSERT_STREQUAL(endpoint->domain, "localhost");
    BSON_ASSERT(!endpoint->subdomain);
    BSON_ASSERT(!endpoint->protocol);
    ASSERT_STREQUAL(endpoint->port, "1234");
    BSON_ASSERT(!endpoint->path);
    BSON_ASSERT(!endpoint->query);
    BSON_ASSERT(mongocrypt_status_ok(status));
    _mongocrypt_endpoint_destroy(endpoint);

    /* A host without a dot separator is invalid if the "allow_empty_subdomain"
     * option is false. */
    memset(&opts, 0, sizeof(opts));
    opts.allow_empty_subdomain = false;
    endpoint = _mongocrypt_endpoint_new("localhost", -1, &opts, status);
    ASSERT_STATUS_CONTAINS(status, "Invalid endpoint, expected dot separator in host, but got: localhost");
    BSON_ASSERT(!endpoint);

    mongocrypt_status_destroy(status);
}

static void _test_mongocrypt_apply_default_port(_mongocrypt_tester_t *tester) {
    char *endpoint;

    endpoint = bson_strdup("example.com");
    _mongocrypt_apply_default_port(&endpoint, "12");
    ASSERT_STREQUAL(endpoint, "example.com:12");
    bson_free(endpoint);

    endpoint = bson_strdup("example.com:34");
    _mongocrypt_apply_default_port(&endpoint, "12");
    ASSERT_STREQUAL(endpoint, "example.com:34");
    bson_free(endpoint);
}

void _mongocrypt_tester_install_endpoint(_mongocrypt_tester_t *tester) {
    INSTALL_TEST(_test_mongocrypt_endpoint);
    INSTALL_TEST(_test_mongocrypt_apply_default_port);
}
