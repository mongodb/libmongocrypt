#include "kms_message/kms_message.h"
#include "kms_message_private.h"
#include <src/hexlify.h>
#include <src/kms_kv_list.h>
#include <src/kms_message/kms_b64.h>
#include <src/kms_port.h>
#include <src/kms_request_str.h>
#include <stdio.h>
#include <stdlib.h>

/* Fuzzer for targeted the kms_response_parser_feed and
 * kms_request_new functions.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kms_response_parser_t *parser = NULL;
    parser = kms_response_parser_new();
    if (parser != NULL) {
        kms_response_parser_feed(parser, data, size);
        kms_response_parser_destroy(parser);
    }

    if (size > 50) {
        /* Create two null-terminated strings */
        char *method = malloc(25);
        memcpy(method, data, 24);
        method[24] = '\0';
        data += 24;
        size -= 24;

        char *uri_path = malloc(25);
        memcpy(uri_path, data, 24);
        uri_path[24] = '\0';

        kms_request_t *request = NULL;
        request = kms_request_new(method, uri_path, NULL);
        if (request != NULL) {
            kms_request_destroy(request);
        }
        free(method);
        free(uri_path);
    }
    return 0;
}
