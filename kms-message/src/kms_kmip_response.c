#include "kms_message/kms_kmip_response.h"
#include "kms_kmip_response_private.h"

#include <stdlib.h>

uint8_t * kms_kmip_response_to_bytes (kms_kmip_response_t *res, uint32_t *len) {
    *len = res->len;
    return res->data;
}

void kms_kmip_response_destroy (kms_kmip_response_t *res) {
    if (!res) {
        return;
    }
    free (res->data);
    free (res);
}
