#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "mongocrypt.h"
#include "mongocrypt-crypto-private.h"
#include "mongocrypt-buffer-private.h"
#include "mongocrypt-status-private.h"

START_TEST(test_hmac_sha512_no_buffer_overflow)
{
    /* Invariant: Buffer reads in _mongocrypt_hmac_sha_512 and related crypto
     * functions never exceed the declared length of destination buffers,
     * even when plaintext->len causes unaligned computation to exceed
     * intermediate buffer sizes. */

    /* Test payloads: various plaintext sizes that could trigger overflow
     * in the unaligned memcpy at line 553 */
    uint32_t payload_sizes[] = {
        4096,   /* 2x typical block-aligned buffer - exploit case */
        65536,  /* 10x oversized input */
        63,     /* boundary: one less than block size */
        32,     /* valid small input */
    };
    int num_payloads = sizeof(payload_sizes) / sizeof(payload_sizes[0]);

    for (int i = 0; i < num_payloads; i++) {
        mongocrypt_t *crypt = mongocrypt_new();
        mongocrypt_status_t *status = mongocrypt_status_new();

        _mongocrypt_buffer_t key, iv, plaintext, ciphertext;
        _mongocrypt_buffer_init(&key);
        _mongocrypt_buffer_init(&iv);
        _mongocrypt_buffer_init(&plaintext);
        _mongocrypt_buffer_init(&ciphertext);

        /* Allocate key (64 bytes for HMAC-SHA-512 + AES-256) */
        key.len = 64;
        key.data = calloc(1, key.len);
        key.owned = true;

        /* Allocate IV (16 bytes) */
        iv.len = 16;
        iv.data = calloc(1, iv.len);
        iv.owned = true;

        /* Allocate oversized plaintext */
        plaintext.len = payload_sizes[i];
        plaintext.data = calloc(1, plaintext.len);
        plaintext.owned = true;
        memset(plaintext.data, 'A', plaintext.len);

        /* Allocate ciphertext buffer large enough */
        ciphertext.len = plaintext.len + 256;
        ciphertext.data = calloc(1, ciphertext.len);
        ciphertext.owned = true;

        /* Call the encryption function - it should either succeed safely
         * or return an error, but never overflow buffers */
        uint32_t bytes_written = 0;
        bool ret = _mongocrypt_do_encryption(
            crypt->crypto, &iv, NULL, &key, &plaintext, &ciphertext,
            &bytes_written, status);

        /* The function must either succeed with valid output or fail gracefully */
        if (ret) {
            ck_assert_uint_le(bytes_written, ciphertext.len);
        }
        /* If it fails, that's also acceptable - no crash means no overflow */

        _mongocrypt_buffer_cleanup(&key);
        _mongocrypt_buffer_cleanup(&iv);
        _mongocrypt_buffer_cleanup(&plaintext);
        _mongocrypt_buffer_cleanup(&ciphertext);
        mongocrypt_status_destroy(status);
        mongocrypt_destroy(crypt);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_hmac_sha512_no_buffer_overflow);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}