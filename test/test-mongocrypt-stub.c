#include <stdio.h>
#include <mongocrypt.h>

int main() {
    printf("Hello mongocrypt-stub!\n");
    mongocrypt_t* crypt;
    mongocrypt_request_t* request;

    crypt = mongocrypt_new (NULL, NULL);
    request = mongocrypt_encrypt_start(crypt, NULL, NULL, NULL, NULL);

    mongocrypt_request_destroy (request);
    mongocrypt_destroy (crypt);
}