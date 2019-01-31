#include <stdio.h>
#include <mongocrypt.h>

int
main ()
{
   printf ("Hello mongocrypt-stub!\n");
   mongocrypt_t *crypt;
   mongocrypt_request_t *request;
   mongocrypt_status_t *status;

   crypt = mongocrypt_new (NULL, NULL);
   status = mongocrypt_status_new ();
   request = mongocrypt_encrypt_start (crypt, NULL, NULL, NULL, status);

   mongocrypt_status_destroy (status);
   mongocrypt_request_destroy (request);
   mongocrypt_destroy (crypt);
}