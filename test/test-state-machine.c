#include <stdio.h>
#include <stdlib.h>

#include <mongocrypt.h>
#include <mongocrypt-decryptor.h>
#include <mongocrypt-encryptor.h>

static bool
encrypt (mongocrypt_t *crypt)
{
   mongocrypt_encryptor_t *request;
   const mongocrypt_key_query_t *key_query = NULL;
   mongocrypt_binary_t *schema;
   mongocrypt_binary_t *marking_response = NULL;
   mongocrypt_key_decrypt_request_t *kms_request = NULL;
   mongocrypt_key_decrypt_request_t *kms_response = NULL;
   mongocrypt_binary_t *key_doc = NULL;
   mongocrypt_encryptor_state_t state;
   bool res;

   schema = mongocrypt_binary_new ();

   request = mongocrypt_encryptor_new (crypt, NULL);
   state = mongocrypt_encryptor_state (request);

   /* Crank the state machine until we reach a terminal state */
   while (true) {
      switch (state) {
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS:
	 /* Driver: when the encryptor is first created,
	    it needs a namespace to begin the encryption
	    process. Add the namespace at this step. */
	 state = mongocrypt_encryptor_add_ns (request, "test.test", NULL);
	 break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA:
	 /* Driver: when the encryptor needs a schema
	    for the given namespace, run listCollections
	    with a filter for that ns, and also with
	    "options.validator.$jsonSchema": {"$exists": True}.
	    Then, give the resulting document or NULL
	    to the encrypter. */
	 state = mongocrypt_encryptor_add_schema (request, schema, NULL);
	 break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS:
	 /* Driver: when the encryptor is ready for
	    markings, first get the schema from the
	    encryptor. If you have just added the schema
	    via add_schema, you may skip this step. Then,
	    formulate a mongocryptd request driver-side,
	    send that request to mongocryptd, and
	    return the response to the encryptor. */
	 schema = mongocrypt_encryptor_get_schema (request, NULL);
	 /* marking_request = build_mongocryptd_command (schema); */
	 /* marking_response = mongocryptd.run_command (marking_request); */
	 state = mongocrypt_encryptor_add_markings (request, marking_response, NULL);
	 break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS:
	 /* Driver: when the encryptor needs keys, ask
	    it for a key query, run that query against
	    the database, and return the keys to
	    the encryptor.

	    When iterating over the resulting cursor,
	    call this method once per key document
            in the cursor. */
	 key_query = mongocrypt_encryptor_get_key_query (request, NULL);
	 /* cursor = collection.find (key_query);
            for key_doc in cursor: */
	 mongocrypt_encryptor_add_key (request,
				       NULL,
				       key_doc,
				       NULL);
	 state = mongocrypt_encryptor_done_adding_keys (request);
	 break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS_DECRYPTED:
	 /* Driver: when the encryptor needs keys decrypted
	    by KMS, ask it for the next KMS request, run
	    that request against KMS, and return the
	    response to the encryptor.

	    This state may occur multiple times in a row.
	    Continue to run KMS requests and return the
	    responses to the encryptor until the encryptor
	    advances its state.

	    KMS requests may also be run in parallel. To get
	    all the requests out before adding any responses,
            call next_kms_request () until it returns NULL.
	    Once all KMS requests are retrieved, they may be
	    run against the KMS server in parallel, and the
	    resulting decrypted keys added to the encryptor
	    in any order.

	    When the encryptor detects that all decrypted
	    keys have been added, it will progress to the next
            state automatically. */
	 kms_request = mongocrypt_encryptor_next_kms_request (request);
	 /* kms_response = run_kms_query (kms_request); */
	 state = mongocrypt_encryptor_add_decrypted_key (request, kms_response);
	 break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NO_ENCRYPTION_NEEDED:
	 printf ("No encryption needed\n");
	 res = true;
	 goto done;

      case MONGOCRYPT_ENCRYPTOR_STATE_ENCRYPTED:
	 printf ("Completed encryption\n");
	 res = true;
	 goto done;

      case MONGOCRYPT_ENCRYPTOR_STATE_ERROR:
	 printf ("Error, could not complete encryption\n");
	 res = false;
	 goto done;

      default:
	 printf ("Error, unknown encryption state\n");
	 abort ();
      }
   }

 done:
   mongocrypt_encryptor_destroy (request);

   return res;
}


static bool
decrypt (mongocrypt_t *crypt)
{
   mongocrypt_decryptor_t *request;
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *encrypted_doc = NULL;
   mongocrypt_binary_t *key_doc = NULL;
   mongocrypt_key_decrypt_request_t *kms_request = NULL;
   mongocrypt_key_decrypt_request_t *kms_response = NULL;
   const mongocrypt_key_query_t *key_query = NULL;
   bool res;

   request = mongocrypt_decryptor_new (crypt, NULL);
   state = mongocrypt_decryptor_state (request);

   /* Crank the state machine until we reach a terminal state */
   while (true) {
      switch (state) {
      case MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC:
	 /* Driver: when the decryptor is first created,
	    it needs a document to decrypt to begin the
	    state machine. Add the encrypted document
	    at this step. */
	 state = mongocrypt_decryptor_add_doc (request, encrypted_doc, NULL);
	 break;

      case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS:
	 /* Driver: when the decryptor needs keys,
	    ask it for a key query, run that query
	    against the database, and return the keys
	    to the decryptor.

	    When iterating over the resulting cursor,
	    call the add_key method once per key document
	    in the cursor. Once all keys have been added
	    to the decryptor, call done_adding_keys (). */
	 key_query = mongocrypt_decryptor_get_key_query (request, NULL);
	 /* cursor = collection.find (key_query);
	    for key_doc in cursor: */
	 mongocrypt_decryptor_add_key (request,
				       NULL,
				       key_doc,
				       NULL);
	 state = mongocrypt_decryptor_done_adding_keys (request);
	 break;

      case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS_DECRYPTED:
	 /* Driver: when the decryptor needs keys decrypted
	    by KMS, ask it for the next KMS request, run
	    that request against KMS, and return the
	    response to the decryptor.

	    This state may occur multiple times in a row.
	    Continue to run KMS requests and return the
	    responses to the decryptor until the decryptor
	    advances its state.

	    KMS requests may also be run in parallel. To get
	    all the requests out before adding any responses,
            call next_kms_request () until it returns NULL.
	    Once all KMS requests are retrieved, they may be
	    run against the KMS server in parallel, and the
	    resulting decrypted keys added to the decryptor
	    in any order.

	    When the decryptor detects that all decrypted
	    keys have been added, it will progress to the next
            state automatically. */
	 kms_request = mongocrypt_decryptor_next_kms_request (request);
	 /* kms_response = run_kms_query (kms_request); */
	 state = mongocrypt_decryptor_add_decrypted_key (request, kms_response);
	 break;


      case MONGOCRYPT_DECRYPTOR_STATE_NO_DECRYPTION_NEEDED:
	 printf ("No decryption needed\n");
	 res = true;
	 goto done;

      case MONGOCRYPT_DECRYPTOR_STATE_DECRYPTED:
	 printf ("Completed decryption\n");
	 res = false;
	 goto done;

      case MONGOCRYPT_DECRYPTOR_STATE_ERROR:
	 printf ("Error, could not complete encryption\n");
	 res = false;
	 goto done;

      default:
	 printf ("Error, unknown encryption state\n");
	 abort ();
      }
   }

 done:
   return res;
}

int
main ()
{
   mongocrypt_t *crypt;

   crypt = mongocrypt_new (NULL, NULL);

   encrypt (crypt);
   decrypt (crypt);

   mongocrypt_destroy (crypt);
}
