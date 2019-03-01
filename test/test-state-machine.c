/* TODO: rename to example-state-machine.c? */
#include <stdio.h>
#include <stdlib.h>

#include <mongocrypt.h>
#include <mongocrypt-decryptor.h>
#include <mongocrypt-encryptor.h>

static bool
_auto_encrypt (mongocrypt_t *crypt)
{
   mongocrypt_encryptor_t *encryptor;
   const mongocrypt_binary_t *key_filter = NULL;
   mongocrypt_binary_t *list_collections_reply;
   const mongocrypt_binary_t *schema;
   mongocrypt_binary_t *marking_response = NULL;
   const mongocrypt_binary_t *msg;
   mongocrypt_key_decryptor_t *key_decryptor = NULL;
   mongocrypt_binary_t *key_doc = NULL;
   mongocrypt_encryptor_state_t state;
   mongocrypt_status_t *status;
   bool res = false;
   uint32_t to_read;
   const uint32_t max_bytes_to_read = 1024;

   list_collections_reply = NULL;
   encryptor = mongocrypt_encryptor_new (crypt, NULL);
   state = mongocrypt_encryptor_add_ns (encryptor, "test.test", NULL);
   status = mongocrypt_status_new ();

   /* Crank the state machine until we reach a terminal state */
   while (true) {
      switch (state) {
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS:
         /* Driver: when the encryptor is first created,
            it needs a namespace to begin the encryption
            process. Add the namespace at this step. */
         state = mongocrypt_encryptor_add_ns (encryptor, "test.test", NULL);
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA:
         /* Driver: when the encryptor needs a schema
            for the given namespace, run listCollections
            with a filter for that ns, and also with
            "options.validator.$jsonSchema": {"$exists": True}.
            Then, give the resulting document or NULL
            to the encryptor. */
         state = mongocrypt_encryptor_add_collection_info (
            encryptor, list_collections_reply, NULL);
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS:
         /* Driver: when the encryptor is ready for
            markings, first get the schema from the
            encryptor. If you have just added the schema
            via add_schema, you may skip this step. Then,
            formulate a mongocryptd request driver-side,
            send that request to mongocryptd, and
            return the response to the encryptor. */
         schema = mongocrypt_encryptor_get_schema (encryptor, NULL);
         /* marking_request = build_mongocryptd_command (schema); */
         /* marking_response = mongocryptd.run_command (marking_request); */
         state = mongocrypt_encryptor_add_markings (
            encryptor, marking_response, NULL);
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS:
         /* Driver: when the encryptor needs keys, ask
            it for a key filter, run a find command with
           that filter against the database, and return
           the keys to the encryptor.

            When iterating over the resulting cursor,
            call this method once per key document
                 in the cursor. */
         key_filter = mongocrypt_encryptor_get_key_filter (encryptor, NULL);
         /* cursor = collection.find (key_filter);
                 for key_doc in cursor: */
         mongocrypt_encryptor_add_key (encryptor, NULL, key_doc, NULL);
         state = mongocrypt_encryptor_done_adding_keys (encryptor);
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
         key_decryptor = mongocrypt_encryptor_next_key_decryptor (encryptor);
         msg = mongocrypt_key_decryptor_msg (key_decryptor, NULL, status);
         /* send msg to kms */
         to_read = mongocrypt_key_decryptor_bytes_needed (key_decryptor,
                                                          max_bytes_to_read);
         while (to_read > 0) {
            uint32_t bytes_read = 0;
            /* recv to_read from the kms socket */
            if (!mongocrypt_key_decryptor_feed (
                   key_decryptor, bytes_read, status)) {
               goto done;
            }
            to_read = mongocrypt_key_decryptor_bytes_needed (key_decryptor,
                                                             max_bytes_to_read);
         }

         state =
            mongocrypt_encryptor_add_decrypted_key (encryptor, key_decryptor);
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
   mongocrypt_encryptor_destroy (encryptor);
   mongocrypt_status_destroy (status);

   return res;
}


static bool
_auto_decrypt (mongocrypt_t *crypt)
{
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *encrypted_doc = NULL;
   mongocrypt_binary_t *key_doc = NULL;
   mongocrypt_key_decryptor_t *key_decryptor = NULL;
   const mongocrypt_binary_t *key_filter = NULL;
   bool res = false;
   const mongocrypt_binary_t *msg;
   uint32_t to_read;
   const uint32_t max_bytes_to_read = 1024;
   mongocrypt_status_t* status;

   decryptor = mongocrypt_decryptor_new (crypt, NULL);
   state = mongocrypt_decryptor_state (decryptor);
   status = mongocrypt_status_new ();

   /* Crank the state machine until we reach a terminal state */
   while (true) {
      switch (state) {
      case MONGOCRYPT_DECRYPTOR_STATE_NEED_DOC:
         /* Driver: when the decryptor is first created,
            it needs a document to decrypt to begin the
            state machine. Add the encrypted document
            at this step. */
         state = mongocrypt_decryptor_add_doc (decryptor, encrypted_doc, NULL);
         break;

      case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS:
         /* Driver: when the decryptor needs keys,
            ask it for a key filter, run a find command
            with that filter against the database, and return the keys
            to the decryptor.

            When iterating over the resulting cursor,
            call the add_key method once per key document
            in the cursor. Once all keys have been added
            to the decryptor, call done_adding_keys (). */
         key_filter = mongocrypt_decryptor_get_key_filter (decryptor, NULL);
         /* cursor = collection.find (key_query);
            for key_doc in cursor: */
         mongocrypt_decryptor_add_key (decryptor, NULL, key_doc, NULL);
         state = mongocrypt_decryptor_done_adding_keys (decryptor);
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
         key_decryptor = mongocrypt_decryptor_next_key_decryptor (decryptor);
         msg = mongocrypt_key_decryptor_msg (key_decryptor, NULL, status);
         /* send msg to kms */
         to_read = mongocrypt_key_decryptor_bytes_needed (key_decryptor,
                                                          max_bytes_to_read);
         while (to_read > 0) {
            uint32_t bytes_read = 0;
            /* recv to_read from the kms socket */
            if (!mongocrypt_key_decryptor_feed (
                   key_decryptor, bytes_read, status)) {
               goto done;
            }
            to_read = mongocrypt_key_decryptor_bytes_needed (key_decryptor,
                                                             max_bytes_to_read);
         }

         state =
            mongocrypt_decryptor_add_decrypted_key (decryptor, key_decryptor);
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
   mongocrypt_decryptor_destroy (decryptor);
   mongocrypt_status_destroy (status);
   return res;
}

int
main ()
{
   mongocrypt_t *crypt;

   crypt = mongocrypt_new (NULL, NULL);

   _auto_encrypt (crypt);
   _auto_decrypt (crypt);

   mongocrypt_destroy (crypt);
}
