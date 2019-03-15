/* TODO: rename to example-state-machine.c? */
#include <stdio.h>
#include <stdlib.h>

#include <mongocrypt.h>
#include <mongocrypt-decryptor.h>
#include <mongocrypt-encryptor.h>
#include <mongocrypt-key-broker.h>
#include <mongocrypt-status.h>

static bool
_decrypt_via_kms (mongocrypt_key_decryptor_t *key_decryptor,
                  mongocrypt_status_t *status)
{
   mongocrypt_binary_t *bytes_received = NULL;
   uint32_t to_read;
   const uint32_t max_bytes_to_read = 1024;
   const mongocrypt_binary_t *msg;

   msg = mongocrypt_key_decryptor_msg (key_decryptor, status);
   /* send_message_to_kms (msg); */
   to_read =
      mongocrypt_key_decryptor_bytes_needed (key_decryptor, max_bytes_to_read);
   while (to_read > 0) {
      /* recv to_read from the kms socket into bytes_received */
      if (!mongocrypt_key_decryptor_feed (
             key_decryptor, bytes_received, status)) {
         return false;
      }

      to_read = mongocrypt_key_decryptor_bytes_needed (key_decryptor,
                                                       max_bytes_to_read);
   }

   return true;
}

static bool
_fetch_and_decrypt_keys (mongocrypt_key_broker_t *kb)
{
   const mongocrypt_binary_t *filter;
   mongocrypt_binary_t *key_doc = NULL;
   mongocrypt_key_decryptor_t *key_decryptor = NULL;
   mongocrypt_status_t *status = mongocrypt_status_new ();
   bool res = false;

   /* First, get a filter to run against the
      key vault. Run a find command with this
      filter against the database. */
   filter = mongocrypt_key_broker_get_key_filter (kb, status);
   if (!filter) {
      printf ("error getting key filter: %s\n",
              mongocrypt_status_message (status));
      goto done;
   }

   /* Next, Add the resulting key documents to
      the key broker. */

   /* cursor = collection.find (filter); */
   /* for key_doc in cursor: */
   if (!mongocrypt_key_broker_add_key (kb, key_doc, status)) {
      printf ("error adding key: %s\n", mongocrypt_status_message (status));
      goto done;
   }

   /* Once all keys are added, signal the key broker. */
   if (!mongocrypt_key_broker_done_adding_keys (kb, status)) {
      printf ("couldn't add all keys\n");
      goto done;
   }

   /* Next, decrypt the keys. To do this, iterate
      through the key_decryptors returned by the
      key broker. For each key_decryptor, run the
      KMS request against KMS and return the response
      to the key broker. This may be done in parallel. */
   key_decryptor = mongocrypt_key_broker_next_decryptor (kb, status);
   while (key_decryptor) {
      if (!_decrypt_via_kms (key_decryptor, status)) {
         printf ("error decrypting key: %s\n",
                 mongocrypt_status_message (status));
         goto done;
      }

      key_decryptor = mongocrypt_key_broker_next_decryptor (kb, status);
   }

   /* Sometimes when next_decryptor returns NULL, it's an error */
   if (!mongocrypt_status_ok (status)) {
      printf ("error: %s\n", mongocrypt_status_message (status));
      goto done;
   }

   /* Otherwise, we are done! */
   res = true;

done:
   mongocrypt_status_destroy (status);

   return res;
}

static bool
_auto_encrypt (mongocrypt_t *crypt)
{
   mongocrypt_key_broker_t *kb;
   mongocrypt_encryptor_t *encryptor;
   mongocrypt_binary_t *list_collections_reply;
   const mongocrypt_binary_t *schema;
   mongocrypt_binary_t *marking_response = NULL;
   mongocrypt_encryptor_state_t state;
   mongocrypt_status_t *status;
   mongocrypt_status_t *error;
   bool res = false;

   list_collections_reply = NULL;
   encryptor = mongocrypt_encryptor_new (crypt);
   status = mongocrypt_status_new ();

   state = mongocrypt_encryptor_state (encryptor);

   /* Crank the state machine until we reach a terminal state */
   while (true) {
      switch (state) {
      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_NS:
         /* Driver: when the encryptor is first created,
            it needs a namespace to begin the encryption
            process. Add the namespace at this step. */
         state = mongocrypt_encryptor_add_ns (encryptor, "test.test");
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_SCHEMA:
         /* Driver: when the encryptor needs a schema
            for the given namespace, run listCollections
            with a filter for that ns, and also with
            "options.validator.$jsonSchema": {"$exists": True}.
            Then, give the resulting document or NULL
            to the encryptor. */
         state = mongocrypt_encryptor_add_collection_info (
            encryptor, list_collections_reply);
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_MARKINGS:
         /* Driver: when the encryptor is ready for
            markings, first get the schema from the
            encryptor. If you have just added the schema
            via add_schema, you may skip this step. Then,
            formulate a mongocryptd request driver-side,
            send that request to mongocryptd, and
            return the response to the encryptor. */
         schema = mongocrypt_encryptor_get_schema (encryptor);
         /* marking_request = build_mongocryptd_command (schema); */
         /* marking_response = mongocryptd.run_command (marking_request); */
         state = mongocrypt_encryptor_add_markings (
            encryptor, marking_response);
         break;

      case MONGOCRYPT_ENCRYPTOR_STATE_NEED_KEYS:
         /* Driver: when the encryptor needs keys,
       transition to talking to its key broker. */
         kb = mongocrypt_encryptor_get_key_broker (encryptor);
         if (!_fetch_and_decrypt_keys (kb)) {
            goto done;
         }

         state = mongocrypt_encryptor_key_broker_done (encryptor);
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
         error = mongocrypt_encryptor_status (encryptor);
         printf ("Error, could not complete encryption: %s\n",
                 mongocrypt_status_message (error));
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
   mongocrypt_key_broker_t *kb;
   mongocrypt_decryptor_t *decryptor;
   mongocrypt_decryptor_state_t state;
   mongocrypt_binary_t *encrypted_doc = NULL;
   mongocrypt_binary_t *key_doc = NULL;
   bool res = false;
   mongocrypt_status_t *status;
   mongocrypt_status_t *error;

   decryptor = mongocrypt_decryptor_new (crypt);
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
         state = mongocrypt_decryptor_add_doc (decryptor, encrypted_doc);
         break;

      case MONGOCRYPT_DECRYPTOR_STATE_NEED_KEYS:
         /* Driver: when the decryptor needs keys,
       transition to talking to the key broker. */
         kb = mongocrypt_decryptor_get_key_broker (decryptor);
         if (!_fetch_and_decrypt_keys (kb)) {
            goto done;
         }
         state = mongocrypt_decryptor_key_broker_done (decryptor);
         break;

      case MONGOCRYPT_DECRYPTOR_STATE_NEED_DECRYPTION:
         /* Decrypt! */
         state = mongocrypt_decryptor_decrypt (decryptor);
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
         error = mongocrypt_decryptor_status (decryptor);
         printf ("Error, could not complete encryption: %s\n",
                 mongocrypt_status_message (error));
         res = false;
         goto done;

      default:
         printf ("Error, unknown decryptor state\n");
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
