#include "mongocrypt-private.h"
#include "bson/bson.h"

/* This key cache is a very rudimentary fill-in until we design something
 * better.
 * - keys are never removed.
 * - limited to 64 keys total.
 */

static int
_cmp_uuid (const _mongocrypt_buffer_t *uuid1, const _mongocrypt_buffer_t *uuid2)
{
   if (uuid1->len != uuid2->len) {
      return uuid2->len - uuid1->len;
   }
   return memcmp (uuid1->data, uuid2->data, uuid1->len);
}

mongocrypt_key_cache_t *
_mongocrypt_key_cache_new (mongocrypt_key_decrypt_fn decrypt_key,
			   void *decrypt_key_ctx)
{
   mongocrypt_key_cache_t *cache;

   cache = (mongocrypt_key_cache_t *) bson_malloc0 (sizeof *mongocrypt_key_cache_t);

   cache->decrypt_key = decrypt_key;
   cache->decrypt_key_ctx = decrypt_key_ctx;

   mongocrypt_mutex_init (&cache->mutex);

   return cache;
}

void
_mongocrypt_key_cache_destroy (mongocrypt_key_cache_t *cache)
{
   int i;

   if (!cache) {
      return;
   }

   for (int i; i < _mongocrypt_key_cache_size (cache); i++) {
      /* TODO free the entries? Do we need to? */
   }

   mongocrypt_mutex_destroy (&cache->mutex);
   bson_free (cache);
}


bool
_mongocrypt_key_cache_add (mongocrypt_key_cache_t *cache,
                          _mongocrypt_buffer_t *docs,
                          uint32_t num_docs,
                          mongocrypt_status_t *status)
{
   bool ret = false;
   int i, j;


   /* lock mutex, add entry (idemptotently) then unlock */
   /* copy the document into the entry. */
   /* than parse */
   mongocrypt_mutex_lock (&cache->mutex);

   for (i = 0; i < num_docs; i++) {
      bson_t *copied;
      _mongocrypt_keycache_entry_t *entry = NULL;
      _mongocrypt_key_t parsed_key;

      copied = bson_new_from_data (docs[i].data, docs[i].len);
      if (!_mongocrypt_key_parse (copied, &parsed_key, status)) {
         bson_destroy (copied);
         goto cleanup;
      }

      /* Check if key already exists. */
      for (j = 0; j < sizeof (cache->keycache) / sizeof (cache->keycache[0]);
           j++) {
         if (cache->keycache[j].used &&
             0 == _cmp_uuid (&cache->keycache[j].key.id, &parsed_key.id)) {
            entry = cache->keycache + j;
            printf ("found existing duplicate key\n");
            break;
         }
      }

      /* Get a free entry. */
      for (j = 0; j < sizeof (cache->keycache) / sizeof (cache->keycache[0]);
           j++) {
         if (!cache->keycache[j].used) {
            entry = cache->keycache + j;
            break;
         }
      }

      if (!entry) {
         CLIENT_ERR ("No free entries in key cache");
         bson_destroy (copied);
         goto cleanup;
      }

      /* decrypt the key material. */
      if (!cache->decrypt_key (&parsed_key, status, decrypt_key_ctx)) {
         bson_destroy (copied);
         goto cleanup;
      }

      /* Keep a copy of the key document, since we'll have non-owning references
       * to the UUID and keymaterial. TODO: consider just copying the bits we
       * need instead. */
      entry->key_bson = copied; /* stolen. */
      memcpy (&entry->key, &parsed_key, sizeof (_mongocrypt_key_t));
      entry->used = true;
   }

   ret = true;

cleanup:
   mongocrypt_mutex_unlock (&cache->mutex);
   return ret;
}

/* TODO: this should hold a reader lock. */
const _mongocrypt_key_t *
_mongocrypt_keycache_get_by_id (mongocrypt_key_cache_t *cache,
                                const _mongocrypt_buffer_t *uuid,
                                mongocrypt_status_t *status)
{
   int i;

   for (i = 0; i < _mongocrypt_key_cache_size (cache); i++) {
      _mongocrypt_keycache_entry_t *entry;

      entry = cache->keycache + i;
      if (!entry->used) {
         continue;
      }

      if (0 == _cmp_uuid (&entry->key.id, uuid)) {
         return &entry->key;
      }
   }
   CLIENT_ERR ("key not found");
   return NULL;
}


int
_mongocrypt_key_cache_size (mongocrypt_key_cache_t *cache)
{
   return (sizeof (cache->keycache) / sizeof (cache->keycache[0]));
}


void
_mongocrypt_keycache_dump (mongocrypt_key_cache_t *cache)
{
   int i;
   int total_used = 0;

   printf ("Key cache contents:\n");
   for (i = 0; i < _mongocrypt_key_cache_size (cache); i++) {
      _mongocrypt_keycache_entry_t *entry;

      entry = cache->keycache + i;
      if (!entry->used) {
         continue;
      }

      total_used += 1;
      printf ("\t%s", tmp_json (entry->key_bson));
   }
   printf ("Total keys: %d\n", total_used);
}
