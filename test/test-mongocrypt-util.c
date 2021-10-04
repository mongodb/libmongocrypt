#include "test-mongocrypt-util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const char* mongocrypt_ctx_state_to_string (mongocrypt_ctx_state_t state) {
   switch (state) {
   case MONGOCRYPT_CTX_ERROR:
      return "MONGOCRYPT_CTX_ERROR";
   case MONGOCRYPT_CTX_NEED_MONGO_COLLINFO:
      return "MONGOCRYPT_CTX_NEED_MONGO_COLLINFO";
   case MONGOCRYPT_CTX_NEED_MONGO_MARKINGS:
      return "MONGOCRYPT_CTX_NEED_MONGO_MARKINGS";
   case MONGOCRYPT_CTX_NEED_MONGO_KEYS:
      return "MONGOCRYPT_CTX_NEED_MONGO_KEYS";
   case MONGOCRYPT_CTX_NEED_KMS:
      return "MONGOCRYPT_CTX_NEED_KMS";
   case MONGOCRYPT_CTX_READY:
      return "MONGOCRYPT_CTX_READY";
   case MONGOCRYPT_CTX_DONE:
      return "MONGOCRYPT_CTX_DONE";
   default:
      return "UNKNOWN";
   }
}

char *
data_to_hex (const uint8_t *buf, size_t len)
{
   char *hex_chars = malloc (len * 2 + 1);

   char *p = hex_chars;
   size_t i;

   for (i = 0; i < len; i++) {
      p += sprintf (p, "%02x", buf[i]);
   }

   *p = '\0';

   return hex_chars;
}

void
bson_iter_bson (bson_iter_t *iter, bson_t *bson)
{
   uint32_t len;
   const uint8_t *data = NULL;
   if (BSON_ITER_HOLDS_DOCUMENT (iter)) {
      bson_iter_document (iter, &len, &data);
   }
   if (BSON_ITER_HOLDS_ARRAY (iter)) {
      bson_iter_array (iter, &len, &data);
   }
   BSON_ASSERT (data);
   bson_init_static (bson, data, len);
}
