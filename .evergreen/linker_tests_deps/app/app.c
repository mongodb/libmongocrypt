#include <bson/bson.h>
#include <mongocrypt/mongocrypt.h>

int main () {
    char *a;
    mongocrypt_binary_t *b;

    printf(".calling bson_malloc0.");
    a = bson_malloc0 (1);
    printf(".calling mongocrypt_binary_new.");
    b = mongocrypt_binary_new ();
    bson_free (a);
    mongocrypt_binary_destroy (b);
    return 0;
}