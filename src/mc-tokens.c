/*
 * Copyright 2022-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mc-tokens-private.h"

struct _mc_CollectionsLevel1Token_t {
    _mongocrypt_buffer_t data;
};

mc_CollectionsLevel1Token_t*
mc_CollectionsLevel1Token_new (_mongocrypt_crypto_t *crypto,
                               const _mongocrypt_buffer_t *RootKey) {
   mc_CollectionsLevel1Token_t * t = bson_malloc0 (sizeof (mc_CollectionsLevel1Token_t));
   _mongocrypt_buffer_init (&t->data);
   return t;
}
const _mongocrypt_buffer_t *
mc_CollectionsLevel1Token_get (mc_CollectionsLevel1Token_t *t) {
    return &t->data;
}

void
mc_CollectionsLevel1Token_destroy (mc_CollectionsLevel1Token_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ServerDataEncryptionLevel1Token_t {
    _mongocrypt_buffer_t data;
};
mc_ServerDataEncryptionLevel1Token_t*
mc_ServerDataEncryptionLevel1Token_new (_mongocrypt_crypto_t *crypto , const _mongocrypt_buffer_t *RootKey) {
   mc_ServerDataEncryptionLevel1Token_t * t = bson_malloc0 (sizeof (mc_ServerDataEncryptionLevel1Token_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ServerDataEncryptionLevel1Token_get (mc_ServerDataEncryptionLevel1Token_t *t) {
    return &t->data;
}
void
mc_ServerDataEncryptionLevel1Token_destroy (mc_ServerDataEncryptionLevel1Token_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_EDCToken_t {
    _mongocrypt_buffer_t data;
};
mc_EDCToken_t*
mc_EDCToken_new (_mongocrypt_crypto_t *crypto , const mc_CollectionsLevel1Token_t *CollectionsLevel1Token) {
   mc_EDCToken_t * t = bson_malloc0 (sizeof (mc_EDCToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_EDCToken_get (mc_EDCToken_t *t) {
    return &t->data;
}
void
mc_EDCToken_destroy (mc_EDCToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ESCToken_t {
    _mongocrypt_buffer_t data;
};
mc_ESCToken_t*
mc_ESCToken_new (_mongocrypt_crypto_t *crypto , const mc_CollectionsLevel1Token_t *CollectionsLevel1Token) {
   mc_ESCToken_t * t = bson_malloc0 (sizeof (mc_ESCToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ESCToken_get (mc_ESCToken_t *t) {
    return &t->data;
}
void
mc_ESCToken_destroy (mc_ESCToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ECCToken_t {
    _mongocrypt_buffer_t data;
};
mc_ECCToken_t*
mc_ECCToken_new (_mongocrypt_crypto_t *crypto , const mc_CollectionsLevel1Token_t *CollectionsLevel1Token) {
   mc_ECCToken_t * t = bson_malloc0 (sizeof (mc_ECCToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ECCToken_get (mc_ECCToken_t *t) {
    return &t->data;
}
void
mc_ECCToken_destroy (mc_ECCToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ECOCToken_t {
    _mongocrypt_buffer_t data;
};
mc_ECOCToken_t*
mc_ECOCToken_new (_mongocrypt_crypto_t *crypto , const mc_CollectionsLevel1Token_t *CollectionsLevel1Token) {
   mc_ECOCToken_t * t = bson_malloc0 (sizeof (mc_ECOCToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ECOCToken_get (mc_ECOCToken_t *t) {
    return &t->data;
}
void
mc_ECOCToken_destroy (mc_ECOCToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_EDCDerivedFromDataToken_t {
    _mongocrypt_buffer_t data;
};
mc_EDCDerivedFromDataToken_t*
mc_EDCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto , const mc_EDCToken_t *EDCToken, const _mongocrypt_buffer_t *v) {
   mc_EDCDerivedFromDataToken_t * t = bson_malloc0 (sizeof (mc_EDCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_EDCDerivedFromDataToken_get (mc_EDCDerivedFromDataToken_t *t) {
    return &t->data;
}
void
mc_EDCDerivedFromDataToken_destroy (mc_EDCDerivedFromDataToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ESCDerivedFromDataToken_t {
    _mongocrypt_buffer_t data;
};
mc_ESCDerivedFromDataToken_t*
mc_ESCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto , const mc_ESCToken_t *ESCToken, const _mongocrypt_buffer_t *v) {
   mc_ESCDerivedFromDataToken_t * t = bson_malloc0 (sizeof (mc_ESCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ESCDerivedFromDataToken_get (mc_ESCDerivedFromDataToken_t *t) {
    return &t->data;
}
void
mc_ESCDerivedFromDataToken_destroy (mc_ESCDerivedFromDataToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ECCDerivedFromDataToken_t {
    _mongocrypt_buffer_t data;
};
mc_ECCDerivedFromDataToken_t*
mc_ECCDerivedFromDataToken_new (_mongocrypt_crypto_t *crypto , const mc_ECCToken_t *EDCToken, const _mongocrypt_buffer_t *v) {
   mc_ECCDerivedFromDataToken_t * t = bson_malloc0 (sizeof (mc_ECCDerivedFromDataToken_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ECCDerivedFromDataToken_get (mc_ECCDerivedFromDataToken_t *t) {
    return &t->data;
}
void
mc_ECCDerivedFromDataToken_destroy (mc_ECCDerivedFromDataToken_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_EDCDerivedFromDataTokenAndCounter_t {
    _mongocrypt_buffer_t data;
};
mc_EDCDerivedFromDataTokenAndCounter_t*
mc_EDCDerivedFromDataTokenAndCounter_new (_mongocrypt_crypto_t *crypto , const mc_EDCDerivedFromDataToken_t *EDCDerivedFromDataToken, uint64_t u) {
   mc_EDCDerivedFromDataTokenAndCounter_t * t = bson_malloc0 (sizeof (mc_EDCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_EDCDerivedFromDataTokenAndCounter_get (mc_EDCDerivedFromDataTokenAndCounter_t *t) {
    return &t->data;
}
void
mc_EDCDerivedFromDataTokenAndCounter_destroy (mc_EDCDerivedFromDataTokenAndCounter_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ESCDerivedFromDataTokenAndCounter_t {
    _mongocrypt_buffer_t data;
};
mc_ESCDerivedFromDataTokenAndCounter_t*
mc_ESCDerivedFromDataTokenAndCounter_new (_mongocrypt_crypto_t *crypto , const mc_ESCDerivedFromDataToken_t *ESCDerivedFromDataToken, uint64_t u) {
   mc_ESCDerivedFromDataTokenAndCounter_t * t = bson_malloc0 (sizeof (mc_ESCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ESCDerivedFromDataTokenAndCounter_get (mc_ESCDerivedFromDataTokenAndCounter_t *t) {
    return &t->data;
}
void
mc_ESCDerivedFromDataTokenAndCounter_destroy (mc_ESCDerivedFromDataTokenAndCounter_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}


struct _mc_ECCDerivedFromDataTokenAndCounter_t {
    _mongocrypt_buffer_t data;
};
mc_ECCDerivedFromDataTokenAndCounter_t*
mc_ECCDerivedFromDataTokenAndCounter_new (_mongocrypt_crypto_t *crypto , const mc_ECCDerivedFromDataToken_t *ECCDerivedFromDataToken, uint64_t u) {
   mc_ECCDerivedFromDataTokenAndCounter_t * t = bson_malloc0 (sizeof (mc_ECCDerivedFromDataTokenAndCounter_t));
   _mongocrypt_buffer_init (&t->data);
   /* TODO */
   return t;
}
const _mongocrypt_buffer_t *
mc_ECCDerivedFromDataTokenAndCounter_get (mc_ECCDerivedFromDataTokenAndCounter_t *t) {
    return &t->data;
}
void
mc_ECCDerivedFromDataTokenAndCounter_destroy (mc_ECCDerivedFromDataTokenAndCounter_t *t) {
    if (!t) {
        return;
    }
    _mongocrypt_buffer_cleanup (&t->data);
    bson_free (t);
}

