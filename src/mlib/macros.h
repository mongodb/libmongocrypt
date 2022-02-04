#ifndef MONGOCRYPT_MACROS_PRIVATE_H
#define MONGOCRYPT_MACROS_PRIVATE_H

#include "./user-check.h"

// clang-format off
#ifndef MCR_WEAK_SYMBOL
    #ifdef _MSC_VER
        #define MCR_WEAK_SYMBOL __declspec(selectany) extern
    #elif defined(__GNUC__) || defined(__clang__)
        #define MCR_WEAK_SYMBOL __attribute__ ((weak, visibility ("hidden")))
    #else
        #error "Don't know how to do weak/selectany symbols on this platform"
    #endif
#endif
// clang-format on

#endif // MONGOCRYPT_MACROS_PRIVATE_H
