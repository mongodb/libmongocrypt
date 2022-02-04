#ifndef MONGOCRYPT_MACROS_PRIVATE_H
#define MONGOCRYPT_MACROS_PRIVATE_H

// clang-format off
#ifndef MCR_WEAK_SYMBOL
    #ifdef _MSC_VER
        #define MCR_WEAK_SYMBOL __declspec(selectany)
    #elif defined(__GNUC__) || defined(__clang__)
        #define MCR_WEAK_SYMBOL __attribute__ ((weak, visibility ("hidden")))
    #else
        #error "Don't know how to do weak/selectany symbols on this platform"
    #endif
#endif
// clang-format on

/**
 * @macro mcr_cxx_inline
 * @brief Declare a function to have C++-style inline semantics.
 *
 * This differs from C's `inline` in that the inline definition will be repeated
 * into every translation unit, and then later "merged" into a single definition
 * by the linker.
 */
#define mcr_cxx_inline MCR_WEAK_SYMBOL inline

#endif // MONGOCRYPT_MACROS_PRIVATE_H
