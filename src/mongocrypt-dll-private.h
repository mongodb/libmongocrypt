#ifndef MONGOCRYPT_DLL_PRIVATE_H
#define MONGOCRYPT_DLL_PRIVATE_H

#include <mlib/str.h>

#include <stdlib.h>

/* No header required for declarations. */
#define MCR_DLL_NULL ((_mcr_dll){._native_handle = NULL, ._error_string = NULL})

/**
 * @brief A dynamically-loaded library i.e. returned by LoadLibrary() or
 * dlopen()
 */
typedef struct _mcr_dll {
   // (All supported platforms using a void* as the library handle type)
   void *_native_handle;
   mstr _error_string;
} _mcr_dll;

/**
 * @brief Open and load a dynamic library at the given filepath.
 *
 * @param filepath A path to a library, suitable for encoding as a filepath on
 * the host system
 * @return _mcr_dll A newly opened dynamic library, which must be
 * released using @ref _mcr_dll_close()
 */
_mcr_dll
_mcr_dll_open (const char *filepath);

/**
 * @brief Close a dynamic library opened with @ref _mcr_dll_open
 *
 * @param dll A dynamic library handle
 */
static inline void
_mcr_dll_close (_mcr_dll dll)
{
   extern void _mcr_dll_close_handle (_mcr_dll);
   _mcr_dll_close_handle (dll);
   mstr_free (dll._error_string);
}

/**
 * @brief Obtain a pointer to an exported entity from the given dynamic library.
 *
 * @param dll A library opened with @ref _mcr_dll_open
 * @param symbol The name of a symbol to open
 * @return void* A pointer to that symbol, or NULL if not found
 */
void *
_mcr_dll_sym (_mcr_dll dll, const char *symbol);

static inline const char *
_mcr_dll_error (_mcr_dll dll)
{
   return dll._error_string.data;
}

#endif // MONGOCRYPT_DLL_PRIVATE_H
