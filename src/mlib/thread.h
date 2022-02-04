#ifndef MLIB_THREAD_H
#define MLIB_THREAD_H

#include "./user-check.h"
#include "./macros.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <stdbool.h>

/**
 * @brief A status object for @ref mlib_call_once.
 */
typedef struct mlib_once_flag {
#ifdef _WIN32
   INIT_ONCE _native;
#else
   pthread_once_t _native;
#endif
} mlib_once_flag;

/**
 * @brief A literal initializer suitable for static initializing an
 * @ref mlib_once_flag object. Can also be used to dynamically initialize or
 * "reset" a flag.
 */
#ifdef _WIN32
#define MLIB_ONCE_INITIALIZER          \
   {                                   \
      ._native = INIT_ONCE_STATIC_INIT \
   }
#else
#define MLIB_ONCE_INITIALIZER      \
   {                               \
      ._native = PTHREAD_ONCE_INIT \
   }
#endif

/**
 * @brief The type of an mlib_call_once callback function.
 */
typedef void (*mlib_init_once_fn_t) (void);

#if _WIN32
/**
 * An indirection layer for mlib_once on Windows platforms. Do not use directly.
 */
mcr_cxx_inline BOOL
_mlib_win32_once_callthru (INIT_ONCE *once, void *param, void *ctx)
{
   (void) once;
   (void) ctx;
   mlib_init_once_fn_t *fn = param;
   (*fn) ();
   return TRUE;
}
#endif

/**
 * @brief Perform thread-safe call-once semantics.
 *
 * For each thread that calls with the same given flag, no thread shall return
 * from this function until the flag is in the "finished" state. If a thread
 * class this function with a "non-finished" flag object, then that thread MIGHT
 * execute the passed pointed-to function. Once any thread fully executes the
 * function for the flag, the flag is marked as "finished".
 *
 * @param flag A once-state flag. Should have been initialized by @ref
 * MLIB_ONCE_INITIALIZER.
 * @param fn A callback to execute if the flag is not in the "finished" state
 * @return zero on success, once otherwise.
 */
mcr_cxx_inline int
mlib_call_once (mlib_once_flag *flag, mlib_init_once_fn_t fn)
{
#ifdef _WIN32
   bool not_okay = InitOnceExecuteOnce (
      &flag->_native, &_mlib_win32_once_callthru, &fn, NULL);
   if (not_okay) {
      return 1;
   }
   return 0;
#else
   return pthread_once (&flag->_native, fn);
#endif
}

#endif // MLIB_THREAD_H
