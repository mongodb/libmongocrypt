#ifndef MLIB_ERROR_PRIVATE_H
#define MLIB_ERROR_PRIVATE_H

#include "./user-check.h"

#include "./macros.h"
#include "./str.h"

#if _WIN32
#include <windows.h>
#endif

static inline mstr
merror_system_error_string (int errn)
{
   //    FormatMessageW (0, NULL, )
}

#endif // MLIB_ERROR_PRIVATE_H