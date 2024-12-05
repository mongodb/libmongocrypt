/**
 * This file is simply a wrapper around <windows.h> and ensures that
 * WIN32_LEAN_AND_MEAN is defined before including it.
 */
#ifndef MLIB_WINDOWS_LEAN_H
#define MLIB_WINDOWS_LEAN_H

#ifdef __has_include
#if !__has_include(<windows.h>)
#error "<mlib/windows-lean.h> is only available when <windows.h> in available."
#endif
#endif

#pragma push_macro("WIN32_LEAN_AND_MEAN")
// Disable macro redefinition warning
#pragma warning(push)
#pragma warning(disable : 4005)
#define WIN32_LEAN_AND_MEAN 1
#pragma warning(pop)
#include <windows.h>
#pragma pop_macro("WIN32_LEAN_AND_MEAN")

#endif // MLIB_WINDOWS_LEAN_H
