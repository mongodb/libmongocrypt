/**
 * This file is not a test case. This file is to generate a dynamic library for
 * testing the dll loading code.
 */

#include <stdio.h>

#if _MSC_VER
__declspec(dllexport)
#else
__attribute__ ((visibility ("default")))
#endif
   int say_hello ()
{
   puts ("Hello, from DLL!\n");
   return 42;
}
