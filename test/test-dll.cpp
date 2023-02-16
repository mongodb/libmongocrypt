/**
 * This file is not a test case. This file is to generate a dynamic library for
 * testing the dll loading code.
 */

#include <iostream>
#include <string>

static std::string global_str;

extern "C"
#if _MSC_VER
    __declspec(dllexport)
#else
__attribute__ ((visibility ("default")))
#endif
        int say_hello() {
    global_str = "Hello, DLL!";
    std::cout << global_str << "\n";
    return 42;
}
