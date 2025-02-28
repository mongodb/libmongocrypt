/**
 * This file is not a test case. This file is to generate a dynamic library for
 * testing the dll loading code.
 */

#include <iostream>
#include <string>

static std::string global_str;

#if defined(_MSC_VER)
#define SAY_HELLO_EXPORT __declspec(dllexport)
#else
#define SAY_HELLO_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

SAY_HELLO_EXPORT int say_hello(); // -Wmissing-prototypes: for testing only.

int say_hello() {
    global_str = "Hello, DLL!";
    std::cout << global_str << "\n";
    return 42;
}

} // extern "C"
