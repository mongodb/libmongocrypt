cmake_minimum_required (VERSION 3.12)

# Preempt the MSVC_RUNTIME_LIBRARY properties
if (POLICY CMP0091)
   cmake_policy (SET CMP0091 NEW)
elseif (DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
   message (WARNING "The CMAKE_MSVC_RUNTIME_LIBRARY variable is set, but CMake is too old to understand it")
endif ()

project (mongocrypt C)

# Used for the csfle-markup util:
enable_language (CXX OPTIONAL)

set (CMAKE_C_STANDARD 99)

option (ENABLE_STATIC "Install static libraries" ON)
option (ENABLE_PIC
   "Enables building of position independent code for static library components."
   ON
)
option (ENABLE_BUILD_FOR_PPA "Maintainer-only option for preparing PPA build" OFF)
option (ENABLE_ONLINE_TESTS "Enable online tests and the csfle utility" ON)

if (ENABLE_WINDOWS_STATIC_RUNTIME)
   if (POLICY CMP0091)
      # CMake 3.15 makes this trivial:
      set (CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
   else ()
      # Fix it up the old-fashioned way
      string (REPLACE "/MDd" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
      string (REPLACE "/MD" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
      string (REPLACE "/MDd" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
      string (REPLACE "/MD" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
      string (APPEND CMAKE_C_FLAGS_DEBUG " /MTd")
      string (APPEND CMAKE_CXX_FLAGS_DEBUG " /MTd")
      string (APPEND CMAKE_C_FLAGS_RELEASE " /MT")
      string (APPEND CMAKE_CXX_FLAGS_RELEASE " /MT")
   endif ()
endif ()

list (APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include (GNUInstallDirs)

include (LTO)
include (ImportBSON)

option (MONGOCRYPT_ENABLE_DECIMAL128 "Enable extended support for Decimal128" ON)
mark_as_advanced (MONGOCRYPT_ENABLE_DECIMAL128)
set (maybe_dfp_library)
if (MONGOCRYPT_ENABLE_DECIMAL128)
   include (ImportDFP)
   set (maybe_dfp_library mongocrypt::intel_dfp)
endif ()

if (USE_SHARED_LIBBSON AND ENABLE_BUILD_FOR_PPA)
   message (FATAL_ERROR "PPA build requires static linking to libbson")
endif ()
if (DEFINED MONGOCRYPT_DFP_DIR AND ENABLE_BUILD_FOR_PPA)
   message (FATAL_ERROR "PPA build requires building with vendored Intel DFP")
endif ()

# Enable a higher warning level and warnings-as-errors
include (MongoC-Warnings)
option (ENABLE_MORE_WARNINGS_AS_ERRORS "Enable extra warnings-as-errors in the build." OFF)
if (ENABLE_MORE_WARNINGS_AS_ERRORS)
   mongoc_add_platform_compile_options (
      msvc:/W3 msvc:/WX msvc:/wd4996 msvc:/wd4359
      gnu-like:-Wall gnu-like:-Werror
      gnu-like:-Wswitch-enum gnu-like:-Wswitch-default
      gnu-like:-Wsign-compare
      )
   add_link_options (
      # Enable link-time warnings. VS 2015 sees LNK4099 spuriously, but it is a
      # non-fatal issue. LNK4217 and LNK4049 appear when using dllimport on
      # locally-defined symbols in kms-message.
      "$<IF:$<C_COMPILER_ID:MSVC>,/WX;/ignore:4217;/ignore:4049;/ignore:4099,-Werror>"
      )
endif ()

add_subdirectory (bindings/cs)

include (GenerateExportHeader)

include (CTest)
include (Platform)


set (MONGOCRYPT_PUBLIC_HEADERS
   src/mongocrypt-compat.h
   src/mongocrypt.h
)

set (MONGOCRYPT_SOURCES
   src/crypto/cng.c
   src/crypto/commoncrypto.c
   src/crypto/libcrypto.c
   src/crypto/none.c
   src/mc-array.c
   src/mc-efc.c
   src/mc-fle2-find-range-payload.c
   src/mc-fle2-find-range-payload-v2.c
   src/mc-fle2-insert-update-payload.c
   src/mc-fle2-insert-update-payload-v2.c
   src/mc-fle2-encryption-placeholder.c
   src/mc-fle2-find-equality-payload.c
   src/mc-fle2-find-equality-payload-v2.c
   src/mc-fle2-payload-iev.c
   src/mc-fle2-payload-iev-v2.c
   src/mc-fle2-payload-uev.c
   src/mc-fle2-payload-uev-common.c
   src/mc-fle2-payload-uev-v2.c
   src/mc-fle2-rfds.c
   src/mc-range-edge-generation.c
   src/mc-range-mincover.c
   src/mc-range-encoding.c
   src/mc-rangeopts.c
   src/mc-reader.c
   src/mc-tokens.c
   src/mc-writer.c
   src/mongocrypt-binary.c
   src/mongocrypt-buffer.c
   src/mongocrypt-cache.c
   src/mongocrypt-cache-collinfo.c
   src/mongocrypt-cache-key.c
   src/mongocrypt-cache-oauth.c
   src/mongocrypt-ciphertext.c
   src/mongocrypt-crypto.c
   src/mongocrypt-ctx-datakey.c
   src/mongocrypt-ctx-decrypt.c
   src/mongocrypt-ctx-encrypt.c
   src/mongocrypt-ctx-rewrap-many-datakey.c
   src/mongocrypt-ctx.c
   src/mongocrypt-endpoint.c
   src/mongocrypt-kek.c
   src/mongocrypt-key.c
   src/mongocrypt-key-broker.c
   src/mongocrypt-kms-ctx.c
   src/mongocrypt-log.c
   src/mongocrypt-marking.c
   src/mongocrypt-opts.c
   src/mongocrypt-status.c
   src/mongocrypt-traverse-util.c
   src/mongocrypt-util.c
   src/mongocrypt.c
   src/os_win/os_mutex.c
   src/os_posix/os_mutex.c
   src/os_win/os_dll.c
   src/os_posix/os_dll.c
   )

# If MONGOCRYPT_CRYPTO is not set, choose a system default.
if (NOT MONGOCRYPT_CRYPTO)
   set (MONGOCRYPT_CRYPTO OpenSSL)
   if (APPLE)
      set (MONGOCRYPT_CRYPTO CommonCrypto)
   elseif (WIN32)
      set (MONGOCRYPT_CRYPTO CNG)
   endif ()
endif ()

# Otherwise, override with crypto hooks.
if (DISABLE_NATIVE_CRYPTO)
   set (MONGOCRYPT_CRYPTO none)
endif ()

set (MONGOCRYPT_ENABLE_CRYPTO 0)
set (MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO 0)
set (MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO 0)
set (MONGOCRYPT_ENABLE_CRYPTO_CNG 0)

if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   message ("Building with common crypto")
   set (MONGOCRYPT_ENABLE_CRYPTO 1)
   set (MONGOCRYPT_ENABLE_CRYPTO_COMMON_CRYPTO 1)
elseif (MONGOCRYPT_CRYPTO STREQUAL CNG)
   message ("Building with CNG")
   set (MONGOCRYPT_ENABLE_CRYPTO 1)
   set (MONGOCRYPT_ENABLE_CRYPTO_CNG 1)
elseif (MONGOCRYPT_CRYPTO STREQUAL OpenSSL)
   message ("Building with OpenSSL")
   include (FindOpenSSL)
   message ("Found OpenSSL version ${OPENSSL_VERSION}")
   set (MONGOCRYPT_ENABLE_CRYPTO 1)
   set (MONGOCRYPT_ENABLE_CRYPTO_LIBCRYPTO 1)
elseif (MONGOCRYPT_CRYPTO STREQUAL none)
   message ("Building with no native crypto, hooks MUST be supplied with mongocrypt_setopt_crypto_hooks")
else ()
   message (FATAL_ERROR "Unknown crypto provider ${MONGOCRYPT_CRYPTO}")
endif ()

set (MONGOCRYPT_ENABLE_TRACE 0)
if (ENABLE_TRACE)
   message (WARNING "Building with trace logging. This is highly insecure. Do not use in a production environment")
   set (MONGOCRYPT_ENABLE_TRACE 1)
endif ()

set (BUILD_VERSION "0.0.0" CACHE STRING "Library version")
if (BUILD_VERSION STREQUAL "0.0.0")
   if (EXISTS ${CMAKE_BINARY_DIR}/VERSION_CURRENT)
      file (STRINGS ${CMAKE_BINARY_DIR}/VERSION_CURRENT BUILD_VERSION)
   elseif (EXISTS ${PROJECT_SOURCE_DIR}/VERSION_CURRENT)
      file (STRINGS ${PROJECT_SOURCE_DIR}/VERSION_CURRENT BUILD_VERSION)
      message (STATUS "File VERSION_CURRENT contained BUILD_VERSION ${BUILD_VERSION}")
   else ()
      find_package (PythonInterp)
      if (PYTHONINTERP_FOUND)
         execute_process (
            COMMAND ${PYTHON_EXECUTABLE} etc/calc_release_version.py
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE CALC_RELEASE_VERSION
            RESULT_VARIABLE CALC_RELEASE_VERSION_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE
         )
         if (NOT CALC_RELEASE_VERSION_RESULT STREQUAL 0)
            # If python failed above, stderr would tell the user about it
            message (FATAL_ERROR
               "BUILD_VERSION not specified and could not be calculated\
 (script invocation failed); specify in CMake command, -DBUILD_VERSION=<version>"
            )
         else ()
            set (BUILD_VERSION ${CALC_RELEASE_VERSION})
            message ("calculated BUILD_VERSION ${BUILD_VERSION}")
            file (WRITE ${CMAKE_BINARY_DIR}/VERSION_CURRENT ${CALC_RELEASE_VERSION})
         endif ()
      else ()
         message (FATAL_ERROR
            "BUILD_VERSION not specified and could not be calculated\
 (Python was not found on the system); specify in CMake command, -DBUILD_VERSION=<version>"
         )
      endif ()
      message (STATUS "Storing BUILD_VERSION ${BUILD_VERSION} in file VERSION_CURRENT for later use")
      file (WRITE ${PROJECT_SOURCE_DIR}/VERSION_CURRENT ${BUILD_VERSION})
   endif ()
else ()
   message (STATUS "Storing BUILD_VERSION ${BUILD_VERSION} in file VERSION_CURRENT for later use")
   file (WRITE ${PROJECT_SOURCE_DIR}/VERSION_CURRENT ${BUILD_VERSION})
endif ()

set (MONGOCRYPT_BUILD_VERSION ${BUILD_VERSION})

configure_file (
   "${PROJECT_SOURCE_DIR}/src/mongocrypt-config.h.in"
   "${PROJECT_BINARY_DIR}/src/mongocrypt-config.h"
)

# Define the mlib target, which is private and header-only. It is not exported
# nor are its headers installed.
add_library (_mongo-mlib INTERFACE)
add_library (mongo::mlib ALIAS _mongo-mlib)
list (APPEND MLIB_DEFINITIONS MLIB_USER)
CHECK_INCLUDE_FILE (strings.h HAVE_STRINGS_H)
if (HAVE_STRINGS_H)
   list (APPEND MLIB_DEFINITIONS MLIB_HAVE_STRINGS_H)
endif ()
set_property(
   TARGET _mongo-mlib
   APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS
   ${MLIB_DEFINITIONS}
   )
set_property(
   TARGET _mongo-mlib
   APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
   "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
   )

# kms-message
add_subdirectory (kms-message)

# Define mongocrypt library
add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories (
   mongocrypt
   PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src"
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
   PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>"
   )
target_link_libraries (
   mongocrypt
   PRIVATE
      _mongocrypt::libbson_for_shared
      kms_message_static
      $<BUILD_INTERFACE:mongo::mlib>
   PUBLIC
      mongocrypt::platform
      ${maybe_dfp_library}
   )

if (NOT USE_SHARED_LIBBSON)
   if (APPLE)
      message ("compiling with unexported symbols list to hide bson symbols")
      set_target_properties (mongocrypt PROPERTIES LINK_FLAGS "-Wl,-unexported_symbols_list,\"${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-hidden-symbols.txt\"")
   elseif (UNIX)
      message ("compiling with version map to version and hide bson symbols")
      set_target_properties (mongocrypt PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-hidden-symbols.map\"")
   endif ()
endif ()

if (NOT WIN32 AND CMAKE_VERSION VERSION_GREATER 3.25)
   # Do not enable conversion warnings with older cmake. Older cmake does not support
   # including headers as system headers when the headers are added to the project via
   # the add_subdirectory() CMake command. libbson produces conversion warnings and is
   # included in ImportBSON.cmake.
   target_compile_options (mongocrypt PRIVATE -Wconversion -Wsign-conversion)
   target_compile_options (kms_message_static PRIVATE -Wconversion -Wsign-conversion)
endif ()

generate_export_header (mongocrypt EXPORT_FILE_NAME src/mongocrypt-export.h BASE_NAME mongocrypt )

add_library (mongocrypt_static STATIC ${MONGOCRYPT_SOURCES})
# Checking CMAKE_C_FLAGS for -fPIC is not a foolproof way of checking whether
# -fPIC was set as a compiler flag. However, users were instructed before to
# pass -fPIC through CMAKE_C_FLAGS. This will prevent redundant output in
# the common case that users are setting -DCMAKE_C_FLAGS='-fPIC'
string (FIND "${CMAKE_C_FLAGS}" "-fPIC" FPIC_LOCATION)
if (NOT WIN32 AND ENABLE_PIC AND "${FPIC_LOCATION}" EQUAL "-1")
   target_compile_options (mongocrypt_static PUBLIC -fPIC)
   message ("Adding -fPIC to compilation of mongocrypt_static components")
endif ()
target_include_directories (
   mongocrypt_static
   PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src"
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
   PUBLIC
      "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>"
   )
target_compile_definitions (
   mongocrypt_static
   PUBLIC
      MONGOCRYPT_STATIC_DEFINE
      KMS_MSG_STATIC
   )
target_link_libraries (
   mongocrypt_static
   PRIVATE
      _mongocrypt::libbson_for_static
      kms_message_static
      $<BUILD_INTERFACE:mongo::mlib>
   PUBLIC
      mongocrypt::platform
      ${maybe_dfp_library}
   )
set (PKG_CONFIG_STATIC_LIBS "\${prefix}/${CMAKE_INSTALL_LIBDIR}/libmongocrypt-static.a")
set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} ${CMAKE_THREAD_LIBS_INIT}")
if (CMAKE_DL_LIBS)
   string (APPEND PKG_CONFIG_STATIC_LIBS " -l${CMAKE_DL_LIBS}")
endif ()
set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libkms_message-static.a")
if (ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libbson-static-for-libmongocrypt.a")
   #librt needed for libbson on linux for clock_gettime
   find_library (RT_LIBRARY rt)
   if (RT_LIBRARY)
      set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} ${RT_LIBRARY}")
   endif ()
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -pthread")
endif ()
if (MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM" AND MONGOCRYPT_ENABLE_DECIMAL128)
   get_property (SYSTEM_DFP_LOC TARGET intel_dfp PROPERTY IMPORTED_LOCATION)
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} ${SYSTEM_DFP_LOC}")
endif ()


if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   target_link_libraries (mongocrypt PRIVATE "-framework CoreFoundation -framework Security")
   target_link_libraries (mongocrypt_static PRIVATE "-framework CoreFoundation -framework Security")
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -framework CoreFoundation -framework Security")
elseif (MONGOCRYPT_CRYPTO STREQUAL CNG)
   target_link_libraries (mongocrypt PRIVATE "bcrypt")
   target_link_libraries (mongocrypt_static PRIVATE "bcrypt")
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -lbcrypt")
elseif (MONGOCRYPT_CRYPTO STREQUAL OpenSSL)
   target_link_libraries (mongocrypt PRIVATE OpenSSL::SSL OpenSSL::Crypto)
   target_link_libraries (mongocrypt_static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -lssl -lcrypto")
endif ()

# Link to libm for math functions (pow, log, etc.)
# Do not link on Apple. On macOS Big Sur, libm resolves to the SDK's tbd file, like:
# /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libm.tbd
# Not all consumers can easily link to a tbd file (notably golang will reject a tbd suffix by default)
# macOS includes libm as part of libSystem (along with libc).
# It does not need to be explicitly linked.
if (NOT APPLE)
   find_library (M_LIBRARY m)
   if (M_LIBRARY)
      set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -lm")
   endif ()
endif ()

set_target_properties (mongocrypt PROPERTIES
   SOVERSION 0
   VERSION "0.0.0"
   OUTPUT_NAME "mongocrypt"
)

set_target_properties (mongocrypt_static PROPERTIES
   SOVERSION 0
   VERSION "0.0.0"
   OUTPUT_NAME "mongocrypt-static"
)

if (BUILD_TESTING)
   # Use C++ in the testing DLL to ensure we can load a library with the C++ runtime
   enable_language (CXX)
   add_library (test-dll MODULE test/test-dll.cpp)
   set_target_properties (test-dll PROPERTIES
      SUFFIX ".dll"
      PREFIX ""
      )

   # Create two stubbed crypt_shared libraries
   add_library (stubbed-crypt_shared SHARED test/crypt_shared-stub.cpp)
   add_library (stubbed-crypt_shared-2 SHARED test/crypt_shared-stub.cpp)

   set_target_properties(stubbed-crypt_shared stubbed-crypt_shared-2 PROPERTIES
      INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/src"
      LINK_LIBRARIES _mongocrypt::libbson_for_static
      COMPILE_FEATURES cxx_std_11
      PREFIX ""
      )

   set_target_properties(stubbed-crypt_shared-2 PROPERTIES SUFFIX ".dll")

   if (MONGOCRYPT_TESTING_CRYPT_SHARED_FILE)
      # Generate a target that copies the CSFLE library into the binary directory of test-mongocrypt
      set (stamp "${CMAKE_CURRENT_BINARY_DIR}/mongo_crypt_v1.copied.$<CONFIG>.stamp")
      add_custom_command (
         OUTPUT "${stamp}"
         COMMAND "${CMAKE_COMMAND}" -E copy
            "${MONGOCRYPT_TESTING_CRYPT_SHARED_FILE}"
            "$<TARGET_FILE_DIR:test-mongocrypt>/mongo_crypt_v1${CMAKE_SHARED_LIBRARY_SUFFIX}"
         COMMAND "${CMAKE_COMMAND}" -E touch "${stamp}"
         DEPENDS "${MONGOCRYPT_TESTING_CRYPT_SHARED_FILE}"
         COMMENT "Getting mongo_crypt library"
         )
      add_custom_target (copy-crypt_shared ALL DEPENDS "${stamp}")
   else ()
      # The first stubbed crypt_shared library will take the place of the actual crypt_shared for testing
      message (STATUS "Generating a stubbed crypt_shared dynamic library for use in testing.")
      message (STATUS "Provide a MONGOCRYPT_TESTING_CRYPT_SHARED_FILE=<filepath> to provide a crypt_shared for use in testing")
      set_target_properties (stubbed-crypt_shared PROPERTIES
         # Normalize the output name expected by libmongocrypt
         OUTPUT_NAME "mongo_crypt_v1"
         )
   endif ()
endif ()

set (TEST_MONGOCRYPT_SOURCES
   test/test-gcp-auth.c
   test/test-mc-efc.c
   test/test-mc-fle2-find-equality-payload-v2.c
   test/test-mc-fle2-find-range-payload-v2.c
   test/test-mc-fle2-payload-iev.c
   test/test-mc-fle2-payload-iev-v2.c
   test/test-mc-fle2-payload-iup.c
   test/test-mc-fle2-payload-iup-v2.c
   test/test-mc-fle2-payload-uev.c
   test/test-mc-fle2-payload-uev-v2.c
   test/test-mc-fle2-rfds.c
   test/test-mc-range-edge-generation.c
   test/test-mc-range-mincover.c
   test/test-mc-rangeopts.c
   test/test-mc-reader.c
   test/test-mc-tokens.c
   test/test-mc-range-encoding.c
   test/test-mc-writer.c
   test/test-mongocrypt-assert-match-bson.c
   test/test-mongocrypt-buffer.c
   test/test-mongocrypt-cache.c
   test/test-mongocrypt-cache-oauth.c
   test/test-mongocrypt-ciphertext.c
   test/test-mongocrypt-cleanup.c
   test/test-mongocrypt-compact.c
   test/test-mongocrypt-crypto.c
   test/test-mongocrypt-crypto-hooks.c
   test/test-mongocrypt-crypto-std-hooks.c
   test/test-mongocrypt-csfle-lib.c
   test/test-mongocrypt-ctx-decrypt.c
   test/test-mongocrypt-ctx-encrypt.c
   test/test-mongocrypt-ctx-rewrap-many-datakey.c
   test/test-mongocrypt-ctx-setopt.c
   test/test-mongocrypt-datakey.c
   test/test-mongocrypt-dll.c
   test/test-mongocrypt-endpoint.c
   test/test-mongocrypt-kek.c
   test/test-mongocrypt-key.c
   test/test-mongocrypt-key-broker.c
   test/test-mongocrypt-key-cache.c
   test/test-mongocrypt-kms-ctx.c
   test/test-mongocrypt-kms-responses.c
   test/test-mongocrypt-local-kms.c
   test/test-mongocrypt-log.c
   test/test-mongocrypt-marking.c
   test/test-mongocrypt-opts.c
   test/test-mongocrypt-status.c
   test/test-mongocrypt-traverse-util.c
   test/test-mongocrypt-util.c
   test/test-mongocrypt.c
   test/test-named-kms-providers.c
   )

# Define test-mongocrypt
add_executable (test-mongocrypt ${TEST_MONGOCRYPT_SOURCES})
# Use the static version since it allows the test binary to use private symbols
target_include_directories (test-mongocrypt PRIVATE ./src "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")
target_link_libraries (test-mongocrypt PRIVATE _mongocrypt::libbson_for_static mongocrypt_static mongo::mlib)
target_include_directories (test-mongocrypt PRIVATE "${CMAKE_CURRENT_LIST_DIR}/test")
target_compile_definitions (test-mongocrypt PRIVATE
   # Set a definition so that testcases can know where test-mongocrypt.exe was written to
   "TEST_MONGOCRYPT_OUTPUT_PATH=\"$<TARGET_FILE:test-mongocrypt>\""
   # Tell test-mongocrypt whether we have a real csfle library for testing
   TEST_MONGOCRYPT_HAVE_REAL_CRYPT_SHARED_LIB=$<BOOL:${MONGOCRYPT_TESTING_CRYPT_SHARED_FILE}>
   )

add_test (
   NAME mongocrypt
   COMMAND test-mongocrypt
   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
   )

foreach (test IN ITEMS path str)
   add_executable (mlib.${test}.test src/mlib/${test}.test.c)
   add_test (mlib.${test} mlib.${test}.test)
   target_link_libraries (mlib.${test}.test PRIVATE mongo::mlib)
endforeach ()

if ("cxx_relaxed_constexpr" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
   file (GLOB_RECURSE test_files CONFIGURE_DEPENDS src/*.test.cpp)
   foreach (file IN LISTS test_files)
      # Compute a nice test name
      file (RELATIVE_PATH relpath "${CMAKE_CURRENT_LIST_DIR}/src" "${file}")
      file (TO_CMAKE_PATH "${relpath}" relpath)
      string (REPLACE "src/" "" relpath "${relpath}")
      string (REPLACE "/" "." test_name "${relpath}")
      string (REGEX REPLACE "\\.test\\.cpp$" "" test_name "${test_name}")
      # Generate a test executable:
      set (exe_name "${test_name}.test")
      add_executable ("${exe_name}" "${file}")
      target_compile_features ("${exe_name}" PRIVATE cxx_relaxed_constexpr)
      target_link_libraries ("${exe_name}" PRIVATE
         mongocrypt
         mongo::mlib
         ${maybe_dfp_library}
         _mongocrypt::libbson_for_static
         )
      add_test ("${test_name}" "${exe_name}")
   endforeach ()
endif ()

if ("cxx_std_20" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
   add_executable (csfle-markup src/csfle-markup.cpp)
   target_link_libraries (csfle-markup PRIVATE mongocrypt_static _mongocrypt::libbson_for_static mongo::mlib)
   target_compile_features (csfle-markup PRIVATE cxx_std_20)
endif ()

# Exclude example-state-machine since it requires native crypto.
if (NOT MONGOCRYPT_CRYPTO STREQUAL none)
   # Define example-state-machine
   add_executable (example-state-machine test/example-state-machine.c)
   target_link_libraries (example-state-machine PRIVATE mongocrypt _mongocrypt::libbson_for_shared)
   target_include_directories (example-state-machine PRIVATE ./src "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")
   add_test (
      NAME example-state-machine
      COMMAND example-state-machine
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
   )

   # Define example-state-machine-static
   add_executable (example-state-machine-static test/example-state-machine.c)
   target_link_libraries (example-state-machine-static PRIVATE mongocrypt_static _mongocrypt::libbson_for_static)
   target_include_directories (example-state-machine-static PRIVATE ./src)
   add_test (
      NAME example-state-machine-static
      COMMAND example-state-machine-static
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
   )

   if (ENABLE_ONLINE_TESTS)
      message ("compiling utilities")
      add_executable (csfle test/util/csfle.c test/util/util.c)
      target_link_libraries (csfle PRIVATE mongocrypt_static)
      target_include_directories (csfle PRIVATE ${CMAKE_BINARY_DIR}/src)
      target_include_directories (csfle PRIVATE ./src)
      target_include_directories (csfle PRIVATE ./kms-message/src)
      target_link_libraries (csfle PRIVATE _mongocrypt::mongoc)
   endif ()
endif ()

if (ENABLE_STATIC)
   set (TARGETS_TO_INSTALL mongocrypt mongocrypt_static)
else ()
   set (TARGETS_TO_INSTALL mongocrypt)
endif ()
install (
   TARGETS ${TARGETS_TO_INSTALL}
   EXPORT mongocrypt_targets
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
   INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# This export set is not installed, and is only to allow export() of the mlib-using targets
install (TARGETS _mongo-mlib EXPORT _exports_for_export)
export (EXPORT _exports_for_export)

install (
   FILES
      ${MONGOCRYPT_PUBLIC_HEADERS}
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-config.h
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-export.h
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt
   COMPONENT Devel
)

set (PROJECT_VERSION "${BUILD_VERSION}")
set (PROJECT_DESCRIPTION "The libmongocrypt client-side field level encryption library.")
if (NOT ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_STATIC_REQUIRES "libbson-static-1.0")
endif ()
if (USE_SHARED_LIBBSON)
   set (PKG_CONFIG_REQUIRES "libbson-1.0")
   set (PKG_CONFIG_STATIC_REQUIRES "libbson-1.0")
endif ()
set (PKG_CONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt")
set (PKG_CONFIG_LIBS "-L\${libdir} -lmongocrypt")
if (ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libbson-static-for-libmongocrypt.a")
   #librt needed for libbson on linux for clock_gettime
   find_library (RT_LIBRARY rt)
   if (RT_LIBRARY)
      set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} ${RT_LIBRARY}")
   endif ()
   set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} -pthread")
endif ()
if (MONGOCRYPT_DFP_DIR STREQUAL "USE-SYSTEM" AND MONGOCRYPT_ENABLE_DECIMAL128)
   get_property (SYSTEM_DFP_LOC TARGET intel_dfp PROPERTY IMPORTED_LOCATION)
   set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} ${SYSTEM_DFP_LOC}")
endif ()
set (PKG_CONFIG_CFLAGS "-I\${includedir}")
set (PKG_CONFIG_STATIC_CFLAGS "${PKG_CONFIG_CFLAGS} -DMONGOCRYPT_STATIC_DEFINE -DKMS_MSG_STATIC")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libmongocrypt.pc"
)
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-static.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libmongocrypt-static.pc"
)

install (
   FILES "${CMAKE_BINARY_DIR}/libmongocrypt.pc"
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
if (ENABLE_STATIC)
   install (
      FILES "${CMAKE_BINARY_DIR}/libmongocrypt-static.pc"
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
   )
endif ()

include (CMakePackageConfigHelpers)
set (INCLUDE_INSTALL_DIRS "${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt")
set (LIBRARY_INSTALL_DIRS ${CMAKE_INSTALL_LIBDIR})

write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config-version.cmake"
   COMPATIBILITY AnyNewerVersion
)

configure_file (cmake/mongocrypt-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config.cmake"
   @ONLY
)

install (EXPORT mongocrypt_targets
   NAMESPACE mongo::
   FILE mongocrypt_targets.cmake
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mongocrypt
)

install (
   FILES
      "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config.cmake"
      "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config-version.cmake"
   DESTINATION
      ${CMAKE_INSTALL_LIBDIR}/cmake/mongocrypt
   COMPONENT
      Devel
)

