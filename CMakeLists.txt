cmake_minimum_required (VERSION 3.5)

if (CMAKE_VERSION VERSION_EQUAL 3.12 OR CMAKE_VERSION VERSION_GREATER 3.12)
   project (mongocrypt C)
else ()
   # GenerateExportHeader only works with C with 3.12 - https://gitlab.kitware.com/cmake/cmake/commit/de348a9638bd51af4523f36c68884b901d4aff18
   project (mongocrypt C CXX)
endif ()

set (CMAKE_C_STANDARD 99)

option (ENABLE_SHARED_BSON "Dynamically link libbson (default is static)" OFF)
option (ENABLE_STATIC "Install static libraries" ON)
option (ENABLE_PIC
   "Enables building of position independent code for static library components."
   ON
)
option (ENABLE_BUILD_FOR_PPA "Maintainer-only option for preparing PPA build" OFF)
if (ENABLE_SHARED_BSON AND ENABLE_BUILD_FOR_PPA)
   message (FATAL_ERROR "PPA build requires static linking to libbson")
endif ()

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

# Attempt to find libbson by new package name.
find_package (bson-1.0 1.11 QUIET)
if (bson-1.0_FOUND)
   message ("--   libbson found version \"${bson-1.0_VERSION}\"")
   set (BSON_TARGET mongo::bson_static)
   if (ENABLE_SHARED_BSON)
      set (BSON_TARGET mongo::bson_shared)
   endif ()
elseif (ENABLE_SHARED_BSON)
   # Try old package name for libbson.
   find_package (libbson-1.0 1.11 REQUIRED)
   message ("--   libbson found version \"${BSON_VERSION}\"")
   message ("--   libbson include path \"${BSON_INCLUDE_DIRS}\"")
   message ("--   libbson libraries \"${BSON_LIBRARIES}\"")
   set (BSON_TARGET ${BSON_LIBRARIES})
   set (BSON_INCLUDES ${BSON_INCLUDE_DIRS})
   set (BSON_DEFINITIONS ${BSON_DEFINITIONS})
else ()
   # Try old package name for libbson.
   find_package (libbson-static-1.0 1.11 REQUIRED)
   message ("--   libbson-static found version \"${BSON_STATIC_VERSION}\"")
   message ("--   libbson-static include path \"${BSON_STATIC_INCLUDE_DIRS}\"")
   message ("--   libbson-static libraries \"${BSON_STATIC_LIBRARIES}\"")
   set (BSON_TARGET ${BSON_STATIC_LIBRARIES})
   set (BSON_INCLUDES ${BSON_STATIC_INCLUDE_DIRS})
   set (BSON_DEFINITIONS ${BSON_STATIC_DEFINITIONS})
endif ()

find_package ( Threads REQUIRED )

add_subdirectory (bindings/cs)

include (GenerateExportHeader)
include (GNUInstallDirs)

enable_testing ()

set (MONGOCRYPT_PUBLIC_HEADERS
   src/mongocrypt-compat.h
)

set (MONGOCRYPT_SOURCES
   src/crypto/cng.c
   src/crypto/commoncrypto.c
   src/crypto/libcrypto.c
   src/crypto/none.c
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
   src/mongocrypt.c
   src/os_win/os_mutex.c
   src/os_win/os_once.c
   src/os_posix/os_mutex.c
   src/os_posix/os_once.c
   )

if ( MSVC )
   # W4996 - POSIX name for this item is deprecated
   set (CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} /W3 /wd4996 /D_CRT_SECURE_NO_WARNINGS /WX")

   # TODO: add support for clang-cl which is detected as MSVC
else ()
   # GNU, Clang, AppleClang
   set (CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -Werror -Wno-missing-braces")
endif ()

# Choose a Crypto provider
set (MONGOCRYPT_CRYPTO OpenSSL)
if (APPLE)
   set (MONGOCRYPT_CRYPTO CommonCrypto)
elseif (WIN32)
   set (MONGOCRYPT_CRYPTO CNG)
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

configure_file (
   "${PROJECT_SOURCE_DIR}/src/mongocrypt-config.h.in"
   "${PROJECT_BINARY_DIR}/src/mongocrypt-config.h"
)

# kms-message
add_subdirectory (kms-message)

# Define mongocrypt library
add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")
target_include_directories (mongocrypt PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>)
target_include_directories (mongocrypt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories (mongocrypt PRIVATE ${BSON_INCLUDES})
target_compile_definitions (mongocrypt PRIVATE ${BSON_DEFINITIONS})
target_link_libraries (mongocrypt PRIVATE ${BSON_TARGET})
target_link_libraries (mongocrypt PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (mongocrypt PRIVATE kms_message_static)

if (NOT ENABLE_SHARED_BSON)
   if (APPLE)
      message ("compiling with unexported symbols list to hide bson symbols")
      set_target_properties (mongocrypt PROPERTIES LINK_FLAGS "-Wl,-unexported_symbols_list,\"${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-hidden-symbols.txt\"")
   elseif (UNIX)
      message ("compiling with version map to version and hide bson symbols")
      set_target_properties (mongocrypt PROPERTIES LINK_FLAGS "-Wl,--version-script=\"${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-hidden-symbols.map\"")
   endif ()
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
target_include_directories (mongocrypt_static PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")
target_include_directories (mongocrypt_static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>)
target_include_directories (mongocrypt_static PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories (mongocrypt_static PRIVATE ${BSON_INCLUDES})
target_compile_definitions (mongocrypt_static PRIVATE ${BSON_DEFINITIONS})
set (PKG_CONFIG_STATIC_LIBS "\${prefix}/${CMAKE_INSTALL_LIBDIR}/libmongocrypt-static.a")
target_link_libraries (mongocrypt_static PRIVATE ${BSON_TARGET})
target_link_libraries (mongocrypt_static PRIVATE ${CMAKE_THREAD_LIBS_INIT})
set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} ${CMAKE_THREAD_LIBS_INIT}")
target_link_libraries (mongocrypt_static PRIVATE kms_message_static)
set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libkms_message-static.a")
if (ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libbson-static-1.0.a")
   #librt needed for libbson on linux for clock_gettime
   find_library (RT_LIBRARY rt)
   if (RT_LIBRARY)
      set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} ${RT_LIBRARY}")
   endif ()
   set (PKG_CONFIG_STATIC_LIBS "${PKG_CONFIG_STATIC_LIBS} -pthread")
endif ()
target_compile_definitions (mongocrypt_static PUBLIC MONGOCRYPT_STATIC_DEFINE KMS_MSG_STATIC)
if (ENABLE_WINDOWS_STATIC_RUNTIME)
   target_compile_options (mongocrypt_static PUBLIC /MT)
   target_compile_options (kms_message_static PUBLIC /MT)
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


set (TEST_MONGOCRYPT_SOURCES
   test/test-mongocrypt-assert-match-bson.c
   test/test-mongocrypt-buffer.c
   test/test-mongocrypt-cache.c
   test/test-mongocrypt-cache-oauth.c
   test/test-mongocrypt-ciphertext.c
   test/test-mongocrypt-crypto.c
   test/test-mongocrypt-crypto-hooks.c
   test/test-mongocrypt-ctx-decrypt.c
   test/test-mongocrypt-ctx-encrypt.c
   test/test-mongocrypt-ctx-setopt.c
   test/test-mongocrypt-datakey.c
   test/test-mongocrypt-endpoint.c
   test/test-mongocrypt-kek.c
   test/test-mongocrypt-key.c
   test/test-mongocrypt-key-broker.c
   test/test-mongocrypt-key-cache.c
   test/test-mongocrypt-kms-responses.c
   test/test-mongocrypt-local-kms.c
   test/test-mongocrypt-log.c
   test/test-mongocrypt-marking.c
   test/test-mongocrypt-status.c
   test/test-mongocrypt-traverse-util.c
   test/test-mongocrypt-util.c
   test/test-mongocrypt.c
)

# Define test-mongocrypt
add_executable (test-mongocrypt ${TEST_MONGOCRYPT_SOURCES})
# Use the static version since it allows the test binary to use private symbols
target_link_libraries (test-mongocrypt PRIVATE mongocrypt_static)
target_include_directories (test-mongocrypt PRIVATE ./src "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")
target_link_libraries (test-mongocrypt PRIVATE ${BSON_TARGET})
target_include_directories (test-mongocrypt PRIVATE ${BSON_INCLUDES})
target_compile_definitions (test-mongocrypt PRIVATE ${BSON_DEFINITIONS})

add_test (mongocrypt test-mongocrypt WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Exclude example-state-machine since it requires native crypto.
if (NOT MONGOCRYPT_CRYPTO STREQUAL none)
   # Define example-state-machine
   add_executable (example-state-machine test/example-state-machine.c)
   target_link_libraries (example-state-machine PRIVATE mongocrypt ${BSON_TARGET})
   target_include_directories (example-state-machine PRIVATE ${BSON_INCLUDES})
   target_compile_definitions (example-state-machine PRIVATE ${BSON_DEFINITIONS})
   target_include_directories (example-state-machine PRIVATE ./src "${CMAKE_CURRENT_SOURCE_DIR}/kms-message/src")

   # Define example-state-machine-static
   add_executable (example-state-machine-static test/example-state-machine.c)
   target_link_libraries (example-state-machine-static PRIVATE mongocrypt_static ${BSON_TARGET})
   target_include_directories (example-state-machine-static PRIVATE ${BSON_INCLUDES})
   target_compile_definitions (example-state-machine-static PRIVATE ${BSON_DEFINITIONS})
   target_include_directories (example-state-machine-static PRIVATE ./src)

   find_package (mongoc-1.0)
   if (ENABLE_ONLINE_TESTS AND mongoc-1.0_FOUND)
      message ("compiling utilities")
      add_executable (csfle test/util/csfle.c test/util/util.c)
      target_link_libraries (csfle PRIVATE mongocrypt_static)
      target_include_directories (csfle PRIVATE ${CMAKE_BINARY_DIR}/src)
      target_include_directories (csfle PRIVATE ./src)
      target_include_directories (csfle PRIVATE ./kms-message/src)
      target_link_libraries (csfle PRIVATE mongo::mongoc_shared)
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

install (
   FILES
      ${MONGOCRYPT_PUBLIC_HEADERS}
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt.h
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-config.h
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-export.h
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt
   COMPONENT Devel
)

set (BUILD_VERSION "0.0.0" CACHE STRING "Library version")

if (BUILD_VERSION STREQUAL "0.0.0")
   if (EXISTS ${PROJECT_SOURCE_DIR}/VERSION_CURRENT)
      file (STRINGS ${PROJECT_SOURCE_DIR}/VERSION_CURRENT BUILD_VERSION)
      message ("file VERSION_CURRENT contained BUILD_VERSION ${BUILD_VERSION}")
   else ()
      include (GetVersion)
      GetVersion (BUILD_VERSION)
      message ("storing BUILD_VERSION ${BUILD_VERSION} in file VERSION_CURRENT for later use")
      file (WRITE ${PROJECT_SOURCE_DIR}/VERSION_CURRENT ${BUILD_VERSION})
   endif ()
else ()
   message ("storing BUILD_VERSION ${BUILD_VERSION} in file VERSION_CURRENT for later use")
   file (WRITE ${PROJECT_SOURCE_DIR}/VERSION_CURRENT ${BUILD_VERSION})
endif ()

message ("Configuring libmongocrypt version ${BUILD_VERSION}")
set (MONGOCRYPT_BUILD_VERSION ${BUILD_VERSION})
configure_file (src/mongocrypt.h.in src/mongocrypt.h)

set (PROJECT_VERSION "${BUILD_VERSION}")
set (PROJECT_DESCRIPTION "The libmongocrypt client-side field level encryption library.")
if (NOT ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_STATIC_REQUIRES "libbson-static-1.0")
endif ()
if (ENABLE_SHARED_BSON)
   set (PKG_CONFIG_REQUIRES "libbson-1.0")
   set (PKG_CONFIG_STATIC_REQUIRES "libbson-1.0")
endif ()
set (PKG_CONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt")
set (PKG_CONFIG_LIBS "-L\${libdir} -lmongocrypt")
if (ENABLE_BUILD_FOR_PPA)
   set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} \${prefix}/${CMAKE_INSTALL_LIBDIR}/libbson-static-1.0.a")
   #librt needed for libbson on linux for clock_gettime
   find_library (RT_LIBRARY rt)
   if (RT_LIBRARY)
      set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} ${RT_LIBRARY}")
   endif ()
   set (PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} -pthread")
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

export (EXPORT mongocrypt_targets
   NAMESPACE mongo::
   FILE "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt_targets.cmake"
)

configure_file (cmake/mongocrypt-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config.cmake"
   COPYONLY
)

install (EXPORT mongocrypt_targets
   NAMESPACE mongo::
   FILE mongocrypt_targets.cmake
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/mongocrypt
)

install (
   FILES
      cmake/mongocrypt-config.cmake
      "${CMAKE_CURRENT_BINARY_DIR}/mongocrypt/mongocrypt-config-version.cmake"
   DESTINATION
      ${CMAKE_INSTALL_LIBDIR}/cmake/mongocrypt
   COMPONENT
      Devel
)

