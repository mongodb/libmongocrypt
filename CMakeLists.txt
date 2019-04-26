cmake_minimum_required (VERSION 3.7)
# 3.7 is the minimum for VERSION_GREATER_EQUAL

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
   project (mongocrypt C)
else()
   # GenerateExportHeader only works with C with 3.12 - https://gitlab.kitware.com/cmake/cmake/commit/de348a9638bd51af4523f36c68884b901d4aff18
   project (mongocrypt C CXX)
endif()

set (CMAKE_C_STANDARD 99)

find_package (libbson-1.0 1.11 REQUIRED)
find_package ( Threads REQUIRED )

add_subdirectory(bindings/cs)

include(GenerateExportHeader)
include (GNUInstallDirs)

enable_testing()

option (ENABLE_TRACE "Enable verbose trace logs. Requires MONGOCRYPT_TRACE environment variable at runtime" OFF)

set (MONGOCRYPT_PUBLIC_HEADERS
   src/mongocrypt.h
   src/mongocrypt-compat.h
)

message ("Found libbson, configuring to add real libmongocrypt target")
message ("--   bson found version \"${BSON_VERSION}\"")
message ("--   bson include path \"${BSON_INCLUDE_DIRS}\"")
message ("--   bson libraries \"${BSON_LIBRARIES}\"")

set (MONGOCRYPT_SOURCES
   src/mongocrypt-binary.c
   src/mongocrypt-buffer.c
   src/mongocrypt-cache.c
   src/mongocrypt-cache-collinfo.c
   src/mongocrypt-cache-key.c
   src/mongocrypt-ciphertext.c
   src/mongocrypt-crypto.c
   src/mongocrypt-ctx-datakey.c
   src/mongocrypt-ctx-decrypt.c
   src/mongocrypt-ctx-encrypt.c
   src/mongocrypt-ctx.c
   src/mongocrypt-key.c
   src/mongocrypt-key-broker.c
   src/mongocrypt-kms-ctx.c
   src/mongocrypt-log.c
   src/mongocrypt-marking.c
   src/mongocrypt-opts.c
   src/mongocrypt-status.c
   src/mongocrypt-traverse-util.c
   src/mongocrypt.c
   )

if (WIN32)
   list(APPEND MONGOCRYPT_SOURCES
      src/os_win/os_mutex.c
      src/os_win/os_once.c
   )
else()
   list(APPEND MONGOCRYPT_SOURCES
      src/os_posix/os_mutex.c
      src/os_posix/os_once.c
   )
endif()


if ( MSVC )
   # W4996 - POSIX name for this item is deprecated
   set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} /W3 /wd4996 /D_CRT_SECURE_NO_WARNINGS /WX")

   # TODO: add support for clang-cl which is detected as MSVC
else()
   # GNU, Clang, AppleClang
   set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -Werror -Wno-missing-braces -Wno-unused-function")
endif()

# Choose a Crypto provider
set (MONGOCRYPT_CRYPTO OpenSSL)
if (APPLE)
   set (MONGOCRYPT_CRYPTO CommonCrypto)
elseif (WIN32)
   set (MONGOCRYPT_CRYPTO CNG)
endif ()


if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   message ("Building with common crypto")
   list(APPEND MONGOCRYPT_SOURCES
      src/crypto/commoncrypto.c
   )
elseif (MONGOCRYPT_CRYPTO STREQUAL CNG)
   message ("Building with CNG")
   list(APPEND MONGOCRYPT_SOURCES
      src/crypto/cng.c
   )
else ()
   message ("Building with OpenSSL")
   include (FindOpenSSL)
   message ("Found OpenSSL version ${OPENSSL_VERSION}")
   list(APPEND MONGOCRYPT_SOURCES
      src/crypto/openssl.c
   )
endif ()


# Define mongocrypt library
add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt PRIVATE ${BSON_INCLUDE_DIRS})
target_include_directories (mongocrypt PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>)
target_link_libraries (mongocrypt PRIVATE ${BSON_LIBRARIES})
target_link_libraries (mongocrypt PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions (mongocrypt PRIVATE "${BSON_DEFINITIONS}")

generate_export_header(mongocrypt EXPORT_FILE_NAME src/mongocrypt-export.h BASE_NAME mongocrypt )

add_library (mongocrypt-static STATIC ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt-static PRIVATE ${BSON_INCLUDE_DIRS})
target_include_directories (mongocrypt-static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/src>)
target_link_libraries (mongocrypt-static PRIVATE ${BSON_LIBRARIES})
target_link_libraries (mongocrypt-static PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions (mongocrypt-static PRIVATE "${BSON_DEFINITIONS}")
target_compile_definitions (mongocrypt-static PUBLIC MONGOCRYPT_STATIC_DEFINE)


if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   target_link_libraries (mongocrypt PRIVATE "-framework CoreFoundation -framework Security")
   target_link_libraries (mongocrypt-static PRIVATE "-framework CoreFoundation -framework Security")
elseif (MONGOCRYPT_CRYPTO STREQUAL CNG)
   target_link_libraries (mongocrypt PRIVATE "bcrypt")
   target_link_libraries (mongocrypt-static PRIVATE "bcrypt")
else ()
   target_link_libraries (mongocrypt PRIVATE OpenSSL::SSL OpenSSL::Crypto)
   target_link_libraries (mongocrypt-static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif ()

# kms-message
find_package (kms_message REQUIRED)
target_link_libraries (mongocrypt PRIVATE kms_message_static)
target_link_libraries (mongocrypt-static PRIVATE kms_message_static)

set (TEST_MONGOCRYPT_SOURCES
   test/test-mongocrypt-cache.c
   test/test-mongocrypt-ciphertext.c
   test/test-mongocrypt-crypto.c
   test/test-mongocrypt-ctx-decrypt.c
   test/test-mongocrypt-ctx-encrypt.c
   test/test-mongocrypt-datakey.c
   test/test-mongocrypt-key-broker.c
   test/test-mongocrypt-local-kms.c
   test/test-mongocrypt-log.c
   test/test-mongocrypt.c
)
# Define test-mongocrypt
add_executable (test-mongocrypt ${TEST_MONGOCRYPT_SOURCES})
# Use the static version since it allows the test binary to use private symbols
target_link_libraries (test-mongocrypt PRIVATE mongocrypt-static)
target_link_libraries (test-mongocrypt PRIVATE mongocrypt)
target_link_libraries (test-mongocrypt PRIVATE kms_message_static)
target_include_directories (test-mongocrypt PRIVATE ./src)
target_include_directories (test-mongocrypt PRIVATE ${BSON_INCLUDE_DIRS})
target_link_libraries (test-mongocrypt PRIVATE ${BSON_LIBRARIES})
target_compile_definitions (test-mongocrypt PRIVATE "${BSON_DEFINITIONS}")

add_test(mongocrypt test-mongocrypt WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Define example-state-machine
add_executable (example-state-machine test/example-state-machine.c)
target_link_libraries (example-state-machine PRIVATE mongocrypt)
target_include_directories (example-state-machine PRIVATE ./src)
target_include_directories (example-state-machine PRIVATE ${BSON_INCLUDE_DIRS})
target_link_libraries (example-state-machine PRIVATE ${BSON_LIBRARIES})
target_compile_definitions (example-state-machine PRIVATE "${BSON_DEFINITIONS}")

if (ENABLE_TRACE)
   target_compile_definitions (mongocrypt PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (mongocrypt-static PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (test-mongocrypt PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (example-state-machine PRIVATE "MONGOCRYPT_TRACE=1")
endif ()

install (TARGETS mongocrypt
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
   INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (TARGETS mongocrypt-static
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
   RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
   INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install (
   FILES
      ${MONGOCRYPT_PUBLIC_HEADERS}
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-export.h
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt
   COMPONENT Devel
)

set (PROJECT_VERSION "0.2.0")
set (PKG_CONFIG_REQUIRES_PRIVATE "libbson-1.0")
set (PKG_CONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt")
set (PKG_CONFIG_LIBS "-L\${libdir} -lmongocrypt")
set (PKG_CONFIG_CFLAGS "-I\${includedir}")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libmongocrypt.pc"
)
set (PKG_CONFIG_STATIC_LIBS "\${prefix}/${CMAKE_INSTALL_LIBDIR}/libmongocrypt-static.a")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libmongocrypt-static.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libmongocrypt-static.pc"
)

install (
   FILES "${CMAKE_BINARY_DIR}/libmongocrypt.pc"
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
install (
   FILES "${CMAKE_BINARY_DIR}/libmongocrypt-static.pc"
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

include (CMakePackageConfigHelpers)
set (INCLUDE_INSTALL_DIRS "${CMAKE_INSTALL_INCLUDEDIR}/mongocrypt")
set (LIBRARY_INSTALL_DIRS ${CMAKE_INSTALL_LIBDIR})

write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-config-version.cmake"
   COMPATIBILITY AnyNewerVersion
)
write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-static-config-version.cmake"
   COMPATIBILITY AnyNewerVersion
)

configure_package_config_file (
   cmake/libmongocrypt-config.cmake.in
   ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-config.cmake
   INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libmongocrypt-config.cmake
   PATH_VARS INCLUDE_INSTALL_DIRS LIBRARY_INSTALL_DIRS
)
configure_package_config_file (
   cmake/libmongocrypt-static-config.cmake.in
   ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-static-config.cmake
   INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libmongocrypt-static-config.cmake
   PATH_VARS INCLUDE_INSTALL_DIRS LIBRARY_INSTALL_DIRS
)

install (
   FILES
      ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-config.cmake
      ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-config-version.cmake
   DESTINATION
      ${CMAKE_INSTALL_LIBDIR}/cmake/libmongocrypt
)
install (
   FILES
      ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-static-config.cmake
      ${CMAKE_CURRENT_BINARY_DIR}/cmake/libmongocrypt-static-config-version.cmake
   DESTINATION
      ${CMAKE_INSTALL_LIBDIR}/cmake/libmongocrypt-static
)

