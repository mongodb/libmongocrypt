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

include(GenerateExportHeader)
include (GNUInstallDirs)

enable_testing()

option (ENABLE_TRACE "Enable verbose trace logs. Requires MONGOCRYPT_TRACE environment variable at runtime" OFF)

set (MONGOCRYPT_PUBLIC_HEADERS
   src/mongocrypt.h
   src/mongocrypt-binary.h
   src/mongocrypt-compat.h
   src/mongocrypt-decryptor.h
   src/mongocrypt-encryptor.h
   src/mongocrypt-key-broker.h
   src/mongocrypt-key-decryptor.h
   src/mongocrypt-opts.h
   src/mongocrypt-status.h
)

message ("Found libbson, configuring to add real libmongocrypt target")
message ("--   bson found version \"${BSON_VERSION}\"")
message ("--   bson include path \"${BSON_INCLUDE_DIRS}\"")
message ("--   bson libraries \"${BSON_LIBRARIES}\"")

set (MONGOCRYPT_SOURCES
   src/mongocrypt.c
   src/mongocrypt-binary.c
   src/mongocrypt-buffer.c
   src/mongocrypt-crypto.c
   src/mongocrypt-decryptor.c
   src/mongocrypt-encryptor.c
   src/mongocrypt-key-broker.c
   src/mongocrypt-key-decryptor.c
   src/mongocrypt-key-cache.c
   src/mongocrypt-log.c
   src/mongocrypt-opts.c
   src/mongocrypt-parsing.c
   src/mongocrypt-schema-cache.c
   src/mongocrypt-status.c
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
endif ()


if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   message ("Building with common crypto")
   list(APPEND MONGOCRYPT_SOURCES
      src/crypto/commoncrypto.c
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
target_include_directories (mongocrypt PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/src)
target_link_libraries (mongocrypt PRIVATE ${BSON_LIBRARIES})
target_link_libraries (mongocrypt PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions (mongocrypt PRIVATE "${BSON_DEFINITIONS}")

generate_export_header(mongocrypt EXPORT_FILE_NAME src/mongocrypt-export.h BASE_NAME mongocrypt )

add_library (mongocrypt-static STATIC ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt-static PRIVATE ${BSON_INCLUDE_DIRS})
target_include_directories (mongocrypt-static PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/src)
target_link_libraries (mongocrypt-static PRIVATE ${BSON_LIBRARIES})
target_link_libraries (mongocrypt-static PRIVATE ${CMAKE_THREAD_LIBS_INIT})
target_compile_definitions (mongocrypt-static PRIVATE "${BSON_DEFINITIONS}")
target_compile_definitions (mongocrypt-static PUBLIC MONGOCRYPT_STATIC_DEFINE)


if (MONGOCRYPT_CRYPTO STREQUAL CommonCrypto)
   target_link_libraries (mongocrypt PRIVATE "-framework CoreFoundation -framework Security")
   target_link_libraries (mongocrypt-static PRIVATE "-framework CoreFoundation -framework Security")
else ()
   target_link_libraries (mongocrypt PRIVATE ${OPENSSL_LIBRARIES})
   target_include_directories (mongocrypt PRIVATE ${OPENSSL_INCLUDE_DIR})

   target_link_libraries (mongocrypt-static PRIVATE ${OPENSSL_LIBRARIES})
   target_include_directories (mongocrypt-static PRIVATE ${OPENSSL_INCLUDE_DIR})
endif ()

# kms-message
find_package (kms_message REQUIRED)
target_link_libraries (mongocrypt PUBLIC kms_message_static)
target_link_libraries (mongocrypt-static PUBLIC kms_message_static)

set (TEST_MONGOCRYPT_SOURCES
   test/test-mongocrypt.c
   test/test-mongocrypt-crypto.c
   test/test-mongocrypt-data-key.c
   test/test-mongocrypt-encryptor.c
   test/test-mongocrypt-decryptor.c
   test/test-mongocrypt-log.c
   test/test-mongocrypt-ciphertext.c
   test/test-mongocrypt-key-broker.c
)
# Define test-mongocrypt
add_executable (test-mongocrypt ${TEST_MONGOCRYPT_SOURCES})
# Use the static version since it allows the test binary to use private symbols
target_link_libraries (test-mongocrypt PRIVATE mongocrypt-static)
target_link_libraries (test-mongocrypt PRIVATE mongocrypt)
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
