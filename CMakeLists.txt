cmake_minimum_required (VERSION 3.0)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
   project (mongocrypt C)
else()
   # GenerateExportHeader only works with C with 3.12 - https://gitlab.kitware.com/cmake/cmake/commit/de348a9638bd51af4523f36c68884b901d4aff18
   project (mongocrypt C CXX)
endif()

set (CMAKE_C_STANDARD 99)

find_package (libbson-static-1.0 1.11 REQUIRED)

include(GenerateExportHeader)

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
message ("--   bson found version \"${BSON_STATIC_VERSION}\"")
message ("--   bson include path \"${BSON_STATIC_INCLUDE_DIRS}\"")
message ("--   bson libraries \"${BSON_STATIC_LIBRARIES}\"")

set (MONGOCRYPT_SOURCES
   src/mongocrypt.c
   src/mongocrypt-binary.c
   src/mongocrypt-buffer.c
   src/mongocrypt-commoncrypto.c
   src/mongocrypt-crypto.c
   src/mongocrypt-decryptor.c
   src/mongocrypt-encryptor.c
   src/mongocrypt-key-broker.c
   src/mongocrypt-key-decryptor.c
   src/mongocrypt-key-cache.c
   src/mongocrypt-log.c
   src/mongocrypt-openssl.c
   src/mongocrypt-opts.c
   src/mongocrypt-parsing.c
   src/mongocrypt-schema-cache.c
   src/mongocrypt-status.c
   )

# Define mongocrypt library
add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt PRIVATE ${BSON_STATIC_INCLUDE_DIRS})
target_include_directories (mongocrypt PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/src)
target_link_libraries (mongocrypt PRIVATE ${BSON_STATIC_LIBRARIES})
target_compile_definitions (mongocrypt PRIVATE "${BSON_STATIC_DEFINITIONS}")

generate_export_header(mongocrypt EXPORT_FILE_NAME src/mongocrypt-export.h BASE_NAME mongocrypt )

add_library (mongocrypt-static STATIC ${MONGOCRYPT_SOURCES})
target_include_directories (mongocrypt-static PRIVATE ${BSON_STATIC_INCLUDE_DIRS})
target_include_directories (mongocrypt-static PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/src)
target_link_libraries (mongocrypt-static PRIVATE ${BSON_STATIC_LIBRARIES})
target_compile_definitions (mongocrypt-static PRIVATE "${BSON_STATIC_DEFINITIONS}")
target_compile_definitions (mongocrypt-static PUBLIC MONGOCRYPT_STATIC_DEFINE)

# Add ssl libraries to mongocrypt
if (APPLE)
   message ("Building with common crypto")
   target_compile_definitions (mongocrypt PRIVATE "MONGOCRYPT_CRYPTO_COMMONCRYPTO=1")
   target_compile_definitions (mongocrypt-static PRIVATE "MONGOCRYPT_CRYPTO_COMMONCRYPTO=1")
   target_link_libraries (mongocrypt PRIVATE "-framework CoreFoundation -framework Security")
   target_link_libraries (mongocrypt-static PRIVATE "-framework CoreFoundation -framework Security")
else ()
   message ("Building with OpenSSL")
   include (FindOpenSSL)
   message ("Found OpenSSL version ${OPENSSL_VERSION}")
   target_link_libraries (mongocrypt PRIVATE ${OPENSSL_LIBRARIES})
   target_include_directories (mongocrypt PRIVATE ${OPENSSL_INCLUDE_DIR})
   target_compile_definitions (mongocrypt PRIVATE "MONGOCRYPT_CRYPTO_OPENSSL=1")

   target_link_libraries (mongocrypt-static PRIVATE ${OPENSSL_LIBRARIES})
   target_include_directories (mongocrypt-static PRIVATE ${OPENSSL_INCLUDE_DIR})
   target_compile_definitions (mongocrypt-static PRIVATE "MONGOCRYPT_CRYPTO_OPENSSL=1")
endif ()

# kms-message
find_package (kms_message REQUIRED)
target_link_libraries (mongocrypt PUBLIC kms_message_static)
target_link_libraries (mongocrypt-static PUBLIC kms_message_static)

# Define test-mongocrypt
add_executable (test-mongocrypt test/test-mongocrypt.c)
# Use the static version since it allows the test binary to use private symbols
target_link_libraries (test-mongocrypt PRIVATE mongocrypt-static)
target_include_directories (test-mongocrypt PRIVATE ./src)
target_include_directories (test-mongocrypt PRIVATE ${BSON_STATIC_INCLUDE_DIRS})
target_link_libraries (test-mongocrypt PRIVATE ${BSON_STATIC_LIBRARIES})
target_compile_definitions (test-mongocrypt PRIVATE "${BSON_STATIC_DEFINITIONS}")

add_test(mongocrypt test-mongocrypt WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


# Define test-state-machine
add_executable (test-state-machine test/test-state-machine.c)
target_link_libraries (test-state-machine PRIVATE mongocrypt)
target_include_directories (test-state-machine PRIVATE ./src)
target_include_directories (test-state-machine PRIVATE ${BSON_STATIC_INCLUDE_DIRS})
target_link_libraries (test-state-machine PRIVATE ${BSON_STATIC_LIBRARIES})
target_compile_definitions (test-state-machine PRIVATE "${BSON_STATIC_DEFINITIONS}")
add_test(state-machine test-state-machine )

if (ENABLE_TRACE)
   target_compile_definitions (mongocrypt PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (mongocrypt-static PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (test-mongocrypt PRIVATE "MONGOCRYPT_TRACE=1")
   target_compile_definitions (test-state-machine PRIVATE "MONGOCRYPT_TRACE=1")
endif ()

install (TARGETS mongocrypt
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   RUNTIME DESTINATION bin
   INCLUDES DESTINATION include
)

install (
   FILES
      ${MONGOCRYPT_PUBLIC_HEADERS}
      ${CMAKE_CURRENT_BINARY_DIR}/src/mongocrypt-export.h
   DESTINATION include/mongocrypt
   COMPONENT Devel
)
