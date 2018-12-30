cmake_minimum_required (VERSION 3.13)
project (mongocrypt C)

set (CMAKE_C_STANDARD 99)

find_package(libmongoc-static-1.0 1.11 REQUIRED)
message ("--   mongoc found version \"${MONGOC_VERSION}\"")
message ("--   mongoc include path \"${MONGOC_INCLUDE_DIRS}\"")
message ("--   mongoc libraries \"${MONGOC_LIBRARIES}\"")

include (FindOpenSSL)

set (MONGOCRYPT_SOURCES
   mongocrypt.c
   mongocrypt.h
   mongocrypt-private.h
   mongocrypt-parsing.c
   mongocrypt-kms.c
   mongocrypt-crypto.c)

add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories(mongocrypt PRIVATE ${MONGOC_STATIC_INCLUDE_DIRS})
target_link_libraries(mongocrypt PRIVATE ${MONGOC_STATIC_LIBRARIES})
target_compile_definitions (mongocrypt PRIVATE "${MONGOC_STATIC_DEFINITIONS}")

message("OpenSSL libs are: ${OPENSSL_LIBRARIES}")
target_link_libraries(mongocrypt PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(mongocrypt PRIVATE ${OPENSSL_INCLUDE_DIR})

# TODO: do better than this.
target_link_libraries(mongocrypt PRIVATE /Users/kevinalbertson/bin/kms/lib/libkms_message_static.a)
target_include_directories(mongocrypt PRIVATE /Users/kevinalbertson/bin/kms/include/)
