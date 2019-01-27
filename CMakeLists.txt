cmake_minimum_required (VERSION 3.0)
project (mongocrypt C)

set (CMAKE_C_STANDARD 99)

find_package(libmongoc-static-1.0 1.11 REQUIRED)
message ("--   mongoc found version \"${MONGOC_VERSION}\"")
message ("--   mongoc include path \"${MONGOC_INCLUDE_DIRS}\"")
message ("--   mongoc libraries \"${MONGOC_LIBRARIES}\"")

include (FindOpenSSL)

set (MONGOCRYPT_SOURCES
   src/mongocrypt.c
   src/mongocrypt.h
   src/mongocrypt-compat.h
   src/mongocrypt-private.h
   src/mongocrypt-parsing.c
   src/mongocrypt-kms.c
   src/mongocrypt-crypto.c
   src/mongocrypt-keycache.c)

add_library (mongocrypt SHARED ${MONGOCRYPT_SOURCES})
target_include_directories(mongocrypt PRIVATE ${MONGOC_STATIC_INCLUDE_DIRS})
target_link_libraries(mongocrypt PRIVATE ${MONGOC_STATIC_LIBRARIES})
target_compile_definitions (mongocrypt PRIVATE "${MONGOC_STATIC_DEFINITIONS}")

target_link_libraries(mongocrypt PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(mongocrypt PRIVATE ${OPENSSL_INCLUDE_DIR})

find_package (kms_message REQUIRED)
target_link_libraries(mongocrypt PRIVATE kms_message_static)

add_executable(test-mongocrypt test/test-mongocrypt.c)
target_link_libraries (test-mongocrypt PRIVATE mongocrypt)
target_include_directories(test-mongocrypt PRIVATE ./src)
target_include_directories(test-mongocrypt PRIVATE ${MONGOC_STATIC_INCLUDE_DIRS})
target_link_libraries(test-mongocrypt PRIVATE ${MONGOC_STATIC_LIBRARIES})
target_compile_definitions (test-mongocrypt PRIVATE "${MONGOC_STATIC_DEFINITIONS}")
