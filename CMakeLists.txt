cmake_minimum_required (VERSION 3.0)
project (mongocrypt C)

set (CMAKE_C_STANDARD 99)

find_package(libmongoc-static-1.0 1.11)

set (MONGOCRYPT_PUBLIC_HEADERS
   src/mongocrypt.h
   src/mongocrypt-binary.h
   src/mongocrypt-compat.h
   src/mongocrypt-key-query.h
   src/mongocrypt-opts.h
   src/mongocrypt-request.h
   src/mongocrypt-status.h
)

if(MONGOC_STATIC_VERSION)
   message("Found libmongoc and libbson, configuring to add real libmongocrypt target")
   message ("--   mongoc found version \"${MONGOC_STATIC_VERSION}\"")
   message ("--   mongoc include path \"${MONGOC_STATIC_INCLUDE_DIRS}\"")
   message ("--   mongoc libraries \"${MONGOC_STATIC_LIBRARIES}\"")

   include (FindOpenSSL)
   message ("Found OpenSSL version ${OPENSSL_VERSION}")

   set (MONGOCRYPT_SOURCES
      src/mongocrypt.c
      src/mongocrypt-buffer.c
      src/mongocrypt-crypto.c
      src/mongocrypt-key-query.c
      src/mongocrypt-kms.c
      src/mongocrypt-key-cache.c
      src/mongocrypt-openssl.c
      src/mongocrypt-opts.c
      src/mongocrypt-parsing.c
      src/mongocrypt-request.c
      src/mongocrypt-status.c
      )

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
else()
   message("libmongoc and libbson *NOT* found. Only configuring mongocrypt-stub target")
endif()

set (MONGOCRYPT_STUB_SOURCES
   src/mongocrypt-stub.c)

add_library (mongocrypt-stub SHARED ${MONGOCRYPT_STUB_SOURCES})

add_executable (test-mongocrypt-stub test/test-mongocrypt-stub.c)
target_link_libraries (test-mongocrypt-stub PRIVATE mongocrypt-stub)
target_include_directories (test-mongocrypt-stub PRIVATE ./src)

install (TARGETS mongocrypt mongocrypt-stub
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   RUNTIME DESTINATION bin
   INCLUDES DESTINATION include
)

install (
   FILES
   ${MONGOCRYPT_PUBLIC_HEADERS}
   DESTINATION include/mongocrypt
   COMPONENT Devel
)