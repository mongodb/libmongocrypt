cmake_minimum_required (VERSION 3.5)
project (kms_message
   VERSION 0.0.1
   LANGUAGES C
)

set (CMAKE_C_STANDARD 90)

include (CheckCCompilerFlag)
# All targets obey visibility, not just library targets.
cmake_policy (SET CMP0063 NEW)
set (CMAKE_C_VISIBILITY_PRESET hidden)
set (KMS_MESSAGE_SOURCES
   src/kms_b64.c
   src/kms_message/kms_b64.h
   src/hexlify.c
   src/hexlify.h
   src/kms_crypto.h
   src/kms_caller_identity_request.c
   src/kms_decrypt_request.c
   src/kms_encrypt_request.c
   src/kms_kv_list.c
   src/kms_kv_list.h
   src/kms_message.c
   src/kms_message/kms_caller_identity_request.h
   src/kms_message/kms_decrypt_request.h
   src/kms_message/kms_encrypt_request.h
   src/kms_message/kms_message.h
   src/kms_message/kms_request.h
   src/kms_message/kms_request_opt.h
   src/kms_message/kms_response.h
   src/kms_message/kms_response_parser.h
   src/kms_request.c
   src/kms_request_opt.c
   src/kms_request_opt_private.h
   src/kms_request_str.c
   src/kms_request_str.h
   src/kms_response.c
   src/kms_response_parser.c
   src/sort.c
   )

if (DISABLE_NATIVE_CRYPTO)
   set (KMS_MESSAGE_SOURCES ${KMS_MESSAGE_SOURCES}
      src/kms_crypto_none.c
   )
elseif (WIN32)
   set (KMS_MESSAGE_SOURCES ${KMS_MESSAGE_SOURCES}
      src/kms_crypto_windows.c
   )
elseif (APPLE)
   set (KMS_MESSAGE_SOURCES ${KMS_MESSAGE_SOURCES}
      src/kms_crypto_apple.c
   )
else()
   set (KMS_MESSAGE_SOURCES ${KMS_MESSAGE_SOURCES}
      src/kms_crypto_openssl.c
   )
endif()

add_library (
   kms_message SHARED
   ${KMS_MESSAGE_SOURCES}
)

add_library (
   kms_message_static STATIC
   ${KMS_MESSAGE_SOURCES}
)

if (NOT DISABLE_NATIVE_CRYPTO)
   if (WIN32)
      target_link_libraries(kms_message "bcrypt")
      target_link_libraries(kms_message_static "bcrypt")
   elseif (APPLE)
      # Nothing
   else()
      include (FindOpenSSL)
      target_link_libraries(kms_message "${OPENSSL_LIBRARIES}")
      target_include_directories(kms_message PRIVATE "${OPENSSL_INCLUDE_DIR}")
      target_link_libraries(kms_message_static "${OPENSSL_LIBRARIES}")
      target_include_directories(kms_message_static PRIVATE "${OPENSSL_INCLUDE_DIR}")
   endif()
endif ()

if ( CMAKE_COMPILER_IS_GNUCC )
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -Wno-unused-function -Wsign-compare -Werror")
endif()
if ( MSVC )
    # W4273 - inconsistent dll linkage
    # W4996 - POSIX name for this item is deprecated
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} /W3 /wd4273 /wd4996 /D_CRT_SECURE_NO_WARNINGS /WX")
endif()

set_target_properties (kms_message PROPERTIES
   SOVERSION 0
   VERSION "0.0.0"
   OUTPUT_NAME "kms_message"
)

set_target_properties (kms_message_static PROPERTIES
   SOVERSION 0
   VERSION "0.0.0"
   OUTPUT_NAME "kms_message-static"
)

target_compile_definitions (kms_message PRIVATE KMS_MSG_COMPILATION)
set_property (TARGET kms_message APPEND PROPERTY
   COMPATIBLE_INTERFACE_STRING kms_message_MAJOR_VERSION
)

target_compile_definitions (kms_message_static PRIVATE KMS_MSG_COMPILATION)
target_compile_definitions (kms_message_static PUBLIC KMS_MSG_STATIC)
set_property (TARGET kms_message_static APPEND PROPERTY
   COMPATIBLE_INTERFACE_STRING kms_message_MAJOR_VERSION
   )

include (CMakePackageConfigHelpers)
install (TARGETS kms_message kms_message_static
   EXPORT kms_message_targets
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
   RUNTIME DESTINATION bin
   INCLUDES DESTINATION include
)

install (
   FILES
   src/kms_message/kms_b64.h
   src/kms_message/kms_decrypt_request.h
   src/kms_message/kms_encrypt_request.h
   src/kms_message/kms_message.h
   src/kms_message/kms_message_defines.h
   src/kms_message/kms_request.h
   src/kms_message/kms_request_opt.h
   src/kms_message/kms_response.h
   src/kms_message/kms_response_parser.h
   DESTINATION include/kms_message
   COMPONENT Devel
)

include (CMakePackageConfigHelpers)
write_basic_package_version_file (
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config-version.cmake"
   VERSION 0.0.1
   COMPATIBILITY AnyNewerVersion
)

export (EXPORT kms_message_targets
   NAMESPACE mongo::
   FILE "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message_targets.cmake"
)

configure_file (cmake/kms_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config.cmake"
   COPYONLY
)

set (ConfigPackageLocation lib/cmake/kms_message)
install (EXPORT kms_message_targets
   NAMESPACE mongo::
   FILE kms_message_targets.cmake
   DESTINATION ${ConfigPackageLocation}
)

install (
   FILES
   cmake/kms_message-config.cmake
   "${CMAKE_CURRENT_BINARY_DIR}/kms_message/kms_message-config-version.cmake"
   DESTINATION ${ConfigPackageLocation}
   COMPONENT Devel
)

# pkg-config.
set (PKG_CONFIG_LIBDIR "\${prefix}/lib")
set (PKG_CONFIG_INCLUDEDIR "\${prefix}/include")
set (PKG_CONFIG_LIBS "-L\${libdir} -lkms_message")
set (PKG_CONFIG_CFLAGS "-I\${includedir}")
configure_file (
   "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libkms_message.pc.in"
   "${CMAKE_CURRENT_BINARY_DIR}/libkms_message.pc"
)

install (
   FILES "${CMAKE_CURRENT_BINARY_DIR}/libkms_message.pc"
   DESTINATION lib/pkgconfig
)

# cannot run tests without crypto
if (NOT DISABLE_NATIVE_CRYPTO)
   add_executable (
      test_kms_request
      ${KMS_MESSAGE_SOURCES}
      test/test_kms_request.c
   )
   target_include_directories(test_kms_request PRIVATE  ${PROJECT_SOURCE_DIR})

   if (WIN32)
      target_link_libraries(test_kms_request "bcrypt")
   elseif (APPLE)
      # Nothing
   else()
      include (FindOpenSSL)
      target_link_libraries(test_kms_request "${OPENSSL_LIBRARIES}")
      target_include_directories(test_kms_request PRIVATE "${OPENSSL_INCLUDE_DIR}")
   endif()
endif ()