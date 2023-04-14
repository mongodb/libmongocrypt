cmake_minimum_required (VERSION 3.12)

project (node-mongocrypt CXX)

set (MODULE_NAME node_mongocrypt)

if (MONGOCRYPT_DEPS STREQUAL "static")
   list (APPEND MODULE_LIBS _mongocrypt::libbson_for_static)
elseif (MONGOCRYPT_DEPS STREQUAL "shared")
   set (MONGOCRYPT_MONGOC_DIR "USE-SYSTEM")
   set (USE_SHARED_LIBBSON ON)
   list (APPEND MODULE_LIBS _mongocrypt::libbson_for_shared)
endif ()
set (BUILD_TESTING OFF)
set (ENABLE_TOOLS OFF)
set (ENABLE_ONLINE_TESTS OFF)
set (ENABLE_SHARED OFF)
set (ENABLE_STATIC ON)
add_subdirectory ("${CMAKE_CURRENT_SOURCE_DIR}/../.." "${CMAKE_CURRENT_BINARY_DIR}/libmongocrypt")
list (APPEND MODULE_INCS "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
list (APPEND MODULE_LIBS mongocrypt_static)

add_library (${MODULE_NAME} SHARED addon/mongocrypt.cc addon/mongocrypt.h ${CMAKE_JS_SRC})

set_target_properties (${MODULE_NAME} PROPERTIES PREFIX "" OUTPUT_NAME mongocrypt SUFFIX ".node")

target_include_directories (${MODULE_NAME} PRIVATE ${MODULE_INCS} ${CMAKE_JS_INC})

target_link_libraries (${MODULE_NAME} PRIVATE ${MODULE_LIBS} ${CMAKE_JS_LIB})
