cmake_minimum_required (VERSION 3.5)
project (app C)
add_executable (app app.c)
find_package (bson-1.0 1.11 REQUIRED)
message ("--   libbson found version \"${bson-1.0_VERSION}\"")
target_link_libraries (app PRIVATE mongo::bson_static)

find_package (mongocrypt REQUIRED)
target_link_libraries (app PRIVATE mongo::mongocrypt)