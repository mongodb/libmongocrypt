cmake_minimum_required (VERSION 3.15...4.0)
project (app C)
add_executable (app app.c)
find_package (bson REQUIRED)
message ("--   libbson found version \"${bson_VERSION}\"")
target_link_libraries (app PRIVATE bson::static)

find_package (mongocrypt REQUIRED)
target_link_libraries (app PRIVATE mongo::mongocrypt)
