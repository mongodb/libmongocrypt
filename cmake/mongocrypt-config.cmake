include(CMakeFindDependencyMacro)
find_dependency(kms_message 0.0.1)
include("${CMAKE_CURRENT_LIST_DIR}/mongocrypt_targets.cmake")
