include(CMakeFindDependencyMacro)
find_dependency(kms_message 0.0.1)
include("${CMAKE_CURRENT_LIST_DIR}/mongocrypt_targets.cmake")

# Find the libbson that will be used for static linking
if (DEFINED MONGOCRYPT_LIBBSON_STATIC_USE)
    set (_static "${MONGOCRYPT_LIBBSON_STATIC_USE}")
elseif (TARGET mongo::bson_static)
    set (_static mongo::bson_static)
else ()
    find_library (
        _MONGOCRYPT_LIBBSON_STATIC_LIB_PATH
        "${CMAKE_STATIC_LIBRARY_PREFIX}bson-static-1.0${CMAKE_STATIC_LIBRARY_SUFFIX}"
        DOC "The static library of libbson that will be used for mongo::mongocrypt_static"
    )
    set (_static "${_MONGOCRYPT_LIBBSON_STATIC_LIB_PATH}")
endif ()

# The static libmongocrypt always requires linking against a libbson.
# If this link resolves to a `NOTFOUND-`, it means that there was no libbson target/variable set
# when find_package(libmongocrypt) was evaluated.
set_property (
    TARGET mongo::_mongocrypt-libbson_for_static
    APPEND PROPERTY INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${_static}>"
)

# BOOL: Whether the libmongocrypt dynamic library in this package needs to link to an external libbson.
#   In the default configuration, the shared lib will include the TUs for a pinned version of libbson
#   and will use linker scripts to "hide" these symbols from the outside world.
#
#   If the libmongocrypt package was built to link against a shared libbson library, then the
#   libmongocrypt dynamic library will contain pending references to libbson symbols that will
#   need to be resolved before the library can be used.
#
#   (Note: static libmongocrypt *always* needs to link against an external libbson, as it does not
#    embed the libbson symbols.)
set (_using_shared_libbson "@USE_SHARED_LIBBSON@")

if (NOT _using_shared_libbson)
    # The libmongocrypt shared library already includes embedded libbson symbols, so there is
    # no usage requirements for a libbson
else ()
    if (DEFINED MONGOCRYPT_LIBBSON_SHARED_USE)
        set (_shared "${MONGOCRYPT_LIBBSON_SHARED_USE}")
    elseif (TARGET mongo::bson_shared)
        set (_shared mongo::bson_shared)
    else ()
        find_library (
            _MONGOCRYPT_LIBBSON_SHARED_LIB_PATH bson-1.0
            DOC "The libbson dynamic library that will be used for linking with mongo::mongocrypt"
        )
        set (_shared "${_MONGOCRYPT_LIBBSON_SHARED_LIB_PATH}")
    endif ()
    set_property (
        TARGET mongo::_mongocrypt-libbson_for_shared
        APPEND PROPERTY INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${_shared}>"
    )
endif ()
