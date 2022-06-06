include(CMakeFindDependencyMacro)
find_dependency(kms_message 0.0.1)
include("${CMAKE_CURRENT_LIST_DIR}/mongocrypt_targets.cmake")

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
set (_shared_needs_libbson "@USE_SHARED_LIBBSON@")

if (NOT DEFINED MONGOCRYPT_USE_LIBBSON_TARGET)
    if (TARGET mongo::bson_static)
        set (MONGOCRYPT_USE_LIBBSON_TARGET mongo::bson_static)
    elseif (TARGET mongo::bson_shared)
        set (MONGOCRYPT_USE_LIBBSON_TARGET mongo::bson_shared)
    else ()
        if (_shared_needs_libbson)
            # If the shared lib needs libbson, then libmongocrypt is unusable until we have a
            # libbson to resolve those symbols. The caller must either find_package()
            # the mongo-c-driver *first*, or must specify a target name using the
            # the MONGOCRYPT_USE_LIBBSON_TARGET variable before calling find_package(libmongocrypt)
            message (WARNING
                "No MONGOCRYPT_USE_LIBBSON_TARGET defined, and no mongo::bson_static/mongo::bson_shared "
                "targets are available. Define MONGOCRYPT_USE_LIBBSON_TARGET to a target name or call "
                "find_package() to import a libbson library before importing libmongocrypt.")
        endif ()
        set (MONGOCRYPT_USE_LIBBSON_TARGET "NOTFOUND-MONGOCRYPT_USE_LIBBSON_TARGET")
    endif ()
endif ()

# The static libmongocrypt always requires linking against a libbson.
# If this link resolves to a `NOTFOUND-`, it means that there was no libbson target/variable set
# when find_package(libmongocrypt) was evaluated.
set_property (
    TARGET mongo::mongocrypt_static
    APPEND PROPERTY
    INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${MONGOCRYPT_USE_LIBBSON_TARGET}>"
)

if (_shared_needs_libbson)
    # If our libmongocrypt dynamic lib did not have the libbson symbols embedded, link against the
    # libbson target that the user wants to use.
    set_property (
        TARGET mongo::mongocrypt
        APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${MONGOCRYPT_USE_LIBBSON_TARGET}>"
    )
endif ()
