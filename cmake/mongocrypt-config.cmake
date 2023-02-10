include(CMakeFindDependencyMacro)
find_dependency(kms_message 0.0.1)
include("${CMAKE_CURRENT_LIST_DIR}/mongocrypt_targets.cmake")

if (DEFINED MONGOCRYPT_LIBBSON_STATIC_USE)
    # The user has named a library that should be linked as the static libbson library
    set_property (
        TARGET mongo::_mongocrypt-libbson_for_static
        APPEND PROPERTY INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${MONGOCRYPT_LIBBSON_STATIC_USE}>"
    )
endif ()


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

if (_using_shared_libbson AND DEFINED MONGOCRYPT_LIBBSON_SHARED_USE)
    # The user has named a library that should be linked as the shared libbson library
    set_property (
        TARGET mongo::_mongocrypt-libbson_for_shared
        APPEND PROPERTY INTERFACE_LINK_LIBRARIES "$<LINK_ONLY:${MONGOCRYPT_LIBBSON_SHARED_USE}>"
    )
endif ()

#[[ BOOL:
    Whether the packaged libmongocrypt expects to use the system's DFP library. Like with
    libbson noted above, the default configuration embeds the TUs for IntelDFP within libmongocrypt
    itself. These TUs are defined with special names and won't collide with other DFP libraries
    that might be used by a final application.

    If we were built against a system DFP, libmongocrypt will have a transitive usage of
    _mongocrypt::system-dfp. We will need to define this IMPORTED target.
]]
set (_using_system_dfp "@USE_SYSTEM_DFP@")
#[[ Filename:
    If this libmongocrypt was built with the system's DFP, this is the filename of the
    library that was used during the find build. This gives us sufficient information to know
    resolve the appropriate library for transitive users.
]]
set (_system_dfp_filename "@SYSTEM_DFP_FILENAME@")

if (_using_system_dfp)
    # Find the library on the system that matches the name of the library that we used when
    # building libmongocrypt. If we found a 'libdfp.so' library, we also want to check for 'libdfp.so.1',
    # since that is the preferred binary name.
    find_library (MONGOCRYPT_SYSTEM_DFP_LIB NAMES "${_system_dfp_filename}" "${_system_dfp_filename}.1")
    if (NOT MONGOCRYPT_SYSTEM_DFP_LIB)
        message (WARNING
                 "Unable to find the '${_system_dfp_filename}' decimal floating-point library that is expected by libmongocrypt. "
                 "Application linking will likely fail. Set MONGOCRYPT_SYSTEM_DFP_LIB to a library path to use.")
    else ()
        add_library (_mongocrypt::system-dfp UNKNOWN IMPORTED)
        set_property (
            TARGET _mongocrypt::system-dfp
            PROPERTY IMPORTED_LOCATION "${MONGOCRYPT_SYSTEM_DFP_LIB}"
            )
    endif ()
endif ()
