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

set (_using_system_intel_dfp "@USE_SYSTEM_INTEL_DFP@")

if (_using_system_intel_dfp)
   find_library (_MONGOCRYPT_SYSTEM_INTEL_DFP_STATIC "${CMAKE_STATIC_LIBRARY_PREFIX}bidgcc000${CMAKE_STATIC_LIBRARY_SUFFIX}")
   set_property (
      TARGET mongo::_mongocrypt-intel_dfp
      PROPERTY IMPORTED_LOCATION "${_MONGOCRYPT_SYSTEM_INTEL_DFP_STATIC}"
      )
endif ()

find_dependency(Threads)

# Link for dlopen():
set_property(TARGET mongo::mongocrypt::platform APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${CMAKE_DL_LIBS})

# Link for special math functions:
if (NOT APPLE)
    find_library (_MONGOCRYPT_M_LIBRARY m)
    if (_MONGOCRYPT_M_LIBRARY)
        set_property(TARGET mongo::mongocrypt::platform APPEND PROPERTY INTERFACE_LINK_LIBRARIES "${_MONGOCRYPT_M_LIBRARY}")
    endif ()
endif ()

# Special runtime:
find_library (_MONGOCRYPT_RT_LIBRARY rt)
if (_MONGOCRYPT_RT_LIBRARY)
    set_property (TARGET mongo::mongocrypt::platform APPEND PROPERTY INTERFACE_LINK_LIBRARIES "${_MONGOCRYPT_RT_LIBRARY}")
endif ()
