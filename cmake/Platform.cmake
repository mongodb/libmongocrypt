#[[
    Defines a platform-support target _mongocrypt::platform.

    This target sets certain internal-only compile definitions, and defines
    usage requirements on certain platform features required by libmongocrypt
    (Threads, dlopen(), math)
]]

add_library (lmc-platform INTERFACE)
add_library (mongocrypt::platform ALIAS lmc-platform)
install (TARGETS lmc-platform EXPORT mongocrypt_targets)
set_property (
    TARGET lmc-platform
    PROPERTY EXPORT_NAME mongocrypt::platform
    )

# Threads:
find_package (Threads REQUIRED)

# Special math:
if (NOT APPLE)
    find_library (M_LIBRARY m)
endif ()

# Special runtime:
find_library (RT_LIBRARY rt)

# Endian detection:
if (DEFINED CMAKE_C_BYTE_ORDER)
    # Newer CMake knows this immediately:
    set (MONGOCRYPT_ENDIAN_DEF "MONGOCRYPT_${CMAKE_C_BYTE_ORDER}")
else ()
    include (TestBigEndian)
    test_big_endian (_is_big)
    set (MONGOCRYPT_ENDIAN_DEF "MONGOCRYPT_$<IF:${_is_big},BIG,LITTLE>_ENDIAN")
endif ()

target_compile_definitions (lmc-platform INTERFACE
    "$<BUILD_INTERFACE:${MONGOCRYPT_ENDIAN_DEF}>"
    )
target_link_libraries (lmc-platform INTERFACE
    Threads::Threads
    # These are build-interface libs, but still required. These will be added
    # to the platform library in mongocrypt-config.cmake using the same
    # find_library() calls:
    $<BUILD_INTERFACE:${CMAKE_DL_LIBS}>
    $<BUILD_INTERFACE:$<$<BOOL:${M_LIBRARY}>:${M_LIBRARY}>>
    $<BUILD_INTERFACE:$<$<BOOL:${RT_LIBRARY}>:${RT_LIBRARY}>>
    )

