
set (MONGO_LTO "OFF"
    CACHE STRING
    "Enable cross-translation unit optimizations (A.K.A. IPO/LTO/LTCG) [OFF/DEFAULT/FAT/THIN]"
    )
set_property (CACHE MONGO_LTO PROPERTY STRINGS OFF DEFAULT FAT THIN)

if (MONGO_LTO STREQUAL "OFF")
    # Nothing to do
    return ()
endif ()

# CMake will know if LTO is supported at any basic level
include (CheckIPOSupported)
check_ipo_supported (RESULT supported OUTPUT out)
if (NOT supported)
    message (SEND_ERROR "LTO is not supported by the compiler (requested by MONGO_LTO=${MONGO_LTO}):\n${out}")
    return ()
endif ()

# Set the appropriate compile/link flags for LTO:
set (_c_flags)
set (_link_flags)
if (MONGO_LTO STREQUAL "DEFAULT")
    # Just use CMake's default INTERPROCEDURAL_OPTIMIZATION
    message (STATUS "Enabling INTERPROCEDURAL_OPTIMIZATION")
    set_property (DIRECTORY PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
elseif (MONGO_LTO STREQUAL "THIN")
    set (_c_flags -flto=thin)
    set (_link_flags -flto=thin)
elseif (MONGO_LTO STREQUAL "FAT")
    set (_c_flags -flto -ffat-lto-objects)
    set (_link_flags -flto=auto)
else ()
    message (SEND_ERROR "Unknown MONGO_LTO setting '${MONGO_LTO}'")
    return ()
endif ()

# We need try_compile(), because we need more than one source file to accurately
# check for LTO support
try_compile (
    MONGO_HAVE_LTO_${MONGO_LTO}
    "${CMAKE_CURRENT_BINARY_DIR}/_mongo-lto-check/${MONGO_LTO}"
    SOURCES "${CMAKE_CURRENT_LIST_DIR}/ltocheck-lib.c"
            "${CMAKE_CURRENT_LIST_DIR}/ltocheck-main.c"
    COMPILE_DEFINITIONS ${_c_flags}
    LINK_LIBRARIES ${_link_flags}
    OUTPUT_VARIABLE out
    )

if (NOT MONGO_HAVE_LTO_${MONGO_LTO})
    message (SEND_ERROR "MONGO_LTO=${MONGO_LTO} is not supported by the current compiler:\n${out}")
    return ()
endif ()

add_compile_options (${_c_flags})
link_libraries (${_link_flags})
