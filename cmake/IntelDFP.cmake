
include (FetchContent)

# When updating the version of IntelDFP, also update the version in etc/purls.txt
set (_default_url "${PROJECT_SOURCE_DIR}/third-party/IntelRDFPMathLib20U2.tar.xz")

set (INTEL_DFP_LIBRARY_URL "${_default_url}"
     CACHE STRING "The URL of an Intel DFP library to use")
set (INTEL_DFP_LIBRARY_URL_HASH
     "SHA256=ac157e69c05556f3fa468ab34caeb1114a3b88ae18241bd41cc57b85a02dd314"
     CACHE STRING "The hash of the archive that lives at INTEL_DFP_LIBRARY_URL (Spelled: <ALGO>=<digest>)")
option (INTEL_DFP_LIBRARY_PATCH_ENABLED
        "Whether to apply patches to the Intel DFP library" ON)

set (_hash_arg)
if (NOT INTEL_DFP_LIBRARY_URL_SHA256 STREQUAL "no-verify")
    set (_hash_arg URL_HASH "${INTEL_DFP_LIBRARY_URL_HASH}")
endif ()

if (NOT INTEL_DFP_LIBRARY_PATCH_ENABLED)
    set (patch_disabled ON)
endif ()

include (Patch)
make_patch_command (patch_command
    STRIP_COMPONENTS 4
    PATCHES
        "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-s390x.patch"
        "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-MONGOCRYPT-571.patch"
        "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-libmongocrypt-pr-625.patch"
        "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-alpine-arm-fix.patch"
    )

# NOTE: The applying of the patch expects the correct input directly from the
#       expanded archive. If the patch needs to be reapplied, you may see errors
#       about trying to update the intel_dfp component. If you are seeing such
#       errors, delete the `_deps/` subdirectory in the build tree and
#       re-run CMake the project.
FetchContent_Declare (
    intel_dfp
    URL "${_default_url}"
    ${_hash_arg}
    PATCH_COMMAND ${patch_command} --verbose
    )

FetchContent_GetProperties (intel_dfp)
if (NOT intel_dfp_POPULATED)
    message (STATUS "Obtaining Intel Decimal FP library: ${INTEL_DFP_LIBRARY_URL}")
    FetchContent_Populate (intel_dfp)
endif ()

# This list of sources was generated by copying the MongoDB server and removing any unnecessary.
# Carefully add sources if more functionality is needed. Bundled sources are checked by static analysis, and may result in a larger binary.
# The "<library>" prefix is replaced below.
# Refer: https://github.com/mongodb/mongo/blob/e9be40f47a77af1931773ad671d4927c0fe6969a/src/third_party/IntelRDFPMathLib20U1/SConscript
set (_dfp_sources
    "<library>/float128/dpml_exception.c"
    "<library>/float128/dpml_ux_bid.c"
    "<library>/float128/dpml_ux_log.c"
    "<library>/float128/dpml_ux_ops.c"
    "<library>/float128/dpml_ux_ops_64.c"
    "<library>/src/bid128.c"
    "<library>/src/bid128_2_str_tables.c"
    "<library>/src/bid128_add.c"
    "<library>/src/bid128_compare.c"
    "<library>/src/bid128_div.c"
    "<library>/src/bid128_fma.c"
    "<library>/src/bid128_fmod.c"
    "<library>/src/bid128_log10.c"
    "<library>/src/bid128_log2.c"
    "<library>/src/bid128_modf.c"
    "<library>/src/bid128_mul.c"
    "<library>/src/bid128_noncomp.c"
    "<library>/src/bid128_round_integral.c"
    "<library>/src/bid128_scalb.c"
    "<library>/src/bid128_scalbl.c"
    "<library>/src/bid128_string.c"
    "<library>/src/bid128_to_int64.c"
    "<library>/src/bid64_to_bid128.c"
    "<library>/src/bid_binarydecimal.c"
    "<library>/src/bid_convert_data.c"
    "<library>/src/bid_decimal_data.c"
    "<library>/src/bid_flag_operations.c"
    "<library>/src/bid_round.c"
    )
# Put in the actual library path:
string (REPLACE "<library>" "${intel_dfp_SOURCE_DIR}/LIBRARY" _dfp_sources "${_dfp_sources}")

#[[
    Intel DFP gives us a very blunt yet powerful hammer to avoid symbol
    collision, since other library may also want a conflicting
    DFP version: Just rename everything!

    All function names are #defined with a `bid` or `binary` prefix, and are
    aliased to their "actual" names with a `__bid` or `__binary` prefix,
    respectively.

    So we can ship our own decimal library without worry, we'll rename those
    hidden symbols.
]]
file (READ "${intel_dfp_SOURCE_DIR}/LIBRARY/src/bid_conf.h" dfp_conf_content)
string (REGEX REPLACE
    #[[
        Match every "#define X Y" where X begins with `"bid" or "binary", and Y
        begins with "__bid" or "__binary". X and Y must be separated by one or
        more spaces.
    ]]
    "#define ((bid|binary)[^ ]+ +)__(bid|binary)([^ +])"
    # Replace Y with "__mongocrypt_bid" or "__mongocrypt_binary" as the new prefix.
    "#define \\1 __mongocrypt_\\3\\4"
    new_content "${dfp_conf_content}"
    )
if (NOT new_content STREQUAL dfp_conf_content)
    # Only rewrite the file if we changed anything, otherwise we update build
    # input timestamps and will trigger a rebuild of DFP.
    file (WRITE "${intel_dfp_SOURCE_DIR}/LIBRARY/src/bid_conf.h" "${new_content}")
endif ()

# Define the object library
add_library (intel_dfp_obj OBJECT ${_dfp_sources})
# Build with -fPIC, since these objects may go into a static OR dynamic library.
set_property (TARGET intel_dfp_obj PROPERTY POSITION_INDEPENDENT_CODE TRUE)

# DFP needs information about the build target platform. Compute that:
set (proc_lower $<LOWER_CASE:${CMAKE_SYSTEM_PROCESSOR}>)
set (ia32_list i386 i486 i586 i686 pentium3 pentium4 athlon geode emscripted x86 arm)
set (efi2_list aarch64 arm64 x86_64 ppc64le riscv64)

set (is_linux $<PLATFORM_ID:Linux>)
set (is_windows $<PLATFORM_ID:Windows>)
set (is_unix $<NOT:${is_windows}>)

# These compiler definitions may seem a bit strange, but the whole DFP library's
# config process is strange. These options match those used in MongoDB server.
target_compile_definitions (intel_dfp_obj PUBLIC
    DECIMAL_CALL_BY_REFERENCE=0
    DECIMAL_GLOBAL_ROUNDING=0
    DECIMAL_GLOBAL_EXCEPTION_FLAGS=0
    UNCHANGED_BINARY_STATUS_FLAGS=0
    USE_COMPILER_F128_TYPE=0
    USE_COMPILER_F80_TYPE=0
    USE_NATIVE_QUAD_TYPE=0
    $<${is_unix}:LINUX=1>
    $<$<PLATFORM_ID:Darwin>:mach=1>
    $<$<PLATFORM_ID:FreeBSD>:freebsd=1>
    $<$<PLATFORM_ID:Linux>:linux=1>
    $<${is_windows}:
        WINDOWS=1
        WNT=1
        winnt=1
    >
    $<$<IN_LIST:${proc_lower},${ia32_list}>:
        IA32=1
        ia32=1
    >
    $<$<IN_LIST:${proc_lower},${efi2_list}>:
        EFI2=1
        efi2=1
    >
    $<$<STREQUAL:${proc_lower},s390x>:
        s390x=1
        BID_BIG_ENDIAN=1
    >
    )

# Suppress warnings in the Intel library, as it generates a lot that aren't of interest
target_compile_options (intel_dfp_obj PRIVATE -w)
target_include_directories(intel_dfp_obj PUBLIC ${intel_dfp_SOURCE_DIR}/LIBRARY/src)

# Define an interface library that attaches the built TUs to the consumer
add_library (_mongocrypt_intel_dfp INTERFACE)
add_library (mongocrypt::intel_dfp ALIAS _mongocrypt_intel_dfp)

# Notify in-tree consumers that IntelDFP is available:
target_compile_definitions (_mongocrypt_intel_dfp INTERFACE $<BUILD_INTERFACE:MONGOCRYPT_INTELDFP>)

target_sources (_mongocrypt_intel_dfp
    #[[
        For targets *within this build* that link with mongocrypt::intel_dfp,
        inject the generated TUs (object files) from the intel_dfp_obj library.

        This will be stripped out of the interface library when it is installed,
        since we don't want to ship the DFP object separately. Instead, users
        will link to libmongocrypt, which will contain the necessary TUs for
        the library (because they link to this interface library).
    ]]
    INTERFACE $<BUILD_INTERFACE:$<TARGET_OBJECTS:intel_dfp_obj>>
    )
target_link_libraries (_mongocrypt_intel_dfp
    INTERFACE
        $<BUILD_INTERFACE:intel_dfp_obj>
        # We do want to propagate an interface requirement: Some platforms need a
        # separate link library to support special math functions.
        $<$<PLATFORM_ID:Linux>:m>
    )

# Give the installed target a name to indicate its hidden-ness
set_property (TARGET _mongocrypt_intel_dfp PROPERTY EXPORT_NAME private::intel_dfp_interface)
install (TARGETS _mongocrypt_intel_dfp EXPORT mongocrypt_targets)
