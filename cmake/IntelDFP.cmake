
include (FetchContent)
find_program (GIT_EXECUTABLE git)
find_program (PATCH_EXECUTABLE patch)

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

# Make the PATCH_COMMAND a no-op if it was disabled
set (patch_command)
set (patch_input_opt)
if (NOT INTEL_DFP_LIBRARY_PATCH_ENABLED)
    set (patch_command "${CMAKE_COMMAND}" -E true)
elseif (GIT_EXECUTABLE)
    set (patch_command "${GIT_EXECUTABLE}" --work-tree=<SOURCE_DIR> apply)
else ()
    set (patch_command "${PATCH_EXECUTABLE}" --dir=<SOURCE_DIR>)
    set (patch_input_opt -i)
endif ()

# NOTE: The applying of the patch expects the correct input directly from the
#       expanded archive. If the patch needs to be reapplied, you may see errors
#       about trying to update the intel_dfp component. If you are seeing such
#       errors, delete the `_deps/` subdirectory in the build tree and
#       re-run CMake the project.
FetchContent_Declare (
    intel_dfp
    URL "${_default_url}"
    ${_hash_arg}
    PATCH_COMMAND
        ${patch_command}
            -p 4 # Strip four path components
            ${patch_input_opt} "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-s390x.patch"
            ${patch_input_opt} "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-MONGOCRYPT-571.patch"
            ${patch_input_opt} "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-libmongocrypt-pr-625.patch"
            ${patch_input_opt} "${PROJECT_SOURCE_DIR}/etc/mongo-inteldfp-alpine-arm-fix.patch"
            --verbose
    )

FetchContent_GetProperties (intel_dfp)
if (NOT intel_dfp_POPULATED)
    message (STATUS "Obtaining Intel Decimal FP library: ${INTEL_DFP_LIBRARY_URL}")
    FetchContent_Populate (intel_dfp)
endif ()

# This list of sources matches the ones used within MongoDB server. The
# "<library>" prefix is replaced below.
# Refer: https://github.com/mongodb/mongo/blob/e9be40f47a77af1931773ad671d4927c0fe6969a/src/third_party/IntelRDFPMathLib20U1/SConscript
set (_dfp_sources
    "<library>/float128/dpml_exception.c"
    "<library>/float128/dpml_four_over_pi.c"
    "<library>/float128/dpml_ux_bessel.c"
    "<library>/float128/dpml_ux_bid.c"
    "<library>/float128/dpml_ux_cbrt.c"
    "<library>/float128/dpml_ux_erf.c"
    "<library>/float128/dpml_ux_exp.c"
    "<library>/float128/dpml_ux_int.c"
    "<library>/float128/dpml_ux_inv_hyper.c"
    "<library>/float128/dpml_ux_inv_trig.c"
    "<library>/float128/dpml_ux_lgamma.c"
    "<library>/float128/dpml_ux_log.c"
    "<library>/float128/dpml_ux_mod.c"
    "<library>/float128/dpml_ux_ops.c"
    "<library>/float128/dpml_ux_ops_64.c"
    "<library>/float128/dpml_ux_pow.c"
    "<library>/float128/dpml_ux_powi.c"
    "<library>/float128/dpml_ux_sqrt.c"
    "<library>/float128/dpml_ux_trig.c"
    "<library>/float128/sqrt_tab_t.c"
    "<library>/src/bid128.c"
    "<library>/src/bid128_2_str_tables.c"
    "<library>/src/bid128_acos.c"
    "<library>/src/bid128_acosh.c"
    "<library>/src/bid128_add.c"
    "<library>/src/bid128_asin.c"
    "<library>/src/bid128_asinh.c"
    "<library>/src/bid128_atan.c"
    "<library>/src/bid128_atan2.c"
    "<library>/src/bid128_atanh.c"
    "<library>/src/bid128_cbrt.c"
    "<library>/src/bid128_compare.c"
    "<library>/src/bid128_cos.c"
    "<library>/src/bid128_cosh.c"
    "<library>/src/bid128_div.c"
    "<library>/src/bid128_erf.c"
    "<library>/src/bid128_erfc.c"
    "<library>/src/bid128_exp.c"
    "<library>/src/bid128_exp10.c"
    "<library>/src/bid128_exp2.c"
    "<library>/src/bid128_expm1.c"
    "<library>/src/bid128_fdimd.c"
    "<library>/src/bid128_fma.c"
    "<library>/src/bid128_fmod.c"
    "<library>/src/bid128_frexp.c"
    "<library>/src/bid128_hypot.c"
    "<library>/src/bid128_ldexp.c"
    "<library>/src/bid128_lgamma.c"
    "<library>/src/bid128_llrintd.c"
    "<library>/src/bid128_log.c"
    "<library>/src/bid128_log10.c"
    "<library>/src/bid128_log1p.c"
    "<library>/src/bid128_log2.c"
    "<library>/src/bid128_logb.c"
    "<library>/src/bid128_logbd.c"
    "<library>/src/bid128_lrintd.c"
    "<library>/src/bid128_lround.c"
    "<library>/src/bid128_minmax.c"
    "<library>/src/bid128_modf.c"
    "<library>/src/bid128_mul.c"
    "<library>/src/bid128_nearbyintd.c"
    "<library>/src/bid128_next.c"
    "<library>/src/bid128_nexttowardd.c"
    "<library>/src/bid128_noncomp.c"
    "<library>/src/bid128_pow.c"
    "<library>/src/bid128_quantexpd.c"
    "<library>/src/bid128_quantize.c"
    "<library>/src/bid128_rem.c"
    "<library>/src/bid128_round_integral.c"
    "<library>/src/bid128_scalb.c"
    "<library>/src/bid128_scalbl.c"
    "<library>/src/bid128_sin.c"
    "<library>/src/bid128_sinh.c"
    "<library>/src/bid128_sqrt.c"
    "<library>/src/bid128_string.c"
    "<library>/src/bid128_tan.c"
    "<library>/src/bid128_tanh.c"
    "<library>/src/bid128_tgamma.c"
    "<library>/src/bid128_to_int16.c"
    "<library>/src/bid128_to_int32.c"
    "<library>/src/bid128_to_int64.c"
    "<library>/src/bid128_to_int8.c"
    "<library>/src/bid128_to_uint16.c"
    "<library>/src/bid128_to_uint32.c"
    "<library>/src/bid128_to_uint64.c"
    "<library>/src/bid128_to_uint8.c"
    "<library>/src/bid32_acos.c"
    "<library>/src/bid32_acosh.c"
    "<library>/src/bid32_add.c"
    "<library>/src/bid32_asin.c"
    "<library>/src/bid32_asinh.c"
    "<library>/src/bid32_atan.c"
    "<library>/src/bid32_atan2.c"
    "<library>/src/bid32_atanh.c"
    "<library>/src/bid32_cbrt.c"
    "<library>/src/bid32_compare.c"
    "<library>/src/bid32_cos.c"
    "<library>/src/bid32_cosh.c"
    "<library>/src/bid32_div.c"
    "<library>/src/bid32_erf.c"
    "<library>/src/bid32_erfc.c"
    "<library>/src/bid32_exp.c"
    "<library>/src/bid32_exp10.c"
    "<library>/src/bid32_exp2.c"
    "<library>/src/bid32_expm1.c"
    "<library>/src/bid32_fdimd.c"
    "<library>/src/bid32_fma.c"
    "<library>/src/bid32_fmod.c"
    "<library>/src/bid32_frexp.c"
    "<library>/src/bid32_hypot.c"
    "<library>/src/bid32_ldexp.c"
    "<library>/src/bid32_lgamma.c"
    "<library>/src/bid32_llrintd.c"
    "<library>/src/bid32_log.c"
    "<library>/src/bid32_log10.c"
    "<library>/src/bid32_log1p.c"
    "<library>/src/bid32_log2.c"
    "<library>/src/bid32_logb.c"
    "<library>/src/bid32_logbd.c"
    "<library>/src/bid32_lrintd.c"
    "<library>/src/bid32_lround.c"
    "<library>/src/bid32_minmax.c"
    "<library>/src/bid32_modf.c"
    "<library>/src/bid32_mul.c"
    "<library>/src/bid32_nearbyintd.c"
    "<library>/src/bid32_next.c"
    "<library>/src/bid32_nexttowardd.c"
    "<library>/src/bid32_noncomp.c"
    "<library>/src/bid32_pow.c"
    "<library>/src/bid32_quantexpd.c"
    "<library>/src/bid32_quantize.c"
    "<library>/src/bid32_rem.c"
    "<library>/src/bid32_round_integral.c"
    "<library>/src/bid32_scalb.c"
    "<library>/src/bid32_scalbl.c"
    "<library>/src/bid32_sin.c"
    "<library>/src/bid32_sinh.c"
    "<library>/src/bid32_sqrt.c"
    "<library>/src/bid32_string.c"
    "<library>/src/bid32_sub.c"
    "<library>/src/bid32_tan.c"
    "<library>/src/bid32_tanh.c"
    "<library>/src/bid32_tgamma.c"
    "<library>/src/bid32_to_bid128.c"
    "<library>/src/bid32_to_bid64.c"
    "<library>/src/bid32_to_int16.c"
    "<library>/src/bid32_to_int32.c"
    "<library>/src/bid32_to_int64.c"
    "<library>/src/bid32_to_int8.c"
    "<library>/src/bid32_to_uint16.c"
    "<library>/src/bid32_to_uint32.c"
    "<library>/src/bid32_to_uint64.c"
    "<library>/src/bid32_to_uint8.c"
    "<library>/src/bid64_acos.c"
    "<library>/src/bid64_acosh.c"
    "<library>/src/bid64_add.c"
    "<library>/src/bid64_asin.c"
    "<library>/src/bid64_asinh.c"
    "<library>/src/bid64_atan.c"
    "<library>/src/bid64_atan2.c"
    "<library>/src/bid64_atanh.c"
    "<library>/src/bid64_cbrt.c"
    "<library>/src/bid64_compare.c"
    "<library>/src/bid64_cos.c"
    "<library>/src/bid64_cosh.c"
    "<library>/src/bid64_div.c"
    "<library>/src/bid64_erf.c"
    "<library>/src/bid64_erfc.c"
    "<library>/src/bid64_exp.c"
    "<library>/src/bid64_exp10.c"
    "<library>/src/bid64_exp2.c"
    "<library>/src/bid64_expm1.c"
    "<library>/src/bid64_fdimd.c"
    "<library>/src/bid64_fma.c"
    "<library>/src/bid64_fmod.c"
    "<library>/src/bid64_frexp.c"
    "<library>/src/bid64_hypot.c"
    "<library>/src/bid64_ldexp.c"
    "<library>/src/bid64_lgamma.c"
    "<library>/src/bid64_llrintd.c"
    "<library>/src/bid64_log.c"
    "<library>/src/bid64_log10.c"
    "<library>/src/bid64_log1p.c"
    "<library>/src/bid64_log2.c"
    "<library>/src/bid64_logb.c"
    "<library>/src/bid64_logbd.c"
    "<library>/src/bid64_lrintd.c"
    "<library>/src/bid64_lround.c"
    "<library>/src/bid64_minmax.c"
    "<library>/src/bid64_modf.c"
    "<library>/src/bid64_mul.c"
    "<library>/src/bid64_nearbyintd.c"
    "<library>/src/bid64_next.c"
    "<library>/src/bid64_nexttowardd.c"
    "<library>/src/bid64_noncomp.c"
    "<library>/src/bid64_pow.c"
    "<library>/src/bid64_quantexpd.c"
    "<library>/src/bid64_quantize.c"
    "<library>/src/bid64_rem.c"
    "<library>/src/bid64_round_integral.c"
    "<library>/src/bid64_scalb.c"
    "<library>/src/bid64_scalbl.c"
    "<library>/src/bid64_sin.c"
    "<library>/src/bid64_sinh.c"
    "<library>/src/bid64_sqrt.c"
    "<library>/src/bid64_string.c"
    "<library>/src/bid64_tan.c"
    "<library>/src/bid64_tanh.c"
    "<library>/src/bid64_tgamma.c"
    "<library>/src/bid64_to_bid128.c"
    "<library>/src/bid64_to_int16.c"
    "<library>/src/bid64_to_int32.c"
    "<library>/src/bid64_to_int64.c"
    "<library>/src/bid64_to_int8.c"
    "<library>/src/bid64_to_uint16.c"
    "<library>/src/bid64_to_uint32.c"
    "<library>/src/bid64_to_uint64.c"
    "<library>/src/bid64_to_uint8.c"
    "<library>/src/bid_binarydecimal.c"
    "<library>/src/bid_convert_data.c"
    "<library>/src/bid_decimal_data.c"
    "<library>/src/bid_decimal_globals.c"
    "<library>/src/bid_dpd.c"
    "<library>/src/bid_feclearexcept.c"
    "<library>/src/bid_fegetexceptflag.c"
    "<library>/src/bid_feraiseexcept.c"
    "<library>/src/bid_fesetexceptflag.c"
    "<library>/src/bid_fetestexcept.c"
    "<library>/src/bid_flag_operations.c"
    "<library>/src/bid_from_int.c"
    "<library>/src/bid_round.c"
    "<library>/src/strtod128.c"
    "<library>/src/strtod32.c"
    "<library>/src/strtod64.c"
    "<library>/src/wcstod128.c"
    "<library>/src/wcstod32.c"
    "<library>/src/wcstod64.c"
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
