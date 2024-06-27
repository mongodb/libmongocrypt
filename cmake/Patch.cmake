find_program(GIT_EXECUTABLE git)
find_program(PATCH_EXECUTABLE patch)

#[[
    Form a new Patch-applying command for the given inputs

    make_patch_command(
        <outvar>
        [DISABLED <bool>]
        [DIRECTORY <dir>]
        [STRIP_COMPONENTS <N>]
        PATCHES [<file> ...]
    )
]]
function(make_patch_command out)
    cmake_parse_arguments(PARSE_ARGV 1 patch "" "DIRECTORY;STRIP_COMPONENTS;DISABLED" "PATCHES")
    if(patch_DISABLED)
        # Use a placeholder "no-op" patch command.
        set(cmd "${CMAKE_COMMAND}" "-E" "true")
    elseif(GIT_EXECUTABLE)
        # git ...
        set(cmd ${GIT_EXECUTABLE})

        if(patch_DIRECTORY)
            # git --work-tree=...
            list(APPEND cmd --work-tree=${patch_DIRECTORY})
        endif()
        # git ... apply ...
        list(APPEND cmd apply)
        # git ... apply -pN ...
        if(patch_STRIP_COMPONENTS)
            list(APPEND cmd -p${patch_STRIP_COMPONENTS})
        endif()
        # Ignore whitespace errors to fix patch errors on Windows: The patch file may be converted to \r\n by git, but libbson fetched with \n.
        list(APPEND cmd "--ignore-whitespace")
        # git accepts patch filepaths as positional arguments
        list(APPEND cmd ${patch_PATCHES})
    else()
        # patch ...
        set(cmd ${PATCH_EXECUTABLE})
        if(patch_DIRECTORY)
            # patch --dir=...
            list(APPEND cmd --dir=${patch_DIRECTORY})
        endif()
        # patch ... -pN ...
        if(patch_STRIP_COMPONENTS)
            list(APPEND cmd -p${patch_STRIP_COMPONENTS})
        endif()
        # Prepend "--input=" to each patch filepath and add them to the argv
        list(TRANSFORM patch_PATCHES PREPEND "--input=")
        list(APPEND cmd ${patch_PATCHES})
    endif()
    set("${out}" "${cmd}" PARENT_SCOPE)
endfunction()
