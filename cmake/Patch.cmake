find_program(GIT_EXECUTABLE git)
find_program(PATCH_EXECUTABLE patch)

#[[
    Form a new Patch-applying command for the given inputs

    make_patch_command(
        <outvar>
        [DIRECTORY <dir>]
        [STRIP_COMPONENTS <N>]
        PATCHES [<file> ...]
    )
]]
function(make_patch_command out)
    cmake_parse_arguments(PARSE_ARGV 1 patch "" "DIRECTORY;STRIP_COMPONENTS" "PATCHES")
    if(GIT_EXECUTABLE)
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
        # git ... apply ...
        foreach(p IN LISTS patch_PATCHES)
            # git ... apply ... <file>
            list(APPEND cmd ${p})
        endforeach()
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
        foreach(p IN LISTS patch_PATCHES)
            # patch ... ---input=<file>
            list(APPEND cmd --input=${p})
        endforeach()
    endif()
    set("${out}" "${cmd}" PARENT_SCOPE)
endfunction()
