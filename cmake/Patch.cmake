find_program (GIT_EXECUTABLE git)
find_program (PATCH_EXECUTABLE patch)

set (patch_command)
set (patch_input_opt)
if (patch_disabled)
    # Make `patch_command` a no-op if it was disabled.
    set (patch_command "${CMAKE_COMMAND}" -E true)
elseif (GIT_EXECUTABLE)
    set (patch_command "${GIT_EXECUTABLE}" --work-tree=<SOURCE_DIR> apply)
else ()
    set (patch_command "${PATCH_EXECUTABLE}" --dir=<SOURCE_DIR>)
    set (patch_input_opt -i)
endif ()
