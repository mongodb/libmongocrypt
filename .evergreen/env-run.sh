#!/usr/bin/env bash

# Executes a subcommand using a VS environment if one is requested, otherwise
# just executes the command with no modified environment

set -eu

if test -n "${VS_VERSION-}"; then
    here="$(dirname "${BASH_SOURCE[0]}")"
    # Set CC and CXX to force CMake to use cl.exe even if GCC/Clang is visible on PATH
    env _run_argv="$*" \
        CC=cl \
        CXX=cl \
        powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Unrestricted \
            -Command "$here/vs-env-run.ps1" \
                -Version "$VS_VERSION*" \
                -TargetArch "${VS_TARGET_ARCH-amd64}" \
                -Command "{ & Invoke-Expression \$env:_run_argv }"
else
    command "$@"
fi
