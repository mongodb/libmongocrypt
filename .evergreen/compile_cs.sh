#!/bin/bash

# Compiles libmongocrypt dependencies and targets.
#
# Set extra cflags for libmongocrypt variables by setting LIBMONGOCRYPT_EXTRA_CFLAGS.
#

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

echo "Begin compile process"

evergreen_root="$(pwd)"

if [ "$OS_NAME" = "windows" ]; then
    # Make sure libbson.dll is in the path on Windows
    export PATH="${MONGOCRYPT_INSTALL_PREFIX}/mongo-c-driver/bin:$PATH"

    for var in TMP TEMP NUGET_PACKAGES NUGET_HTTP_CACHE_PATH APPDATA; do export $var=z:\\data\\tmp; done

    # Make dotnet happy over ssh
    export DOTNET_CLI_HOME=$(cygpath -w "${evergreen_root}/dotnet_home")
else
    export PATH=$PATH:/usr/share/dotnet
fi

dotnet_tool=$(which dotnet)

"$dotnet_tool" build -c Release "$LIBMONGOCRYPT_DIR/cmake-build/bindings/cs/cs.sln"

"$dotnet_tool" test -c Release "$LIBMONGOCRYPT_DIR/cmake-build/bindings/cs/MongoDB.Libmongocrypt.Test/MongoDB.Libmongocrypt.Test.csproj" -- RunConfiguration.TargetPlatform=x64
