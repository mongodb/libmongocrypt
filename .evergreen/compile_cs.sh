# Compiles libmongocrypt dependencies and targets.
#
# Set extra cflags for libmongocrypt variables by setting LIBMONGOCRYPT_EXTRA_CFLAGS.
#

set -o xtrace
set -o errexit

echo "Begin compile process"

evergreen_root="$(pwd)"

. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh

. ${evergreen_root}/libmongocrypt/.evergreen/setup-venv.sh

cd $evergreen_root

dotnet_tool=$(which dotnet)

if [ "$OS" == "Windows_NT" ]; then
    # Make sure libbson.dll is in the path on Windows
    export PATH=${INSTALL_PREFIX}/mongo-c-driver/bin:$PATH

    for var in TMP TEMP NUGET_PACKAGES NUGET_HTTP_CACHE_PATH APPDATA; do export $var=z:\\data\\tmp; done

    # Make dotnet happy over ssh
    export DOTNET_CLI_HOME=$(cygpath -w "${evergreen_root}/dotnet_home")
fi

"$dotnet_tool" build libmongocrypt/cmake-build/bindings/cs/cs.sln

"$dotnet_tool" test libmongocrypt/cmake-build/bindings/cs/MongoDB.Crypt.Test/MongoDB.Crypt.Test.csproj -- RunConfiguration.TargetPlatform=x64
