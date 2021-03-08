#!/bin/sh
# This script creates 4 folder inside $packagingFolder
# 1. libmongocrypt-all. This folder contains all platform-specific C libraries.
# 2. csharp-v{$bindingsReleaseVersion}. After all, this folder will containts the fully ready source code.
# 3. downloaded_mongocrypt. This folder contains the used in the libmongocrypt platform-specific C libraries.
# 4. artifacts. After all, the generated .nupkg files will be placed here.
#
# Input data:
# $libmongocryptAllUrl - this is the link on EG patch that contains all required platform-specific C libraries.

packagingFolder="c:/build"
bindingsReleaseVersion="1.2.1"
fork="https://github.com/DmitryLukyanov/libmongocrypt.git"
bracnhName="csharp-v1.2.1_release"
libmongocryptAllUrl="https://mciuploads.s3.amazonaws.com/libmongocrypt/all/master/508e21f4abff9f5519e0357a63a4ad30d2c24692/libmongocrypt-all.tar.gz"
libmongocryptAllFolder="libmongocrypt-all"
downloadedMongocryptFolder=downloaded_mongocrypt
csharpGitTagName=csharp-v$bindingsReleaseVersion

# Start
cd $packagingFolder
#Download libs
echo "Download libs"
mkdir $libmongocryptAllFolder
cd $libmongocryptAllFolder
curl --url $libmongocryptAllUrl --output libmongocrypt-all.tar.gz
echo "Unzipping.."
tar xzvf libmongocrypt-all.tar.gz
cd ../
read -p "Press any key to proceed with libmongocrypt cloning.."

# Clone libmongocrypt
echo "Clone Libmongocrypt"

mkdir $csharpGitTagName
cd $csharpGitTagName
git clone --branch $bracnhName $fork
cd libmongocrypt
read -p "Press any key to proceed with git tags.."

# Create git tags
git tag -a $csharpGitTagName -m $csharpGitTagName
read -p "Press any key to push this tag to origin.."
git push origin $csharpGitTagName
# Make pushing this tag to the upstream manually
read -p "Press any key to proceed with building and testing.."

# Create cmake-build
mkdir cmake-build
cd cmake-build
mkdir RelWithDebInfo
cd RelWithDebInfo
mkdir "${packagingFolder}"/"${downloadedMongocryptFolder}"
cp ${packagingFolder}/${libmongocryptAllFolder}/windows-test/bin/mongocrypt.dll ${packagingFolder}/${downloadedMongocryptFolder}
# nocrypto
cp ${packagingFolder}/${libmongocryptAllFolder}/ubuntu1804-64/nocrypto/lib/libmongocrypt.so ${packagingFolder}/${downloadedMongocryptFolder}
# nocrypto
cp ${packagingFolder}/${libmongocryptAllFolder}/macos/nocrypto/lib/libmongocrypt.dylib ${packagingFolder}/${downloadedMongocryptFolder}
cp -r ${packagingFolder}/${downloadedMongocryptFolder}/* ${packagingFolder}/${csharpGitTagName}/libmongocrypt/cmake-build/RelWithDebInfo

echo "Building.."
cd ../../bindings/cs/MongoDB.Libmongocrypt
dotnet build MongoDB.Libmongocrypt.csproj --configuration Release
echo "Running tests.."
cd ../MongoDB.Libmongocrypt.Test
# net452 tests will fail with the expected error `System.PlatformNotSupportedException : MongoDB.Libmongocrypt needs to be run in a 64-bit process.`
dotnet test MongoDB.Libmongocrypt.Test.csproj --configuration Release
read -p "Press any key to proceed with packing.."

# packing
cd ../MongoDB.Libmongocrypt
dotnet pack MongoDB.Libmongocrypt.csproj --configuration Release -p:PackageVersion=${bindingsReleaseVersion} -p:NoWarn=NU1605 -p:NoWarn=NU5100 --output ../../../../../artifacts
read -p "Done. Don't forget to push a new tag to the upstream and publish the .nupkg file"