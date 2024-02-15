#!/bin/bash

# Test the Java bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

if [ "Windows_NT" = "$OS" ]; then
   export JAVA_HOME=/cygdrive/c/java/jdk11
else
   export JAVA_HOME=/opt/java/jdk11
fi

./gradlew -version
./gradlew clean downloadJnaLibs check --info -DgitRevision=${GIT_REVISION}
