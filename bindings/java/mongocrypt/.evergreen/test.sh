#!/bin/bash

# Test the Java bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail


if [ "Windows_NT" = "$OS" ]; then
   export JDK8="/cygdrive/c/java/jdk8"
   export JDK11="/cygdrive/c/java/jdk11"
else
  export JDK8="/opt/java/jdk8"
  export JDK11="/opt/java/jdk11"
fi

if [ -d "$JDK11" ]; then
  export JAVA_HOME=$JDK11
else
  export JAVA_HOME=$JDK8
fi

./gradlew -version
./gradlew clean downloadJnaLibs check --info -DgitRevision=${GIT_REVISION}
