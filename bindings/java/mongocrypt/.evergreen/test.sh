#!/bin/bash

# Test the Java bindings for libmongocrypt

set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

export JAVA_HOME="/opt/java/jdk8"

if [ "Windows_NT" = "$OS" ]; then
   export JAVA_HOME=/cygdrive/c/java/jdk8
else
   export JAVA_HOME=/opt/java/jdk8
fi

./gradlew -version

./gradlew clean check --info -Djna.debug_load=true
