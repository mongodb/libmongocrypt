#!/bin/bash

# DO NOT ECHO COMMANDS AS THEY CONTAIN SECRETS!

set -o errexit  # Exit the script with error if any of the commands fail

############################################
#            Main Program                  #
############################################

echo ${ring_file_gpg_base64} | base64 -d > ${PROJECT_DIRECTORY}/secring.gpg

trap "rm ${PROJECT_DIRECTORY}/secring.gpg; exit" EXIT HUP

export ORG_GRADLE_PROJECT_nexusUsername=${nexus_username}
export ORG_GRADLE_PROJECT_nexusPassword=${nexus_password}
export ORG_GRADLE_PROJECT_signing_keyId=${signing_keyId}
export ORG_GRADLE_PROJECT_signing_password=${signing_password}
export ORG_GRADLE_PROJECT_signing_secretKeyRingFile=${PROJECT_DIRECTORY}/secring.gpg

echo "Publishing snapshot with jdk11"
export JAVA_HOME="/opt/java/jdk11"

SYSTEM_PROPERTIES="-Dorg.gradle.internal.publish.checksums.insecure=true -Dorg.gradle.internal.http.connectionTimeout=120000 -Dorg.gradle.internal.http.socketTimeout=120000"

./gradlew -version
./gradlew ${SYSTEM_PROPERTIES} --stacktrace --info  publishToSonatype
