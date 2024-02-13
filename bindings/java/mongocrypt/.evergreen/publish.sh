#!/bin/bash

# DO NOT ECHO COMMANDS AS THEY CONTAIN SECRETS!

set -o errexit  # Exit the script with error if any of the commands fail

############################################
#            Main Program                  #
############################################

echo ${RING_FILE_GPG_BASE64} | base64 -d > ${PROJECT_DIRECTORY}/secring.gpg

trap "rm ${PROJECT_DIRECTORY}/secring.gpg; exit" EXIT HUP

export ORG_GRADLE_PROJECT_nexusUsername=${NEXUS_USERNAME}
export ORG_GRADLE_PROJECT_nexusPassword=${NEXUS_PASSWORD}
export ORG_GRADLE_PROJECT_signing_keyId=${SIGNING_KEY_ID}
export ORG_GRADLE_PROJECT_signing_password=${SIGNING_PASSWORD}
export ORG_GRADLE_PROJECT_signing_secretKeyRingFile=${PROJECT_DIRECTORY}/secring.gpg

echo "Publishing snapshot with jdk8"
export JAVA_HOME="/opt/java/jdk8"

SYSTEM_PROPERTIES="-Dorg.gradle.internal.publish.checksums.insecure=true -Dorg.gradle.internal.http.connectionTimeout=120000 -Dorg.gradle.internal.http.socketTimeout=120000"

{
    # Add output of git commands as system properties.
    # These values can be computed in Gradle. This is to work around observed hangs computing these values in Gradle on JDK 8. Refer: MONGOCRYPT-590.
    # Once JDK 8 is no longer the minimum this block may be removed.
    gitDescribe="$(git describe --tags --always --dirty)"
    gitRevision="$(git rev-parse HEAD)"
    if git describe --tags --exact-match HEAD >/dev/null 2>&1; then
        # Commit is tagged. Check if it is a "java-" tag.
        if [[ "$gitDescribe" == "java-"* ]]; then
            # Get commit for the libmongocrypt tag by removing the "java-" prefix.
            libmongocryptTag="${gitDescribe:5}"
            # Use `git rev-list` to get tagged commit hash. (`git rev-parse` returns the tag hash)
            gitRevision=$(git rev-list -n 1 $libmongocryptTag)
        fi
    fi
    SYSTEM_PROPERTIES="$SYSTEM_PROPERTIES -DgitDescribe=${gitDescribe} -DgitRevision=${gitRevision}"
}

./gradlew -version
./gradlew ${SYSTEM_PROPERTIES} --stacktrace --info  publishToSonatype
