#!/usr/bin/bash

set -eux

DRIVERS_TOOLS="$(pwd)/drivers-tools"
PROJECT_DIRECTORY="$(pwd)/libmongocrypt"

# Python has cygwin path problems on Windows.
if [ "Windows_NT" = "${OS:-}" ]; then
    DRIVERS_TOOLS=$(cygpath -m $DRIVERS_TOOLS)
    PROJECT_DIRECTORY=$(cygpath -m $PROJECT_DIRECTORY)
fi
export PROJECT_DIRECTORY
export DRIVERS_TOOLS

export MONGO_ORCHESTRATION_HOME="$DRIVERS_TOOLS/.evergreen/orchestration"
export MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"

cat <<EOT > expansion.yml
DRIVERS_TOOLS: "$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME: "$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES: "$MONGODB_BINARIES"
PROJECT_DIRECTORY: "$PROJECT_DIRECTORY"
EOT

# Set up drivers-tools with a .env file.
git clone --branch fix-csfle-teardown https://github.com/blink1073/drivers-evergreen-tools.git ${DRIVERS_TOOLS}
cat <<EOT > ${DRIVERS_TOOLS}/.env
DRIVERS_TOOLS="$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME="$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES="$MONGODB_BINARIES"
PROJECT_DIRECTORY="$PROJECT_DIRECTORY"
EOT

# Get the secrets
bash $DRIVERS_TOOLS/.evergreen/csfle/setup-secrets.sh