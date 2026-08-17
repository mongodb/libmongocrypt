#!/usr/bin/bash

set -eux

DRIVERS_TOOLS="$(pwd)/drivers-tools"
PROJECT_DIRECTORY="${project_directory}"
PYMONGO_DIR="$(pwd)/mongo-python-driver"

# Python has cygwin path problems on Windows.
if [ "Windows_NT" = "${OS:-}" ]; then
    DRIVERS_TOOLS=$(cygpath -m $DRIVERS_TOOLS)
    PROJECT_DIRECTORY=$(cygpath -m $PROJECT_DIRECTORY)
fi
export PROJECT_DIRECTORY
export DRIVERS_TOOLS

export MONGO_ORCHESTRATION_HOME="$DRIVERS_TOOLS/.evergreen/orchestration"
export MONGODB_BINARIES="$DRIVERS_TOOLS/mongodb/bin"
export MONGOCRYPT_DIR=${PROJECT_DIRECTORY}/all/${variant_name}

cat <<EOT > expansion.yml
DRIVERS_TOOLS: "$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME: "$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES: "$MONGODB_BINARIES"
PROJECT_DIRECTORY: "$PROJECT_DIRECTORY"
PYMONGO_DIR: "$PYMONGO_DIR"
MONGOCRYPT_DIR: "$MONGOCRYPT_DIR"
EOT

# Set up drivers-tools with a .env file.
git clone https://github.com/mongodb-labs/drivers-evergreen-tools.git ${DRIVERS_TOOLS}

# PYTHON-6005: drivers-tools' ensure_uv takes the first python3 on PATH, and
# RHEL 8.2's is 3.6, which uv publishes no distribution for, so every step that
# runs a drivers-tools script fails before it starts. Put the newest toolchain
# python3 in front where the platform one is too old. Only .env is a durable
# place to do it: handle-paths.sh sources it, so it reaches the later steps that
# invoke drivers-tools directly.
#
# Remove once mongodb-labs/drivers-evergreen-tools#829 has merged, which hands
# the choice to find_python3 and prefers the toolchain on its own.
PYTHON_SHIM=""
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    TOOLCHAIN_PYTHON=$(ls -d /opt/mongodbtoolchain/v*/bin/python3 2>/dev/null | sort -V | tail -n1)
    if [ -n "${TOOLCHAIN_PYTHON}" ]; then
        PYTHON_SHIM="${DRIVERS_TOOLS}/.python-shim"
        mkdir -p "${PYTHON_SHIM}"
        ln -sf "${TOOLCHAIN_PYTHON}" "${PYTHON_SHIM}/python3"
    fi
fi

cat <<EOT > ${DRIVERS_TOOLS}/.env
DRIVERS_TOOLS="$DRIVERS_TOOLS"
MONGO_ORCHESTRATION_HOME="$MONGO_ORCHESTRATION_HOME"
MONGODB_BINARIES="$MONGODB_BINARIES"
PROJECT_DIRECTORY="$PROJECT_DIRECTORY"
EOT
if [ -n "${PYTHON_SHIM}" ]; then
    echo "PATH=\"${PYTHON_SHIM}:\$PATH\"" >> ${DRIVERS_TOOLS}/.env
fi

# Get the secrets
# Opt in to corporate Azure credentials (DRIVERS-3392)
export FLE_AZURE_USE_CORPORATE=YES
bash $DRIVERS_TOOLS/.evergreen/csfle/setup-secrets.sh
# Start the csfle servers
bash $DRIVERS_TOOLS/.evergreen/csfle/start-servers.sh

# Clone mongo-python-driver
git clone https://github.com/mongodb/mongo-python-driver.git ${PYMONGO_DIR}
