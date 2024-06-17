#! /bin/bash
set -o xtrace   # Write all commands first to stderr
set -o errexit  # Exit the script with error if any of the commands fail

bash ${DRIVERS_TOOLS}/.evergreen/csfle/teardown.sh
bash ${DRIVERS_TOOLS}/.evergreen/teardown.sh
