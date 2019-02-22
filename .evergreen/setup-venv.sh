#!/bin/sh
# Enters a virtual environment or creates one named 'venv'.
#

echo $VIRTUAL_ENV
if [ "$VIRTUAL_ENV" != "$(pwd)/venv" ]; then
    echo "VIRTUAL_ENV=${VIRTUAL_ENV}, updating to use 'venv'"
    if [ -d venv ]; then
        echo "venv found: activating"
        . ./venv/bin/activate
    else
        echo "venv not found: creating, installing, and activating"
        python -m virtualenv venv
        . ./venv/bin/activate
        ./venv/bin/pip install -r libmongocrypt/.evergreen/requirements.txt
    fi
else
    echo "Already in virtual env, nothing to do."
fi