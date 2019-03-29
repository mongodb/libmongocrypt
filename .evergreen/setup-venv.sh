#!/bin/bash
# Enters a virtual environment or creates one named 'venv'.
#

echo $VIRTUAL_ENV
if [ "$VIRTUAL_ENV" != "$(pwd)/venv" ]; then
    echo "VIRTUAL_ENV=${VIRTUAL_ENV}, updating to use 'venv'"

    if [ -d venv ]; then
        echo "venv found: activating"
        if [ "Windows_NT" == "$OS" ]; then
            . ./venv/Scripts/activate
        else
            . ./venv/bin/activate
        fi
    else
        echo "venv not found: creating, installing, and activating"
        python -m virtualenv venv
        if [ "Windows_NT" == "$OS" ]; then
            . ./venv/Scripts/activate
        else
            . ./venv/bin/activate
        fi

        pip install -r libmongocrypt/.evergreen/requirements.txt
    fi
else
    echo "Already in virtual env, nothing to do."
fi