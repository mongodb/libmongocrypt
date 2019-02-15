#!/bin/sh

if [ -f venv ]; then
    exit 0
fi

python -m virtualenv venv
cd venv
. bin/activate
./bin/pip install GitPython