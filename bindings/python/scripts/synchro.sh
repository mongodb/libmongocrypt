#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname ${BASH_SOURCE:-$0})

python $SCRIPT_DIR/synchro.py "$@"
python -m ruff check $SCRIPT_DIR/../pymongocrypt/synchronous --fix --silent
