#!/bin/bash
# Downloads and prepares the C driver source, then compiles libmongocrypt's
# dependencies and targets.
#
# NOTE: This script is not meant to be invoked for Evergreen builds.  It is a
# convenience script for users of libmongocrypt

. "$(dirname "${BASH_SOURCE[0]}")/init.sh"

bash "$EVG_DIR/setup-env.sh"
bash "$EVG_DIR/build_all.sh"

