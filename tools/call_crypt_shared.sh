#!/usr/bin/env bash
uv run "$(dirname "${BASH_SOURCE[0]}")/call_crypt_shared/call_crypt_shared.py" "$@"
