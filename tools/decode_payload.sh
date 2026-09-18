#!/usr/bin/env bash
uv run "$(dirname "${BASH_SOURCE[0]}")/decode_payload/decode_payload.py" "$@"
