#!/usr/bin/env bash

. "$(dirname "${BASH_SOURCE[0]}")/setup-env.sh"

set -euo pipefail

: "${EARTHLY_VERSION:=0.8.16}"

# Calc the arch of the executable we want
arch="$(uname -m)"
case "$arch" in
    x86_64)
        arch=amd64
        ;;
    aarch64|arm64)
        arch=arm64
        ;;
    *)
        echo "Unknown architecture: $arch" 1>&1
        exit 99
        ;;
esac

# The location where the Earthly executable will live
cache_dir="$USER_CACHES_DIR/earthly-sh/$EARTHLY_VERSION"
mkdir -p "$cache_dir"

exe_filename="earthly-$OS_NAME-$arch$EXE_SUFFIX"
if [[ "$OS_NAME" == "macos" ]]; then
    # Earthly downloads use `darwin`.
    exe_filename="earthly-darwin-$arch$EXE_SUFFIX"
fi
exe_path="$cache_dir/$exe_filename"

if test -f "$exe_path" && ! "$exe_path" --version; then
    echo "Failed to execute Earthly executable, removing and re-downloading"
    rm "$exe_path"
fi

# Download if it isn't already present
if ! test -f "$exe_path"; then
    echo "Downloading $exe_filename $EARTHLY_VERSION"
    url="https://github.com/earthly/earthly/releases/download/v$EARTHLY_VERSION/$exe_filename"
    curl --retry 5 -LsS --max-time 120 --fail "$url" --output "$exe_path"
fi

chmod a+x "$exe_path"

# Some targets (`+sign`, `+silkbomb`, and the SBOM targets built on it) pull images from the
# DevProd Platforms ECR registry. In CI, the "earthly" Evergreen function authenticates to ECR
# before invoking this script (see .evergreen/config.yml) and sets CI=true to signal that here.
# Outside of CI, authenticate with a local AWS SSO profile so release engineers can run these
# targets directly.
if [[ -z "${CI:-}" ]]; then
    needs_ecr_auth=
    for arg in "$@"; do
        case "$arg" in
            +sign | +silkbomb | +sbom-generate | +sbom-generate-new-serial-number | +sbom-validate)
                needs_ecr_auth=1
                ;;
        esac
    done
    if [[ -n "$needs_ecr_auth" ]]; then
        command -v aws >/dev/null || {
            echo "missing required program aws" 1>&2
            exit 1
        }
        : "${DEVPROD_PLATFORMS_ECR_PROFILE:=ECRScopedAccess-901841024863}"
        aws ecr get-login-password --region us-east-1 --profile "$DEVPROD_PLATFORMS_ECR_PROFILE" \
            | docker login --username AWS --password-stdin 901841024863.dkr.ecr.us-east-1.amazonaws.com
    fi
fi

"$exe_path" "$@"
