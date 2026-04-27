#!/usr/bin/env bash

export_uv_tool_dirs() {
  : "${UV_TOOL_DIR:="$(mktemp -d)"}" || return
  : "${UV_TOOL_BIN_DIR:="$(mktemp -d)"}" || return

  PATH="${UV_TOOL_BIN_DIR:?}:${PATH:-}"

  # Windows requires "C:\path\to\dir" instead of "/cygdrive/c/path/to/dir" (PATH is automatically converted).
  if [[ "${OSTYPE:?}" == cygwin ]]; then
    UV_TOOL_DIR="$(cygpath -aw "${UV_TOOL_DIR:?}")" || return
    UV_TOOL_BIN_DIR="$(cygpath -aw "${UV_TOOL_BIN_DIR:?}")" || return
  fi

  UV_PYTHON_INSTALL_DIR="${UV_TOOL_DIR:?}"

  export PATH UV_TOOL_DIR UV_TOOL_BIN_DIR UV_PYTHON_INSTALL_DIR
}

install_build_tools() {
  export_uv_tool_dirs || return

  if ! command -v uv &>/dev/null; then
    echo "missing system-provided uv binary: fallback to uv-installer.sh" >&2
    : "${EVG_DIR:="$(dirname "${BASH_SOURCE[0]}")"}" || return
    . "${EVG_DIR:?}/init.sh" || return

    version="$(perl -lne 'm|APP_VERSION=\"(.*)\"| && print $1' "${EVG_DIR:?}/uv-installer.sh")" || return
    uv_install_dir="${USER_CACHES_DIR:?}/uv-$version"

    script="$(mktemp)" || return
    cp -f "${EVG_DIR:?}/uv-installer.sh" "${script:?}" || return
    chmod +x "${script:?}" || return
    env \
        UV_INSTALL_DIR="${uv_install_dir:?}" \
        UV_UNMANAGED_INSTALL=1 \
        INSTALLER_PRINT_VERBOSE=1 \
        "${script:?}" || return

    PATH="${uv_install_dir:?}:$PATH" || return
    uv --version || return
  fi

  # PyPI `cmake` requires a sufficiently recent Python version.
  uv python install --no-bin -q || uv python install -q || return

  uv tool install -q cmake || return

  if [[ -f /etc/redhat-release && -x /opt/mongodbtoolchain/v4/bin/ninja ]]; then
    # Avoid strange "Could NOT find Threads" CMake configuration error on RHEL when using PyPI CMake, PyPI Ninja, and
    # C++20 or newer by using MongoDB Toolchain's Ninja binary instead.
    ln -sf /opt/mongodbtoolchain/v4/bin/ninja "${UV_TOOL_BIN_DIR:?}/ninja" || return
  else
    uv tool install -q ninja || return
  fi

  uvx python --version || return
  cmake --version | head -n 1 || return
  echo "ninja version: $(ninja --version)" || return

  export CMAKE_GENERATOR="${CMAKE_GENERATOR:="Ninja"}"
}
