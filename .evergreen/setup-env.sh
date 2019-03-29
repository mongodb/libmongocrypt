#!/bin/bash
evergreen_root="$(pwd)"

INSTALL_PREFIX=${evergreen_root}/install

mkdir -p "${evergreen_root}/install"

if [ "$OS" == "Windows_NT" ]; then
	INSTALL_PREFIX=$(cygpath -w $INSTALL_PREFIX)
fi


