#!/bin/bash
evergreen_root="$(pwd)"

[ -d "${MONGOCRYPT_INSTALL_PREFIX:=${evergreen_root}/install/libmongocrypt}" ] || mkdir -p "${MONGOCRYPT_INSTALL_PREFIX}"

if [ "$OS" == "Windows_NT" ]; then
	MONGOCRYPT_INSTALL_PREFIX=$(cygpath -w $MONGOCRYPT_INSTALL_PREFIX)
fi


