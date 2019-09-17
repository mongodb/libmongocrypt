#!/bin/bash
evergreen_root="$(pwd)"

[ -d "${BSON_INSTALL_PREFIX:=${evergreen_root}/install/mongo-c-driver}" ] || mkdir -p "${BSON_INSTALL_PREFIX}"
[ -d "${MONGOCRYPT_INSTALL_PREFIX:=${evergreen_root}/install/libmongocrypt}" ] || mkdir -p "${MONGOCRYPT_INSTALL_PREFIX}"

if [ "$OS" == "Windows_NT" ]; then
	BSON_INSTALL_PREFIX=$(cygpath -w $BSON_INSTALL_PREFIX)
	MONGOCRYPT_INSTALL_PREFIX=$(cygpath -w $MONGOCRYPT_INSTALL_PREFIX)
fi


