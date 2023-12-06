#!/bin/bash -ex
cd /python

# Compile wheel
# https://github.com/pypa/manylinux/issues/49
rm -rf build
/opt/python/cp37-cp37m/bin/python setup.py bdist_wheel

# Audit wheels and write manylinux tag
for whl in dist/*.whl; do
    # Skip already built manylinux wheels.
    if [[ "$whl" != *"manylinux"* ]]; then
        auditwheel repair $whl -w dist
        rm $whl
    fi
done
