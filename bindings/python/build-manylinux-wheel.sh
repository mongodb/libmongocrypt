#!/bin/bash -ex
cd /python

# Compile wheel
# https://github.com/pypa/manylinux/issues/49
rm -rf build
/opt/python/cp37-cp37m/bin/python setup.py bdist_wheel --universal

# Audit wheels and write manylinux2010 tag
for whl in dist/*.whl; do
    # Skip already built manylinux2010 wheels.
    if [[ "$whl" != *"manylinux2"* ]]; then
        auditwheel repair $whl -w dist
        rm $whl
    fi
done
