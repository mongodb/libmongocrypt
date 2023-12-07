#!/bin/bash -ex
cd /python

/opt/python/cp37-cp37m/bin/python -m build --wheel

# Audit wheels and write manylinux tag
for whl in dist/*none-any.whl; do
    # Skip already built manylinux wheels.
    if [[ "$whl" != *"manylinux"* ]]; then
        auditwheel repair $whl -w dist
        rm $whl
    fi
done
