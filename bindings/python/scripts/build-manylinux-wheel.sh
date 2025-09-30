#!/bin/bash -ex
cd /python

mkdir /tmp/wheelhouse
/opt/python/cp38-cp38/bin/python -m build --wheel --outdir /tmp/wheelhouse
# Audit wheels and repair manylinux tags
auditwheel repair /tmp/wheelhouse/*.whl -w dist
