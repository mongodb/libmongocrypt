import os

from setuptools import setup, find_packages


with open('README.rst') as f:
    LONG_DESCRIPTION = f.read()

# Single source the version.
version_file = os.path.realpath(os.path.join(
    os.path.dirname(__file__), 'pymongocrypt', 'version.py'))
version = {}
with open(version_file) as fp:
    exec(fp.read(), version)

setup(
    name="pymongocrypt",
    version=version['__version__'],
    description="Python bindings for libmongocrypt",
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=["cffi>=1.12.0,<2"],
    author="Shane Harvey",
    author_email="mongodb-user@googlegroups.com",
    url="github.com/mongodb/libmongocrypt",
    keywords=["mongo", "mongodb", "pymongocrypt", "pymongo", "mongocrypt",
              "bson"],
    test_suite="test",
    tests_require=["pymongo"],
)
