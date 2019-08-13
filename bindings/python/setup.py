import os

from setuptools import setup, find_packages


with open('README.rst', 'rb') as f:
    LONG_DESCRIPTION = f.read().decode('utf8')

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
    packages=find_packages(exclude=['test']),
    package_data={'pymongocrypt': ['*.dll', '*.so', '*.dylib']},
    zip_safe=False,
    install_requires=["cffi>=1.12.0,<2", "cryptography>=2.0,<3"],
    author="Shane Harvey",
    author_email="mongodb-user@googlegroups.com",
    url="github.com/mongodb/libmongocrypt",
    keywords=["mongo", "mongodb", "pymongocrypt", "pymongo", "mongocrypt",
              "bson"],
    test_suite="test",
    tests_require=["pymongo"],
)
