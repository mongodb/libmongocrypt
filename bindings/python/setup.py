import os
import sys

from setuptools import setup, find_packages

if sys.version_info[:3] < (3, 7):
    raise RuntimeError("pymongocrypt requires Python version >= 3.7")

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
    # Note cryptography is uncapped because it does not follow semver.
    install_requires=[
        "cffi>=1.12.0,<2",
        "cryptography>=2.5",
        # cryptography 40 dropped support for PyPy <7.3.10.
        "cryptography<40;platform_python_implementation=='PyPy' and implementation_version<'7.3.10'",
        "requests<3.0.0",
        "packaging>=21.0"
    ],
    author="Shane Harvey",
    author_email="mongodb-user@googlegroups.com",
    url="https://github.com/mongodb/libmongocrypt/tree/master/bindings/python",
    keywords=["mongo", "mongodb", "pymongocrypt", "pymongo", "mongocrypt",
              "bson"],
    test_suite="test",
    license="Apache License, Version 2.0",
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Database"],
)
