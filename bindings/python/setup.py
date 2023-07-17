import os
import sys

from setuptools import setup, find_packages

if sys.version_info[:3] < (3, 7):
    raise RuntimeError("pymongocrypt requires Python version >= 3.7")

# Make our Windows and macOS wheels platform specific because we embed
# libmongocrypt. On Linux we ship manylinux2010 wheels which cannot do this or
# else auditwheel raises the following error:
# RuntimeError: Invalid binary wheel, found the following shared
# library/libraries in purelib folder:
# 	libmongocrypt.so
# The wheel has to be platlib compliant in order to be repaired by auditwheel.
cmdclass = {}
if sys.platform in ('win32', 'darwin'):
    try:
        from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
        class bdist_wheel(_bdist_wheel):

            def finalize_options(self):
                _bdist_wheel.finalize_options(self)
                self.root_is_pure = False

            def get_tag(self):
                python, abi, plat = _bdist_wheel.get_tag(self)
                # Our python source is py3 compatible.
                python, abi = 'py3', 'none'
                return python, abi, plat

        cmdclass['bdist_wheel'] = bdist_wheel
    except ImportError:
        # Version of wheel is too old, use None to fail a bdist_wheel attempt.
        cmdclass['bdist_wheel'] = None

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
    cmdclass=cmdclass,
)
