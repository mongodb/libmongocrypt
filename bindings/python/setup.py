import os
import sys

from setuptools import setup, find_packages

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
                # Our python source is py2/3 compatible.
                python, abi = 'py2.py3', 'none'
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

# Print a warning if the embedded libmongocrypt binary is not found.
linux = False
_base = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'pymongocrypt')
if sys.platform == 'win32':
    _path = os.path.join(_base, 'mongocrypt.dll')
elif sys.platform == 'darwin':
    _path = os.path.join(_base, 'libmongocrypt.dylib')
else:
    _path = os.path.join(_base, 'libmongocrypt.so')
    linux = True

_PYMONGOCRYPT_LIB = os.environ.get('PYMONGOCRYPT_LIB')

message = """
*****************************************************\n
The embedded libmongocrypt binary is not present (%r)\n%s
You may need to install libmongocrypt manually and set
the PYMONGOCRYPT_LIB environment variable.\n
*****************************************************\n
"""

if linux:
    pip_message = ('Please upgrade to pip>=19 to support manylinux2010 wheels'
                   'and try again.')
else:
    pip_message = ''

if not os.path.isfile(_path) and not (
        _PYMONGOCRYPT_LIB and os.path.isfile(_PYMONGOCRYPT_LIB)):
    sys.stdout.write(message % (_path, pip_message))

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
    url="https://github.com/mongodb/libmongocrypt/tree/master/bindings/python",
    keywords=["mongo", "mongodb", "pymongocrypt", "pymongo", "mongocrypt",
              "bson"],
    test_suite="test",
    tests_require=["pymongo"],
    license="Apache License, Version 2.0",
    python_requires=">=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Database"],
    cmdclass=cmdclass,
)
