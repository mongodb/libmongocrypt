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

setup(
    cmdclass=cmdclass,
)
