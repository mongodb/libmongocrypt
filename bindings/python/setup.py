import sys
from setuptools import setup 

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


def parse_reqs_file(fname):
    with open(fname) as fid:  # noqa:PTH123
        lines = [li.strip() for li in fid.readlines()]
    return [li for li in lines if li and not li.startswith("#")]


extras_require = dict(  # noqa:C408
    test=parse_reqs_file("test-requirements.txt")
)

setup(cmdclass=cmdclass, install_requires=parse_reqs_file("requirements.txt"),
      extras_require=extras_require)
