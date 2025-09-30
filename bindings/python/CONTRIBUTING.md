# Contributing to PyMongoCrypt

## Asyncio considerations
PyMongoCrypt adds asyncio capability by modifying the source files in */asynchronous to */synchronous using [unasync](https://github.com/python-trio/unasync/) and some custom transforms.

Where possible, edit the code in `*/asynchronous/*.py` and not the synchronous files. You can run `pre-commit run --all-files synchro` before running tests if you are testing synchronous code.

To prevent the synchro hook from accidentally overwriting code, it first checks to see whether a sync version of a file is changing and not its async counterpart, and will fail. In the unlikely scenario that you want to override this behavior, first export `OVERRIDE_SYNCHRO_CHECK=1`.

Sometimes, the synchro hook will fail and introduce changes many previously unmodified files. This is due to static Python errors, such as missing imports, incorrect syntax, or other fatal typos. To resolve these issues, run `pre-commit run --all-files --hook-stage manual ruff` and fix all reported errors before running the synchro hook again.

## Updating the libmongocrypt bindings

To update the libmongocrypt bindings in `pymongocrypt/binding.py`, run the following script:

```bash
python scripts/update_binding.py
```

## Update the bundled version of libmongocrypt

To update the bundled version of libmongocrypt, run the following script:

```bash
bash script/update-version.sh <new-version>
```

This will set the version in `scripts/libmongocrypt-version.sh` and update `sbom.json` to reflect
the new vendored version of `libmongocrypt`.

## Building wheels

To build wheels, run `scripts/release.sh`.  It will build the appropriate wheel for the current system
on Windows and MacOS.  If docker is available on Linux or MacOS, it will build the manylinux wheels.
