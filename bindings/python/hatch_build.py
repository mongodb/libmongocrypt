"""A custom hatch build hook for pymongo."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomHook(BuildHookInterface):
    """The pymongocrypt build hook."""

    def initialize(self, version, build_data):
        """Initialize the hook."""
        if self.target_name == "sdist":
            return

        # Ensure wheel is marked as binary.
        # On linux, we use auditwheel to set the name.
        if sys.platform == "darwin":
            os.environ["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
            build_data["tag"] = "py3-none-macosx_11_0_universal2"
            patt = ".dylib"
        elif os.name == "nt":
            build_data["tag"] = "py3-none-win_amd64"
            patt = ".dll"
        else:
            patt = ".so"

        here = Path(__file__).parent.resolve()
        dpath = here / "pymongocrypt"
        for fpath in dpath.glob(f"*{patt}"):
            relpath = os.path.relpath(fpath, here)
            build_data["artifacts"].append(relpath)
            build_data["force_include"][relpath] = relpath
