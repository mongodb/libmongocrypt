#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "pymongo",
#   "cffi",
#   "pyyaml",
# ]
# ///
import json
import os
import unittest
import yaml
from pathlib import Path

import bson
from bson import binary, json_util
import call_crypt_shared

if os.environ.get("CRYPT_SHARED_LIB") is None:
    raise RuntimeError(
        "CRYPT_SHARED_LIB environment variable must be set to the path of the crypt_shared library"
    )


class TestCallCryptShared(unittest.TestCase):
    def test_get_version(self):
        lib = os.environ["CRYPT_SHARED_LIB"]
        got = call_crypt_shared.get_version(lib)
        self.assertTrue(got.startswith("mongo_crypt_v1"), got)

    def test_analyze_query(self):
        if "REGENERATE_GOLDEN_FILES" in os.environ:
            print("Regenerating golden files")
        for test_path in Path("tests").glob("*.yml"):
            file_name = test_path.stem

            # Read and transform test file: YML => JSON => BSON
            as_yaml = yaml.safe_load(test_path.open("r"))
            cmd_json = json.dumps(as_yaml)
            json_options = json_util.JSONOptions(
                json_mode=json_util.JSONMode.CANONICAL,
                uuid_representation=binary.UuidRepresentation.STANDARD,
            )
            cmd_dict = json_util.loads(cmd_json, json_options=json_options)
            codec_options = bson.CodecOptions(
                uuid_representation=binary.UuidRepresentation.STANDARD
            )
            cmd_bson = bson.encode(cmd_dict, codec_options=codec_options)

            lib = os.environ["CRYPT_SHARED_LIB"]
            got_bson = call_crypt_shared.analyze_query(lib, cmd_bson, "test.test")
            got_dict = json_util.loads(json.dumps(yaml.safe_load(got_bson)))
            got_json = bson.json_util.dumps(got_dict, indent=2)
            if "REGENERATE_GOLDEN_FILES" in os.environ:
                Path(f"tests/{file_name}.golden.json").write_text(got_json)
            else:
                expect = Path(f"tests/{file_name}.golden.json").read_text()
                self.maxDiff = None  # To print big string
                self.assertEqual(got_json, expect, msg=f"Failed to match: {file_name}")


if __name__ == "__main__":
    unittest.main()
