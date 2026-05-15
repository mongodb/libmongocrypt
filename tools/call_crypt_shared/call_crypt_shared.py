#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "pymongo",
#   "cffi",
#   "pyyaml",
# ]
# ///

import argparse
import bson
from bson import binary, json_util
import os
import re
import sys
import yaml
import json
import cffi
from pathlib import Path


ffi = cffi.FFI()


def _preprocess_header(header_path: str) -> str:
    lines = []
    ifcount = 0
    with open(header_path, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if line in (
                "#ifndef MONGO_CRYPT_SUPPORT_H",
                "#endif  // MONGO_CRYPT_SUPPORT_H",
            ):
                continue
            if re.match(r"^#if", line):
                ifcount += 1
                continue
            if re.match(r"^#end", line):
                ifcount -= 1
                continue
            if ifcount > 0:
                continue
            if re.match(r"^#", line):
                continue
            line = re.sub(r"MONGO_CRYPT_API ", "", line)
            line = re.sub(r"MONGO_API_CALL( ?)", "", line)
            lines.append(line)
    return "\n".join(lines)


# lib is the returned object from ffi.dlopen.
_lib = None


class _mongo_crypt_v1_status_Wrapper:
    def __init__(self):
        self._cdata = _lib.mongo_crypt_v1_status_create()

    def __enter__(self):
        return self

    def cdata(self) -> cffi.FFI.CData:
        return self._cdata

    def get_explanation(self):
        got = _lib.mongo_crypt_v1_status_get_explanation(self._cdata)
        return ffi.string(got)

    def __exit__(self, exc_type, exc_val, exc_tb):
        _lib.mongo_crypt_v1_status_destroy(self._cdata)


class _mongo_crypt_v1_lib_Wrapper:
    def __init__(self):
        with _mongo_crypt_v1_status_Wrapper() as status:
            self._cdata = _lib.mongo_crypt_v1_lib_create(status.cdata())
            if not self._cdata:
                raise Exception(
                    "error in mongo_crypt_v1_lib_create: {}".format(
                        status.get_explanation()
                    )
                )

    def __enter__(self):
        return self

    def cdata(self) -> cffi.FFI.CData:
        return self._cdata

    def __exit__(self, exc_type, exc_val, exc_tb):
        with _mongo_crypt_v1_status_Wrapper() as status:
            got = _lib.mongo_crypt_v1_lib_destroy(self._cdata, status.cdata())
            if got != _lib.MONGO_CRYPT_V1_SUCCESS:
                raise Exception(
                    "error in mongo_crypt_v1_lib_destroy: ({}): {}".format(
                        got, status.get_explanation()
                    )
                )


class _mongo_crypt_v1_bson_Wrapper:
    def __init__(self, cdata: cffi.FFI.CData):
        self._cdata = cdata

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _lib.mongo_crypt_v1_bson_free(self._cdata)


class _mongo_crypt_v1_query_analyzer_Wrapper:
    def __init__(self, crypt: _mongo_crypt_v1_lib_Wrapper):
        with _mongo_crypt_v1_status_Wrapper() as status:
            self._cdata = _lib.mongo_crypt_v1_query_analyzer_create(
                crypt.cdata(), status.cdata()
            )
            if self._cdata == ffi.NULL:
                raise Exception(
                    "error in mongo_crypt_v1_query_analyzer_create: {}".format(
                        status.get_explanation()
                    )
                )

    def __enter__(self):
        return self

    def analyze_query(self, cmd_bytes: bytes, ns: str):
        with _mongo_crypt_v1_status_Wrapper() as status:
            documentBSON = ffi.new("uint8_t[]", cmd_bytes)
            ns_bytes = ns.encode("utf8")
            ns_cdata = ffi.new("char[]", ns_bytes)
            ns_len = ffi.cast("uint32_t", len(ns_bytes))
            bson_len_ptr = ffi.new("uint32_t*")
            got = _lib.mongo_crypt_v1_analyze_query(
                self._cdata,
                documentBSON,
                ns_cdata,
                ns_len,
                bson_len_ptr,
                status.cdata(),
            )
            if got == ffi.NULL:
                raise Exception(
                    "error in mongo_crypt_v1_analyze_query: {}".format(
                        status.get_explanation()
                    )
                )
            with _mongo_crypt_v1_bson_Wrapper(got):
                got_bson = bson.decode(ffi.buffer(got, bson_len_ptr[0]))
                return got_bson

    def __exit__(self, exc_type, exc_val, exc_tb):
        _lib.mongo_crypt_v1_query_analyzer_destroy(self._cdata)


class _lib_Wrapper:
    def __init__(self, lib: str):
        global _lib
        _lib = ffi.dlopen(lib)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ffi.dlclose(_lib)


_parsed_header = False


def _parse_header():
    global _parsed_header
    if _parsed_header:
        return
    header_path = Path(__file__).resolve().parent / "mongo_crypt.h"
    ffi.cdef(_preprocess_header(header_path))
    _parsed_header = True


_json_options = json_util.JSONOptions(
    json_mode=json_util.JSONMode.CANONICAL,
    uuid_representation=binary.UuidRepresentation.STANDARD,
)


def analyze_query(lib: str, cmd_bytes: bytes, ns: str):
    global _json_options
    _parse_header()
    with _lib_Wrapper(lib):
        with _mongo_crypt_v1_lib_Wrapper() as crypt:
            with _mongo_crypt_v1_query_analyzer_Wrapper(crypt) as qa:
                got = qa.analyze_query(cmd_bytes, ns)
                return json_util.dumps(got, json_options=_json_options, indent=4)


def get_version(lib: str):
    _parse_header()
    with _lib_Wrapper(lib):
        version_cdata = _lib.mongo_crypt_v1_get_version_str()
        version = ffi.string(version_cdata)
        return version.decode("utf8")


def main():
    global _json_options

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version", action="store_true", help="Print version of crypt shared library"
    )
    parser.add_argument(
        "--lib",
        help="Path to the crypt shared library. May be passed as the environment variable CRYPT_SHARED_LIB_PATH.",
    )
    parser.add_argument(
        "--cmd",
        help="Path to a file containing the command to analyze. The format must be extended canonical JSON. If not present, input is read from stdin.",
    )
    parser.add_argument(
        "--ns",
        help="The namespace of the command. Defaults to test.test",
        default="test.test",
    )
    args = parser.parse_args()

    lib = os.getenv("CRYPT_SHARED_LIB_PATH", args.lib)
    if not lib:
        print(
            "Error: --lib argument or CRYPT_SHARED_LIB_PATH environment variable must be provided.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.version:
        print(get_version(lib))
        return

    # Read and transform input: YML => JSON => BSON
    if args.cmd:
        with open(args.cmd, "r") as infile:
            as_yaml = yaml.safe_load(infile)
            cmd_json = json.dumps(as_yaml)
    else:
        as_yaml = yaml.safe_load(sys.stdin)
        cmd_json = json.dumps(as_yaml)
    cmd_dict = json_util.loads(cmd_json, json_options=_json_options)
    codec_options = bson.CodecOptions(
        uuid_representation=binary.UuidRepresentation.STANDARD
    )
    cmd_bson = bson.encode(cmd_dict, codec_options=codec_options)
    print(analyze_query(lib, cmd_bson, args.ns))


if __name__ == "__main__":
    main()
