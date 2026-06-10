#!/usr/bin/env python3
"""
Generate seed corpus files for the fuzz_mongocrypt fuzzer.

Each corpus file has the format:
  [1 byte: op selector] [BSON payload for the init call] [optional extra bytes]

The optional extra bytes are consumed by drive_ctx() as it walks the state
machine.  For NEED_MONGO_* states it reads a 2-byte LE length then that many
bytes; for NEED_KMS it reads exactly bytes_needed bytes from the KMS context.

Op selectors (must match the enum in fuzz_mongocrypt.c):
  0  OP_ENCRYPT
  1  OP_DECRYPT
  2  OP_EXPLICIT_ENCRYPT
  3  OP_EXPLICIT_DECRYPT
  4  OP_DATAKEY            (input_bin ignored; extra bytes unused unless
  5  OP_REWRAP_MANY_DATAKEY  state machine needs feeding)
  6  OP_EXPLICIT_ENCRYPT_EXPRESSION
  7  OP_DATAKEY_AWS        (extra bytes fed to KMS HTTP response parser)
  8  OP_DATAKEY_KMIP       (extra bytes fed to KMIP/TTLV response parser)

Usage:
  python3 test/gen_fuzz_corpus.py [output_dir]

  output_dir defaults to test/data/fuzz_mongocrypt_corpus relative to the
  script's own location.
"""

import os
import struct
import sys

# ---------------------------------------------------------------------------
# Minimal BSON encoder (no external dependencies)
# ---------------------------------------------------------------------------

def _bson_elem_string(key: str, value: str) -> bytes:
    k = key.encode() + b"\x00"
    v = value.encode() + b"\x00"
    return b"\x02" + k + struct.pack("<I", len(v)) + v


def _bson_elem_int32(key: str, value: int) -> bytes:
    return b"\x10" + key.encode() + b"\x00" + struct.pack("<i", value)


def _bson_elem_binary(key: str, data: bytes, subtype: int = 0x04) -> bytes:
    k = key.encode() + b"\x00"
    return b"\x05" + k + struct.pack("<I", len(data)) + bytes([subtype]) + data


def bson(*elements: bytes) -> bytes:
    """Wrap element bytes into a BSON document."""
    body = b"".join(elements) + b"\x00"
    return struct.pack("<I", 4 + len(body)) + body


EMPTY_BSON = bson()  # {5, 0, 0, 0, 0}

# ---------------------------------------------------------------------------
# Helper to build "extra" bytes that drive_ctx() can consume
# ---------------------------------------------------------------------------

def mongo_response_bytes(doc: bytes = EMPTY_BSON, count: int = 3) -> bytes:
    """
    Bytes that satisfy NEED_MONGO_* state transitions.
    drive_ctx reads: [2-byte LE len][len bytes], then calls mongo_done.
    Repeat `count` times to cover COLLINFO → MARKINGS → KEYS.
    """
    chunk = struct.pack("<H", len(doc)) + doc
    return chunk * count


# ---------------------------------------------------------------------------
# Corpus entries
# ---------------------------------------------------------------------------

def build_entries() -> dict[str, bytes]:
    entries: dict[str, bytes] = {}

    # -- OP_ENCRYPT (0) ------------------------------------------------------
    # mongocrypt_ctx_encrypt_init expects a command BSON doc.
    for cmd, coll in [("find", "test"), ("aggregate", "test"), ("insert", "test")]:
        name = f"op0_encrypt_{cmd}"
        payload = bson(_bson_elem_string(cmd, coll))
        entries[name] = bytes([0]) + payload
        # With extra bytes to drive state machine transitions.
        entries[name + "_extra"] = bytes([0]) + payload + mongo_response_bytes()

    # -- OP_DECRYPT (1) ------------------------------------------------------
    # mongocrypt_ctx_decrypt_init expects a BSON document.
    doc_payload = bson(_bson_elem_string("field", "value"))
    entries["op1_decrypt_doc"] = bytes([1]) + doc_payload
    entries["op1_decrypt_empty"] = bytes([1]) + EMPTY_BSON
    entries["op1_decrypt_doc_extra"] = bytes([1]) + doc_payload + mongo_response_bytes()

    # -- OP_EXPLICIT_ENCRYPT (2) ---------------------------------------------
    # mongocrypt_ctx_explicit_encrypt_init expects {"v": <value>}.
    str_payload = bson(_bson_elem_string("v", "hello"))
    int_payload = bson(_bson_elem_int32("v", 42))
    entries["op2_explicit_encrypt_str"] = bytes([2]) + str_payload
    entries["op2_explicit_encrypt_int"] = bytes([2]) + int_payload
    entries["op2_explicit_encrypt_extra"] = bytes([2]) + str_payload + mongo_response_bytes()

    # -- OP_EXPLICIT_DECRYPT (3) ---------------------------------------------
    # mongocrypt_ctx_explicit_decrypt_init expects {"v": <ciphertext>}.
    payload = bson(_bson_elem_string("v", "data"))
    entries["op3_explicit_decrypt"] = bytes([3]) + payload
    entries["op3_explicit_decrypt_extra"] = bytes([3]) + payload + mongo_response_bytes()

    # -- OP_DATAKEY (4) ------------------------------------------------------
    # input_bin is not used by the init path; empty BSON is a safe placeholder.
    entries["op4_datakey"] = bytes([4]) + EMPTY_BSON
    entries["op4_datakey_extra"] = bytes([4]) + EMPTY_BSON + mongo_response_bytes()

    # -- OP_REWRAP_MANY_DATAKEY (5) ------------------------------------------
    # mongocrypt_ctx_rewrap_many_datakey_init expects a BSON filter doc.
    filter_payload = bson(_bson_elem_string("provider", "local"))
    entries["op5_rewrap_empty_filter"] = bytes([5]) + EMPTY_BSON   # rewrap all keys
    entries["op5_rewrap_filter"] = bytes([5]) + filter_payload
    entries["op5_rewrap_filter_extra"] = bytes([5]) + filter_payload + mongo_response_bytes()

    # -- OP_EXPLICIT_ENCRYPT_EXPRESSION (6) ----------------------------------
    # mongocrypt_ctx_explicit_encrypt_expression_init expects {"v": <expr>}.
    payload = bson(_bson_elem_string("v", "expr"))
    entries["op6_encrypt_expr"] = bytes([6]) + payload
    entries["op6_encrypt_expr_extra"] = bytes([6]) + payload + mongo_response_bytes()

    # -- OP_DATAKEY_AWS (7) --------------------------------------------------
    # input_bin is not used; drive_ctx feeds extra bytes to the KMS HTTP parser.
    entries["op7_datakey_aws"] = bytes([7]) + EMPTY_BSON
    # A minimal well-formed HTTP 200 response exercises the happy path of the parser.
    http_ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: 2\r\n\r\n{}"
    entries["op7_datakey_aws_http_ok"] = bytes([7]) + EMPTY_BSON + http_ok
    # A truncated / malformed response exercises error handling.
    entries["op7_datakey_aws_http_trunc"] = bytes([7]) + EMPTY_BSON + b"HTTP/1.1 200"

    # -- OP_DATAKEY_KMIP (8) -------------------------------------------------
    # input_bin is not used; drive_ctx feeds extra bytes to the KMIP/TTLV parser.
    entries["op8_datakey_kmip"] = bytes([8]) + EMPTY_BSON
    # Minimal KMIP/TTLV frame: tag=0x42007B (Response Message), type=0x01 (Structure), length=0.
    ttlv_frame = bytes([0x42, 0x00, 0x7B, 0x01, 0x00, 0x00, 0x00, 0x00])
    entries["op8_datakey_kmip_ttlv"] = bytes([8]) + EMPTY_BSON + ttlv_frame

    # -- Crash PoCs from security audit --------------------------------------
    #
    # KMIP TTLV parser integer overflow (crash-kmip-parser-overflow):
    #   TTLV header with tag=0x420018, type=0x01 (Structure), length=0xFFFFFFFF.
    #   The parser attempts to allocate/read 4 GiB, overflowing an integer used
    #   to track remaining bytes.
    entries["crash-kmip-parser-overflow"] = bytes([
        0x08,                          # OP_DATAKEY_KMIP
        0x42, 0x00, 0x18,              # TTLV tag
        0x01,                          # TTLV type: Structure
        0xFF, 0xFF, 0xFF, 0xFF,        # TTLV length: 0xFFFFFFFF
    ])

    # KMS HTTP chunked-transfer parser overflow (crash-kms-chunked-overflow*):
    #   Chunked response whose chunk-size field is 0x7FFFFFFF.  The parser uses
    #   a signed 32-bit (or similarly bounded) accumulator, so this value wraps
    #   or overflows before any data bytes are read.
    #   The -bof variant appends one data byte ('X') after the chunk-size line,
    #   pushing the parser into the body-copy path where the overflow manifests
    #   as an out-of-bounds write.
    _chunked_http = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"7fffffff\r\n"
    )
    entries["crash-kms-chunked-overflow"] = bytes([0x07]) + _chunked_http
    entries["crash-kms-chunked-overflow-bof"] = bytes([0x07]) + _chunked_http + b"X"

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.join(script_dir, "data", "fuzz_mongocrypt_corpus")
    out_dir = sys.argv[1] if len(sys.argv) > 1 else default_out

    os.makedirs(out_dir, exist_ok=True)

    entries = build_entries()
    for name, data in sorted(entries.items()):
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {path}  ({len(data)} B)")

    print(f"\n{len(entries)} files written to {out_dir}")


if __name__ == "__main__":
    main()
