#!/usr/bin/env python3
"""Deterministic fixture generator for m3-deobfuscator.

Writes inert, clearly-benchmark fixtures under ../fixtures/. Run:

    python3 build_fixtures.py
"""
import base64
import binascii
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.normpath(os.path.join(HERE, "..", "fixtures"))

SINGLE_KEY = 0x42
REPEAT_KEY = bytes([0x5A, 0xA3, 0x2F])
MARKER = b"M3-Sandbox-Marker::Command-Executed"
BEACON = b"192.0.2.10 beacon payload: authorize only"
REPEAT_PLAIN = b"authorized lab beacon id 77 establish outbound shell and exfil data now"
CLIENT_TAG = b"lab-sandbox-client-id-0x7f3a"


def xor_bytes(data, key):
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    klen = len(key)
    return bytes(data[i] ^ key[i % klen] for i in range(len(data)))


def build_payload_bin():
    parts = [
        xor_bytes(MARKER, SINGLE_KEY),
        b"\x90" * 24,
        b"\nDECOY-STRING-SEVEN-ACROSS-EIGHT\n",
        base64.b64encode(BEACON),
        b" ; ",
        binascii.hexlify(b"lab-beacon-ok"),
        b"\n",
    ]
    return b"".join(parts)


def build_python_fixture():
    payload_b64 = base64.b64encode(xor_bytes(CLIENT_TAG, 0x5A)).decode()
    lines = [
        "import base64 as _b",
        "",
        "# flagged fixture: obfuscated-but-benign python sample",
        "def _unxor(data, key):",
        "    return bytes(b ^ key for b in data)",
        "",
        "_payload = _b.b64decode(\"%s\")" % payload_b64,
        "",
        "_api = \"api\" + \"_key\"",
        "_host = \"127\" + \".0.0.1\"",
        "_port = 13 * 100 + 37",
        "_decoy = eval(\"'dec' + 'oy'\")",
        "",
        "def run(_h=_host):",
        "    return _unxor(_payload, 0x5A)",
    ]
    return "\n".join(lines) + "\n"


def write(name, data):
    os.makedirs(FIX, exist_ok=True)
    path = os.path.join(FIX, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def main():
    out = []
    out.append(write("obfuscated_payload.bin", build_payload_bin()))
    out.append(write("xor_single.bin", xor_bytes(MARKER, SINGLE_KEY)))
    out.append(write("xor_repeat.bin", xor_bytes(REPEAT_PLAIN * 3, REPEAT_KEY)))
    out.append(write("obfuscated_python.py", build_python_fixture().encode()))
    for p in out:
        print("wrote %s (%d bytes)" % (p, os.path.getsize(p)))


if __name__ == "__main__":
    main()