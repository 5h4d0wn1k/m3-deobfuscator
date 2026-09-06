#!/usr/bin/env python3
"""Tests for m3-deobfuscator."""
import json
import os
import sys
import unittest
import base64

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from deobfuscator import (XORDecoder, decode_all_encodings, decode_hex_strings,
                          fold_constants, disassemble_python, entropy,
                          extract_strings, AnalysisResult,
                          Deobfuscator, build_report)
from build_fixtures import xor_bytes, MARKER, SINGLE_KEY, REPEAT_KEY, BEACON, CLIENT_TAG, REPEAT_PLAIN


class TestXOR(unittest.TestCase):
    def setUp(self):
        self.xd = XORDecoder()

    def test_single_byte_recovery(self):
        enc = xor_bytes(MARKER, SINGLE_KEY)
        hits = self.xd.single_byte(enc)
        self.assertTrue(hits, "should find at least one single-byte XOR hit")
        found = any(MARKER.decode() in h.output_preview for h in hits)
        self.assertTrue(found, "marker should appear in one of the decoded hits")

    def test_repeating_key_recovery(self):
        plain = REPEAT_PLAIN * 3
        enc = xor_bytes(plain, REPEAT_KEY)
        hits = self.xd.repeating_key(enc)
        self.assertTrue(hits, "should find repeating-key XOR hit")
        found = any(REPEAT_PLAIN.decode()[:12] in h.output_preview for h in hits)
        self.assertTrue(found, "plaintext prefix should appear in one of the hits")


class TestDecoding(unittest.TestCase):
    def test_base64_decode(self):
        enc = b"prefix " + base64.b64encode(bytes(BEACON)) + b" suffix"
        hits = decode_all_encodings(enc)
        self.assertTrue(any("192.0.2.10" in h.output_preview for h in hits))

    def test_hex_decode(self):
        hex_str = "414243444546"  # ABCDEF
        data = b" hexpayload: " + hex_str.encode() + b" "
        hits = decode_hex_strings(data)
        self.assertTrue(any("ABCDEF" in h.output_preview for h in hits))


class TestFolding(unittest.TestCase):
    def test_const_fold_and_eval(self):
        src = '_a="api"+"_key"\n_port=13*100+37\n_d=eval("\'dec\' + \'oy\'")\n'
        _, folds, err = fold_constants(src)
        self.assertFalse(err)
        results = [f.result for f in folds]
        kinds = [f.kind for f in folds]
        # constant folding of "api"+"_key" => "api_key", 13*100+37 => 1337
        self.assertTrue(any("'api_key'" in r for r in results), results)
        self.assertTrue(any("1337" in r for r in results), results)
        # eval(...) calls are surfaced as instrumentation folds, never executed
        self.assertIn("eval", kinds)


class TestDis(unittest.TestCase):
    def test_dis_returns_bytecode(self):
        code = "x = 1\ny = 2\nz = x + y\n"
        out = disassemble_python(code)
        self.assertIn("LOAD_CONST", out)


class TestFixtureELF(unittest.TestCase):
    def test_cli_on_fixture_py(self):
        """obfuscated_python.py parses as valid Python and fold finds at least one fold."""
        fpath = os.path.join(FIX, "obfuscated_python.py")
        self.assertTrue(os.path.exists(fpath), fpath)
        with open(fpath) as f:
            src = f.read()
        import ast
        ast.parse(src)
        _, folds, err = fold_constants(src)
        self.assertFalse(err)
        self.assertGreaterEqual(len(folds), 3)

    def test_payload_report(self):
        fpath = os.path.join(FIX, "obfuscated_payload.bin")
        self.assertTrue(os.path.exists(fpath))
        deob = Deobfuscator(fpath)
        res = deob.run()
        self.assertGreater(len(res.decoded_payloads), 0)
        self.assertGreater(len(res.susp_patterns), 0)
        self.assertIn("Base64 decode", [d["method"] for d in res.decoded_payloads])


class TestCLI(unittest.TestCase):
    SCRIPT = os.path.join(os.path.dirname(__file__), "..", "firmware", "deobfuscator.py")

    def test_help(self):
        import subprocess
        r = subprocess.run([sys.executable, self.SCRIPT, "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("deobfuscate", r.stdout.lower())

    def test_fixture_run(self):
        import subprocess, tempfile
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.json")
            fpath = os.path.join(FIX, "obfuscated_payload.bin")
            r = subprocess.run([sys.executable, self.SCRIPT, fpath, "-o", out],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(out))
            d = json.load(open(out))
            self.assertGreater(len(d["decoded_payloads"]), 0)

    def test_missing_file(self):
        import subprocess
        r = subprocess.run([sys.executable, self.SCRIPT, "/no/such/file"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()