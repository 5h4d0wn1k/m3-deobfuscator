#!/usr/bin/env python3
"""
M3 — Deobfuscator

Real, pure-stdlib deobfuscation passes for educational malware analysis:

  * string XOR lifting            single- and repeating-key XOR recovery to
                                  printable ASCII (confidence-ranked)
  * base64 / base32 / base16      decode of encoded blobs found in the sample
  * hex lifting                   decode of hex-encoded byte strings
  * eval / constant folding       AST pass that folds constant expressions and
                                  eval("...") calls back to their literal value
  * bytecode disassembly          dismodule disassembly of embedded Python
  * suspicious pattern scan       shellcode / anti-debug / persistence / exfil
                                  signature matches + entropy analysis

Offline, deterministic, stdlib-only (no python-magic / yara / lief).

Usage:
    python3 deobfuscator.py <file> [-o reports/out.json] [--markdown]

WARNING: Educational / authorized analysis only.
"""

import argparse
import ast
import base64
import binascii
import hashlib
import json
import logging
import math
import operator
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("m3")

# ---------------------------------------------------------------------------
# entropy / strings
# ---------------------------------------------------------------------------


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((p / n) * math.log2(p / n) for p in c.values())


@dataclass
class ExtractedString:
    offset: int
    value: str
    encoding: str
    category: str
    length: int


@dataclass
class DecodedPayload:
    method: str
    input_preview: str
    output_preview: str
    output_hex: str
    confidence: float
    entropy_before: float
    entropy_after: float


@dataclass
class FoldResult:
    kind: str            # const | eval
    expression: str
    result: str
    line: int


@dataclass
class AnalysisResult:
    file_path: str
    file_size: int
    file_type: str
    md5: str
    sha256: str
    total_entropy: float
    extracted_strings: list = field(default_factory=list)
    decoded_payloads: list = field(default_factory=list)
    susp_patterns: list = field(default_factory=list)
    folds: list = field(default_factory=list)          # constant folding
    disassembly: str = ""
    recommendations: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# string extraction / categorization
# ---------------------------------------------------------------------------

CATEGORIES = {
    "url": re.compile(r"https?://[^\s\x00-\x1f]{4,}"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "registry": re.compile(r"HK(?:LM|CU|CR|U|CC)\\[^\s\x00-\x1f]{4,}"),
    "api_call": re.compile(
        r"\b(?:Create|Open|Read|Write|Load|Get|Set|Send|Recv|Virtual|Alloc|"
        r"Internet|URL|Http|Socket|Process|Thread|File|Reg|Crypt)[A-Za-z]*\b"),
}

def _most_frequent(values):
    from collections import Counter as _C
    return _C(values).most_common(1)[0][0]


PRINTABLE = set(range(32, 127))


def extract_strings(data, min_len=6, max_strings=2000):
    out = []
    run = []
    start = 0
    for i, b in enumerate(data):
        if b in PRINTABLE:
            if not run:
                start = i
            run.append(chr(b))
        else:
            if len(run) >= min_len:
                s = "".join(run)
                cat = next((c for c, p in CATEGORIES.items() if p.search(s)),
                           "generic")
                out.append(ExtractedString(start, s, "ascii", cat, len(s)))
            run = []
    if len(run) >= min_len:
        s = "".join(run)
        cat = next((c for c, p in CATEGORIES.items() if p.search(s)), "generic")
        out.append(ExtractedString(start, s, "ascii", cat, len(s)))
    out.sort(key=lambda x: x.length, reverse=True)
    return out[:max_strings]


# ---------------------------------------------------------------------------
# XOR lifting
# ---------------------------------------------------------------------------


class XORDecoder:
    def single_byte(self, data):
        results = []
        eb = entropy(data)
        for key in range(256):
            dec = bytes(b ^ key for b in data)
            ea = entropy(dec)
            printable = sum(1 for b in dec if b in PRINTABLE) / max(len(dec), 1)
            if printable > 0.55:
                conf = min(printable * max(1 - ea / 8.0, 0.3), 1.0)
                results.append(DecodedPayload(
                    method="XOR single-byte (key=0x%02x)" % key,
                    input_preview=binascii.hexlify(data[:48]).decode(),
                    output_preview=dec.decode("latin1")[:200],
                    output_hex=binascii.hexlify(dec[:96]).decode(),
                    confidence=round(conf, 4),
                    entropy_before=round(eb, 4), entropy_after=round(ea, 4)))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def repeating_key(self, data, max_len=16):
        results = []
        eb = entropy(data)
        for klen in range(2, min(max_len, len(data))):
            blocks = [data[i:i + klen] for i in range(0, len(data), klen)]
            full = [b for b in blocks if len(b) == klen]
            if not full:
                continue
            zipped = list(zip(*full))
            # Standard IC-based recovery: the most frequent byte in each key
            # column is very likely the plaintext space (0x20).
            key = bytes(0x20 ^ _most_frequent(col) for col in zipped)
            dec = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
            printable = sum(1 for b in dec if b in PRINTABLE) / max(len(dec), 1)
            ea = entropy(dec)
            if printable > 0.55:
                conf = min(printable * max(1 - ea / 8.0, 0.3), 1.0)
                results.append(DecodedPayload(
                    method="XOR repeating (len=%d key=%s)"
                           % (klen, binascii.hexlify(key).decode()),
                    input_preview=binascii.hexlify(data[:48]).decode(),
                    output_preview=dec.decode("latin1")[:200],
                    output_hex=binascii.hexlify(dec[:96]).decode(),
                    confidence=round(conf, 4),
                    entropy_before=round(eb, 4), entropy_after=round(ea, 4)))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:5]


# ---------------------------------------------------------------------------
# base64 / hex lifting
# ---------------------------------------------------------------------------


def decode_all_encodings(data):
    results = []
    eb = entropy(data)
    seen = set()
    for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        enc = m.group().decode("ascii")
        if enc in seen:
            continue
        seen.add(enc)
        for encname, fn in (("Base64", base64.b64decode),
                            ("Base32", base64.b32decode),
                            ("Base16", base64.b16decode)):
            try:
                dec = fn(enc)
            except Exception:
                continue
            if len(dec) < 4:
                continue
            printable = sum(1 for b in dec if b in PRINTABLE) / max(len(dec), 1)
            if printable > 0.5:
                text = dec.decode("latin1")
                results.append(DecodedPayload(
                    method="%s decode" % encname,
                    input_preview=enc[:80],
                    output_preview=text[:200],
                    output_hex=binascii.hexlify(dec[:96]).decode(),
                    confidence=round(printable * 0.8, 4),
                    entropy_before=round(eb, 4),
                    entropy_after=round(entropy(dec), 4)))
                break
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results[:15]


def decode_hex_strings(data):
    results = []
    text = data.decode("latin1")
    for m in re.finditer(r"(?:0x)?([0-9a-fA-F]{2}(?:\s?[0-9a-fA-F]{2}){3,})",
                         text):
        h = m.group(1).replace(" ", "").replace("0x", "")
        try:
            dec = bytes.fromhex(h)
        except ValueError:
            continue
        if len(dec) < 3:
            continue
        printable = sum(1 for b in dec if b in PRINTABLE) / max(len(dec), 1)
        if printable > 0.5:
            results.append(DecodedPayload(
                method="Hex decode",
                input_preview=m.group(0)[:80],
                output_preview=dec.decode("latin1")[:200],
                output_hex=binascii.hexlify(dec[:96]).decode(),
                confidence=round(printable * 0.7, 4),
                entropy_before=round(entropy(data), 4),
                entropy_after=round(entropy(dec), 4)))
    return results[:10]


# ---------------------------------------------------------------------------
# eval / constant folding (AST pass)
# ---------------------------------------------------------------------------

FOLD_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
}

_SAFE_TYPES = (int, float, str, bytes)


class _Folder(ast.NodeTransformer):
    """Fold constant BinOp subtrees and eval('const') calls; record folds."""

    def __init__(self):
        self.folds = []

    def visit_BinOp(self, node):
        node = self.generic_visit(node)
        op = FOLD_OPS.get(type(node.op))
        if (op is not None
                and isinstance(node.left, ast.Constant)
                and isinstance(node.right, ast.Constant)
                and isinstance(node.left.value, _SAFE_TYPES)
                and isinstance(node.right.value, _SAFE_TYPES)):
            if isinstance(node.left.value, bytes) or isinstance(node.right.value, bytes):
                return node
            try:
                val = op(node.left.value, node.right.value)
            except Exception:
                return node
            if isinstance(val, _SAFE_TYPES):
                self.folds.append(FoldResult(
                    kind="const",
                    expression="%r %s %r" % (
                        node.left.value,
                        type(node.op).__name__[3:].upper(),
                        node.right.value),
                    result=repr(val), line=node.lineno))
                return ast.copy_location(
                    ast.Constant(value=val, kind=None), node)
        return node

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if (isinstance(node.func, ast.Name) and node.func.id == "eval"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            self.folds.append(FoldResult(
                kind="eval",
                expression="eval(%r)" % node.args[0].value,
                result=repr(node.args[0].value), line=node.lineno))
            return ast.copy_location(
                ast.Constant(value=node.args[0].value, kind=None), node)
        return node


def fold_constants(source):
    """Fold constant expressions + eval('...') in Python source via the std
    ast module. Returns (folded_source, [FoldResult], error_str_or_empty)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return source, [], str(e)
    folder = _Folder()
    new_tree = folder.visit(tree)
    try:
        folded_src = ast.unparse(new_tree)
    except Exception:
        folded_src = source
    return folded_src, sorted(folder.folds, key=lambda f: (f.line, f.kind)), ""


def disassemble_python(source_or_pyc, limit=120):
    """Real disassembly of a Python source/pyc using the built-in dis module."""
    import dis
    import marshal
    import types
    if isinstance(source_or_pyc, bytes):
        code = marshal.loads(source_or_pyc[16:])
    else:
        code = compile(source_or_pyc, "<obfuscated>", "exec")
    out = []
    out.append("module code object disassembly")
    for line in dis.Bytecode(code).dis().splitlines()[:limit]:
        out.append("  " + line)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            out.append("\n# function %r" % (const.co_name or "<lambda>"))
            for line in dis.Bytecode(const).dis().splitlines()[:limit]:
                out.append("  " + line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# suspicious pattern scan
# ---------------------------------------------------------------------------

SUSPECT = {
    "nop_sled": re.compile(rb"\x90{16,}"),
    "anti_debug": re.compile(
        rb"(?:IsDebuggerPresent|CheckRemoteDebugger|ptrace|PTRACE_TRACEME)",
        re.IGNORECASE),
    "persistence": re.compile(
        rb"(?:CurrentVersion\\Run|schtasks|/etc/cron|HKLM\\SOFTWARE)",
        re.IGNORECASE),
    "exfil/network": re.compile(
        rb"(?:InternetOpen|HttpSendRequest|URLDownload|WSAStartup|socket\()",
        re.IGNORECASE),
    "bad_eval": re.compile(rb"\beval\s*\("),
    "exec_string": re.compile(rb"(?:exec|system|popen|subprocess)\s*\("),
}


def scan_suspicious(data):
    hits = []
    for name, pat in SUSPECT.items():
        ms = pat.findall(data)
        if ms:
            hits.append({"pattern": name, "count": len(ms),
                         "samples": [m.decode("ascii", "replace")[:80]
                                     for m in ms[:5]]})
    return hits


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------


def detect_file_type(data):
    if data[:2] == b"MZ":
        return "PE executable"
    if data[:4] == b"\x7fELF":
        return "ELF executable"
    if data[:4] == b"%PDF":
        return "PDF document"
    if data[:2] == b"PK":
        return "ZIP archive"
    return "Unknown"


class Deobfuscator:
    def __init__(self, path, do_xor=True, do_b64=True, do_hex=True,
                 do_fold=True, do_dis=True, max_strings=2000):
        self.path = path
        self.flags = (do_xor, do_b64, do_hex, do_fold, do_dis)
        self.max_strings = max_strings

    def run(self):
        with open(self.path, "rb") as f:
            data = f.read()
        hashes = {"md5": hashlib.md5(data).hexdigest(),
                  "sha256": hashlib.sha256(data).hexdigest()}
        res = AnalysisResult(
            file_path=self.path, file_size=len(data),
            file_type=detect_file_type(data),
            md5=hashes["md5"], sha256=hashes["sha256"],
            total_entropy=round(entropy(data), 4))
        res.extracted_strings = [asdict(s) for s in
                                 extract_strings(data, max_strings=self.max_strings)]

        do_xor, do_b64, do_hex, do_fold, do_dis = self.flags
        xd = XORDecoder()
        if do_xor:
            res.decoded_payloads += xd.single_byte(data)
            res.decoded_payloads += xd.repeating_key(data)
        if do_b64:
            res.decoded_payloads += decode_all_encodings(data)
        if do_hex:
            res.decoded_payloads += decode_hex_strings(data)
        dc = [asdict(p) for p in res.decoded_payloads]
        dc.sort(key=lambda x: x["confidence"], reverse=True)
        res.decoded_payloads = dc[:40]

        res.susp_patterns = scan_suspicious(data)

        if do_fold or do_dis:
            try:
                text = data.decode("utf-8", "replace")
            except Exception:
                text = ""
            if re.search(r"^\s*(import|def |class |x\s*=)", text,
                         re.MULTILINE):
                if do_fold:
                    _, folds, _ = fold_constants(text)
                    res.folds = [asdict(f) for f in folds[:40]]
                if do_dis:
                    res.disassembly = disassemble_python(text)
        return res


def build_report(res, markdown=False):
    if markdown:
        lines = ["# M3 Deobfuscation Report", "",
                 "**File:** `%s`  " % res.file_path,
                 "**Type:** %s  " % res.file_type,
                 "**Size:** %d bytes  " % res.file_size,
                 "**SHA256:** `%s`  " % res.sha256,
                 "**File entropy:** %.4f" % res.total_entropy,
                 "", "## Constant folds", ""]
        for f in res.folds:
            lines.append("- `%s => %s` (line %d)" % (f["expression"],
                                                     f["result"], f["line"]))
        lines += ["", "## Decoded payloads", ""]
        for p in res.decoded_payloads[:12]:
            lines.append("- **%s** conf=%.2f" % (p["method"], p["confidence"]))
            lines.append("  `%s`" % p["output_preview"][:80])
        lines += ["", "## Disassembly (excerpt)", ""]
        for ln in res.disassembly.splitlines()[:18]:
            lines.append("    " + ln)
        return "\n".join(lines)
    return json.dumps(asdict(res), indent=2)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="deobfuscator.py",
        description="M3 - Deobfuscator (XOR/base64/hex lifting, constant "
                    "folding, dis disassembly)")
    parser.add_argument("input", help="Path to file to deobfuscate")
    parser.add_argument("-o", "--output", default=None,
                        help="Write JSON report here (default reports/…)")
    parser.add_argument("--markdown", action="store_true",
                        help="Also emit a Markdown report")
    parser.add_argument("--max-strings", type=int, default=2000)
    parser.add_argument("--no-xor", action="store_true")
    parser.add_argument("--no-base64", action="store_true")
    parser.add_argument("--no-hex", action="store_true")
    parser.add_argument("--no-fold", action="store_true")
    parser.add_argument("--no-dis", action="store_true")
    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        print("Error: file not found: %s" % args.input)
        return 1
    try:
        deob = Deobfuscator(
            args.input, do_xor=not args.no_xor, do_b64=not args.no_base64,
            do_hex=not args.no_hex, do_fold=not args.no_fold,
            do_dis=not args.no_dis, max_strings=args.max_strings)
        res = deob.run()
    except Exception as e:
        print("Error: %s" % e)
        return 1

    out = args.output or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "deobf_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(build_report(res, markdown=False))
    if args.markdown:
        mdp = out + ".md"
        with open(mdp, "w") as f:
            f.write(build_report(res, markdown=True))
        print("Markdown report: %s" % mdp)

    print(build_report(res, markdown=True))
    print("\nJSON report: %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())