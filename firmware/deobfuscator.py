#!/usr/bin/env python3
"""
M3 — Deobfuscation Tool: XOR decoding, base64 unpacking, string extraction

Educational tool for malware deobfuscation and encoded payload analysis.
"""

import os
import sys
import re
import json
import base64
import string
import hashlib
import argparse
import binascii
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import Counter

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


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
class ExtractedString:
    offset: int
    value: str
    encoding: str
    category: str
    length: int


@dataclass
class AnalysisResult:
    file_path: str
    file_size: int
    file_type: str
    md5: str
    sha256: str
    total_entropy: float
    extracted_strings: List[ExtractedString]
    decoded_payloads: List[DecodedPayload]
    suspicious_patterns: List[Dict]
    recommendations: List[str]


class EntropyAnalyzer:
    @staticmethod
    def calculate(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * (p and __import__('math').log2(p))
        return entropy

    @staticmethod
    def classify(entropy: float) -> str:
        if entropy < 1.0:
            return "very low (likely structured data)"
        elif entropy < 3.0:
            return "low (likely text/code)"
        elif entropy < 5.0:
            return "medium (mixed content)"
        elif entropy < 7.0:
            return "high (likely compressed/encrypted)"
        else:
            return "very high (likely random/encrypted)"


class StringExtractor:
    MIN_LENGTH = 4
    PRINTABLE = set(string.printable)

    CATEGORIES = {
        'url': re.compile(r'https?://[^\s\x00-\x1f]{4,}'),
        'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'file_path': re.compile(r'[A-Z]:\\[^\s\x00-\x1f]{4,}|/(?:usr|etc|var|tmp|home)/[^\s\x00-\x1f]{4,}'),
        'registry': re.compile(r'HK(?:LM|CU|CR|U|CC)\\[^\s\x00-\x1f]{4,}'),
        'api_call': re.compile(r'\b(?:Create|Open|Read|Write|Close|Load|Get|Set|Send|Recv|Connect|Bind|Listen|Accept|Virtual|Alloc|Free|Protect|Copy|Move|Delete|Reg|Internet|URL|Http|Socket|Process|Thread|File|Pipe|Mutex|Event|Service|Crypt|Hash|Encrypt|Decrypt)[A-Za-z]*\b'),
        'powershell': re.compile(r'(?:powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\s+[^\s\x00-\x1f]{2,}', re.IGNORECASE),
        'base64_chunk': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
    }

    def extract(self, data: bytes, max_strings: int = 5000) -> List[ExtractedString]:
        strings = []
        current = []
        offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= self.MIN_LENGTH:
                    s = ''.join(current)
                    category = self._categorize(s)
                    encoding = self._detect_encoding(s)
                    strings.append(ExtractedString(
                        offset=offset, value=s, encoding=encoding,
                        category=category, length=len(s)
                    ))
                current = []
                offset = i + 1

        if len(current) >= self.MIN_LENGTH:
            s = ''.join(current)
            strings.append(ExtractedString(
                offset=offset, value=s,
                encoding=self._detect_encoding(s),
                category=self._categorize(s), length=len(s)
            ))

        strings.sort(key=lambda x: x.length, reverse=True)
        return strings[:max_strings]

    def _categorize(self, s: str) -> str:
        for cat, pattern in self.CATEGORIES.items():
            if pattern.search(s):
                return cat
        return 'generic'

    def _detect_encoding(self, s: str) -> str:
        if re.match(r'^[01]+$', s) and len(s) % 8 == 0:
            return 'binary'
        if re.match(r'^[0-9a-fA-F]+$', s) and len(s) >= 8 and len(s) % 2 == 0:
            return 'hex'
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', s) and len(s) >= 16:
            try:
                decoded = base64.b64decode(s)
                printable_ratio = sum(1 for b in decoded if 32 <= b <= 126) / max(len(decoded), 1)
                if printable_ratio > 0.5:
                    return 'base64'
            except Exception:
                pass
        return 'ascii'


class XORDecoder:
    def decode_single_byte(self, data: bytes) -> List[DecodedPayload]:
        results = []
        entropy_before = EntropyAnalyzer.calculate(data)

        for key in range(256):
            decoded = bytes([b ^ key for b in data])
            entropy_after = EntropyAnalyzer.calculate(decoded)
            printable_ratio = sum(1 for b in decoded if 32 <= b <= 126) / max(len(decoded), 1)

            if printable_ratio > 0.6 and entropy_after < entropy_before:
                confidence = printable_ratio * (1 - entropy_after / 8.0)
                try:
                    text = decoded.decode('ascii', errors='ignore')
                except Exception:
                    text = repr(decoded)
                results.append(DecodedPayload(
                    method=f'XOR single-byte (key=0x{key:02x})',
                    input_preview=binascii.hexlify(data[:50]).decode(),
                    output_preview=text[:200],
                    output_hex=binascii.hexlify(decoded[:100]).decode(),
                    confidence=min(confidence, 1.0),
                    entropy_before=entropy_before,
                    entropy_after=entropy_after
                ))

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]

    def decode_repeating_key(self, data: bytes, max_key_len: int = 16) -> List[DecodedPayload]:
        results = []
        entropy_before = EntropyAnalyzer.calculate(data)

        for key_len in range(2, min(max_key_len + 1, len(data) // 4)):
            for start_pos in range(min(key_len, len(data))):
                key_fragment = data[start_pos::key_len][:key_len]
                key = bytes([key_fragment[i % len(key_fragment)] for i in range(key_len)])
                decoded = bytes([data[i] ^ key[i % key_len] for i in range(len(data))])

                printable_ratio = sum(1 for b in decoded if 32 <= b <= 126) / max(len(decoded), 1)
                entropy_after = EntropyAnalyzer.calculate(decoded)

                if printable_ratio > 0.65 and entropy_after < 5.0:
                    confidence = printable_ratio * (1 - entropy_after / 8.0)
                    try:
                        text = decoded.decode('ascii', errors='ignore')
                    except Exception:
                        text = repr(decoded)
                    results.append(DecodedPayload(
                        method=f'XOR repeating-key (len={key_len}, key={binascii.hexlify(key).decode()})',
                        input_preview=binascii.hexlify(data[:50]).decode(),
                        output_preview=text[:200],
                        output_hex=binascii.hexlify(decoded[:100]).decode(),
                        confidence=min(confidence, 1.0),
                        entropy_before=entropy_before,
                        entropy_after=entropy_after
                    ))

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:10]


class Base64Decoder:
    def decode_all(self, data: bytes) -> List[DecodedPayload]:
        results = []
        entropy_before = EntropyAnalyzer.calculate(data)

        patterns = [
            re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}'),
            re.compile(rb'[A-Za-z0-9+/]{20,}={1,2}'),
        ]

        seen = set()
        for pattern in patterns:
            for match in pattern.finditer(data):
                encoded = match.group().decode('ascii')
                if encoded in seen:
                    continue
                seen.add(encoded)

                for encoding in [base64.b64decode, base64.b32decode, base64.b16decode]:
                    try:
                        decoded = encoding(encoded)
                        if len(decoded) < 4:
                            continue
                        entropy_after = EntropyAnalyzer.calculate(decoded)
                        printable_ratio = sum(
                            1 for b in decoded if 32 <= b <= 126
                        ) / max(len(decoded), 1)

                        if printable_ratio > 0.5:
                            confidence = printable_ratio * 0.8
                            try:
                                text = decoded.decode('utf-8', errors='ignore')
                            except Exception:
                                text = repr(decoded)
                            method_name = {
                                base64.b64decode: 'Base64',
                                base64.b32decode: 'Base32',
                                base64.b16decode: 'Base16/Hex'
                            }[encoding]
                            results.append(DecodedPayload(
                                method=f'{method_name} decode',
                                input_preview=encoded[:100],
                                output_preview=text[:200],
                                output_hex=binascii.hexlify(decoded[:100]).decode(),
                                confidence=min(confidence, 1.0),
                                entropy_before=entropy_before,
                                entropy_after=entropy_after
                            ))
                            break
                    except Exception:
                        continue

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:20]


class HexDecoder:
    def decode(self, data: bytes) -> List[DecodedPayload]:
        results = []
        entropy_before = EntropyAnalyzer.calculate(data)

        text = data.decode('ascii', errors='ignore')
        hex_pattern = re.compile(r'(?:0x)?([0-9a-fA-F]{2}(?:\s*[0-9a-fA-F]{2}){3,})')
        for match in hex_pattern.finditer(text):
            hex_str = match.group(1).replace(' ', '')
            try:
                decoded = bytes.fromhex(hex_str)
                if len(decoded) < 2:
                    continue
                entropy_after = EntropyAnalyzer.calculate(decoded)
                printable_ratio = sum(
                    1 for b in decoded if 32 <= b <= 126
                ) / max(len(decoded), 1)

                if printable_ratio > 0.5:
                    confidence = printable_ratio * 0.7
                    try:
                        dec_text = decoded.decode('utf-8', errors='ignore')
                    except Exception:
                        dec_text = repr(decoded)
                    results.append(DecodedPayload(
                        method='Hex decode',
                        input_preview=hex_str[:100],
                        output_preview=dec_text[:200],
                        output_hex=binascii.hexlify(decoded[:100]).decode(),
                        confidence=min(confidence, 1.0),
                        entropy_before=entropy_before,
                        entropy_after=entropy_after
                    ))
            except ValueError:
                continue

        return results[:10]


class SuspiciousPatternDetector:
    PATTERNS = {
        'shellcode_nops': re.compile(rb'\x90{16,}', re.DOTALL),
        'api_hashing': re.compile(rb'(?:GetModuleHandle|GetProcAddress|LoadLibrary)[A-Z][a-z]+'),
        'anti_debug': re.compile(rb'(?:IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformation|OutputDebugString)', re.IGNORECASE),
        'persistence': re.compile(rb'(?:CurrentVersion\\Run|schtasks|HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion)', re.IGNORECASE),
        'evasion': re.compile(rb'(?:NtSetInformationThread|SetThreadContext|VirtualProtect|PAGE_EXECUTE)', re.IGNORECASE),
        'data_exfil': re.compile(rb'(?:InternetOpen|HttpSendRequest|URLDownload|WSAStartup|socket|connect)', re.IGNORECASE),
        'crypto_imports': re.compile(rb'(?:CryptEncrypt|CryptDecrypt|CryptAcquireContext|BCryptEncrypt|AES|RSA)', re.IGNORECASE),
    }

    def scan(self, data: bytes) -> List[Dict]:
        findings = []
        for name, pattern in self.PATTERNS.items():
            matches = pattern.findall(data)
            if matches:
                findings.append({
                    'pattern': name,
                    'count': len(matches),
                    'samples': [m.decode('ascii', errors='replace')[:100] for m in matches[:5]]
                })
        return findings


class Deobfuscator:
    def __init__(self, args):
        self.input_path = args.input
        self.output_dir = args.output or os.path.join(os.path.dirname(self.input_path) or '.', 'deob_output')
        self.max_strings = args.max_strings
        self.xor_enabled = args.xor
        self.base64_enabled = args.base64
        self.hex_enabled = args.hex

        os.makedirs(self.output_dir, exist_ok=True)

        self.string_extractor = StringExtractor()
        self.xor_decoder = XORDecoder()
        self.base64_decoder = Base64Decoder()
        self.hex_decoder = HexDecoder()
        self.pattern_detector = SuspiciousPatternDetector()
        self.entropy_analyzer = EntropyAnalyzer()

    def _compute_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

    def _detect_file_type(self, data: bytes) -> str:
        if MAGIC_AVAILABLE:
            try:
                return magic.from_buffer(data)
            except Exception:
                pass
        if data[:2] == b'MZ':
            return 'PE executable'
        if data[:4] == b'\x7fELF':
            return 'ELF executable'
        if data[:4] == b'%PDF':
            return 'PDF document'
        if data[:3] == b'PK\x03\x04'[:3]:
            return 'ZIP archive'
        return 'Unknown'

    def run(self) -> AnalysisResult:
        logger.info(f"Analyzing: {self.input_path}")

        with open(self.input_path, 'rb') as f:
            data = f.read()

        hashes = self._compute_hashes(data)
        entropy = self.entropy_analyzer.calculate(data)
        file_type = self._detect_file_type(data)

        logger.info(f"File type: {file_type}")
        logger.info(f"Entropy: {entropy:.2f} ({self.entropy_analyzer.classify(entropy)})")
        logger.info(f"SHA256: {hashes['sha256']}")

        strings = self.string_extractor.extract(data, self.max_strings)
        logger.info(f"Extracted {len(strings)} strings")

        decoded_payloads = []
        if self.xor_enabled:
            xor_results = self.xor_decoder.decode_single_byte(data)
            xor_results.extend(self.xor_decoder.decode_repeating_key(data))
            decoded_payloads.extend(xor_results)
            logger.info(f"XOR: Found {len(xor_results)} potential decodings")

        if self.base64_enabled:
            b64_results = self.base64_decoder.decode_all(data)
            decoded_payloads.extend(b64_results)
            logger.info(f"Base64: Found {len(b64_results)} potential decodings")

        if self.hex_enabled:
            hex_results = self.hex_decoder.decode(data)
            decoded_payloads.extend(hex_results)
            logger.info(f"Hex: Found {len(hex_results)} potential decodings")

        suspicious = self.pattern_detector.scan(data)
        logger.info(f"Suspicious patterns: {len(suspicious)}")

        recommendations = self._generate_recommendations(
            entropy, strings, decoded_payloads, suspicious
        )

        result = AnalysisResult(
            file_path=self.input_path,
            file_size=len(data),
            file_type=file_type,
            md5=hashes['md5'],
            sha256=hashes['sha256'],
            total_entropy=entropy,
            extracted_strings=[asdict(s) for s in strings[:200]],
            decoded_payloads=[asdict(p) for p in decoded_payloads[:50]],
            suspicious_patterns=suspicious,
            recommendations=recommendations
        )

        report_path = os.path.join(self.output_dir, 'deobfuscation_report.json')
        with open(report_path, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
        logger.info(f"Report saved to: {report_path}")

        strings_path = os.path.join(self.output_dir, 'extracted_strings.txt')
        with open(strings_path, 'w') as f:
            for s in strings:
                f.write(f"[{s.offset:08x}] [{s.category}] {s.value}\n")
        logger.info(f"Strings saved to: {strings_path}")

        return result


def print_report(result: AnalysisResult):
    print("\n" + "=" * 60)
    print("  M3 — Deobfuscation Tool — Report")
    print("=" * 60)
    print(f"  File:      {result.file_path}")
    print(f"  Size:      {result.file_size} bytes")
    print(f"  Type:      {result.file_type}")
    print(f"  MD5:       {result.md5}")
    print(f"  SHA256:    {result.sha256}")
    print(f"  Entropy:   {result.total_entropy:.2f}")
    print("-" * 60)
    print(f"  Strings:         {len(result.extracted_strings)}")
    print(f"  Decoded:         {len(result.decoded_payloads)}")
    print(f"  Suspicious:      {len(result.suspicious_patterns)}")
    print(f"  Recommendations: {len(result.recommendations)}")
    print("-" * 60)

    if result.extracted_strings:
        print("  Top Strings:")
        for s in result.extracted_strings[:15]:
            print(f"    [{s['category']}] {s['value'][:80]}")

    if result.decoded_payloads:
        print("\n  Decoded Payloads:")
        for dp in result.decoded_payloads[:10]:
            print(f"    [{dp['method']}] confidence={dp['confidence']:.2f}")
            print(f"      Output: {dp['output_preview'][:80]}")

    if result.suspicious_patterns:
        print("\n  Suspicious Patterns:")
        for sp in result.suspicious_patterns:
            print(f"    [!] {sp['pattern']}: {sp['count']} matches")

    if result.recommendations:
        print("\n  Recommendations:")
        for rec in result.recommendations:
            print(f"    -> {rec}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='M3 — Deobfuscation Tool'
    )
    parser.add_argument(
        'input', help='Path to file to deobfuscate'
    )
    parser.add_argument(
        '-o', '--output', help='Output directory for results'
    )
    parser.add_argument(
        '--max-strings', type=int, default=5000,
        help='Maximum strings to extract (default: 5000)'
    )
    parser.add_argument(
        '--no-xor', dest='xor', action='store_false',
        help='Disable XOR decoding'
    )
    parser.add_argument(
        '--no-base64', dest='base64', action='store_false',
        help='Disable Base64 decoding'
    )
    parser.add_argument(
        '--no-hex', dest='hex', action='store_false',
        help='Disable hex decoding'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output'
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}")
        sys.exit(1)

    deob = Deobfuscator(args)
    result = deob.run()
    print_report(result)


if __name__ == '__main__':
    main()
