# M3 — Deobfuscation Tool

XOR decoding, base64 unpacking, string extraction, and encoded payload analysis.

## Overview

This project implements a deobfuscation toolkit that:
- Decodes XOR-encrypted data (single-byte and repeating key)
- Unpacks Base64/Base32/Base16 encoded payloads
- Decodes hex-encoded byte sequences
- Extracts and categorizes strings from binary files
- Detects suspicious patterns (shellcode, anti-debug, persistence)
- Performs entropy analysis to identify encrypted regions
- Generates comprehensive deobfuscation reports

## Features

- **XOR Decoding**: Single-byte and repeating-key XOR brute force
- **Base64 Decoding**: Auto-detect and decode Base64/Base32/Base16
- **Hex Decoding**: Decode hex-encoded byte sequences
- **String Extraction**: Categorized string extraction with offset tracking
- **Pattern Detection**: Identify shellcode, anti-debug, persistence mechanisms
- **Entropy Analysis**: Classify data regions by randomness
- **JSON Reports**: Detailed analysis with confidence scores
- **Export**: Save extracted strings and decoded payloads

## Installation

```bash
pip install python-magic
```

## Usage

```bash
# Full analysis
python3 deobfuscator.py suspicious_binary.bin

# Custom output directory
python3 deobfuscator.py malware.exe -o ./deob_output

# XOR only
python3 deobfuscator.py payload.bin --no-base64 --no-hex

# Limit string extraction
python3 deobfuscator.py sample.bin --max-strings 1000
```

## Example Output

```
============================================================
  M3 — Deobfuscation Tool — Report
============================================================
  File:      payload.bin
  Size:      24576 bytes
  Type:      PE executable
  MD5:       abc123...
  SHA256:    def456...
  Entropy:   6.85
------------------------------------------------------------
  Strings:         342
  Decoded:         15
  Suspicious:      4
  Recommendations: 3
------------------------------------------------------------
  Top Strings:
    [url] http://c2server.evil.com/beacon
    [api_call] CreateRemoteThread
    [powershell] powershell -enc SQBmACg...
  Decoded Payloads:
    [XOR single-byte (key=0x37)] confidence=0.92
      Output: VirtualAllocEx...WriteProcessMemory...
============================================================
```

## Architecture

```
m3-deobfuscator/
├── firmware/
│   ├── deobfuscator.py    # Main deobfuscation implementation
│   └── patterns/          # Custom pattern definitions
├── README.md
└── requirements.txt
```

## How It Works

1. **File Analysis**: Compute hashes, entropy, detect file type
2. **String Extraction**: Extract and categorize printable strings
3. **XOR Brute Force**: Try all single-byte keys and repeating-key patterns
4. **Base64 Detection**: Scan for and decode Base64/Base32/Base16 sequences
5. **Hex Decode**: Identify and decode hex-encoded byte sequences
6. **Pattern Matching**: Scan for known suspicious patterns
7. **Report**: Generate JSON report with all findings and recommendations

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the file/system owner before analyzing content
- Reverse engineering of software may violate license agreements
- This tool should ONLY be used on files you own or have written authorization to analyze

### Legal Framework
- **DMCA §1201**: Circumvention of technological protection measures may be illegal
- **CFAA**: Unauthorized access to computer systems is a federal crime
- **EUCD/InfoSoc Directive**: Similar protections in European law
- **Export Controls**: Deobfuscation tools may be subject to export restrictions

### Acceptable Use
- Analyzing malware samples in controlled environments
- Authorized reverse engineering with written scope
- Academic research and security education
- Analyzing your own software

### Prohibited Use
- Reverse engineering commercial software without authorization
- Circumventing copy protection or DRM
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

## License

MIT
