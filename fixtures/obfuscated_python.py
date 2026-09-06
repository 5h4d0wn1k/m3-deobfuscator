import base64 as _b

# flagged fixture: obfuscated-but-benign python sample
def _unxor(data, key):
    return bytes(b ^ key for b in data)

_payload = _b.b64decode("Njs4dyk7ND44NSJ3OTYzPzQudzM+d2oibTxpOw==")

_api = "api" + "_key"
_host = "127" + ".0.0.1"
_port = 13 * 100 + 37
_decoy = eval("'dec' + 'oy'")

def run(_h=_host):
    return _unxor(_payload, 0x5A)
