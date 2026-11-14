"""
hash_decoder.py — Auto-detect and decode hash / encoding types for the Crypto CTF Agent.

Supports:
  Encodings : Base64, URL-safe Base64, Base32, Base85, Base58, Base62,
              Hexadecimal, Binary, Octal, ROT13, URL-encoding, HTML entities, Morse code
  Hashes    : MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, bcrypt, Argon2,
              NTLM, RIPEMD-160, CRC32, Tiger-192, Whirlpool, and more

Double / multi-layer detection: repeatedly decodes until plaintext or hash is reached.
"""

import re
import base64
import binascii
import urllib.parse
import hashlib
from typing import Optional, List, Dict, Any

# ─── Hash fingerprinting patterns ────────────────────────────────────────────
HASH_PATTERNS: List[tuple] = [
    ("CRC32",          r"^[a-fA-F0-9]{8}$",    "32-bit"),
    ("xxHash64",       r"^[a-fA-F0-9]{16}$",   "64-bit"),
    ("MD5",            r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("NTLM",           r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("MD4",            r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("LM Hash",        r"^[a-fA-F0-9]{32}$",   "128-bit"),
    ("SHA-1",          r"^[a-fA-F0-9]{40}$",   "160-bit"),
    ("RIPEMD-160",     r"^[a-fA-F0-9]{40}$",   "160-bit"),
    ("Tiger-192",      r"^[a-fA-F0-9]{48}$",   "192-bit"),
    ("SHA-224",        r"^[a-fA-F0-9]{56}$",   "224-bit"),
    ("SHA3-224",       r"^[a-fA-F0-9]{56}$",   "224-bit"),
    ("SHA-256",        r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("SHA3-256",       r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("HAVAL-256",      r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("GOST R 34.11",   r"^[a-fA-F0-9]{64}$",   "256-bit"),
    ("SHA-384",        r"^[a-fA-F0-9]{96}$",   "384-bit"),
    ("SHA3-384",       r"^[a-fA-F0-9]{96}$",   "384-bit"),
    ("SHA-512",        r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("SHA3-512",       r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("Whirlpool",      r"^[a-fA-F0-9]{128}$",  "512-bit"),
    ("bcrypt",         r"^\$2[aby]?\$\d{2}\$.{53}$", "bcrypt"),
    ("Argon2",         r"^\$argon2",            "argon2"),
    ("scrypt",         r"^\$s0\$",              "scrypt"),
]

# ─── Morse code table ─────────────────────────────────────────────────────────
MORSE_TO_CHAR: Dict[str, str] = {
    '.-': 'A', '-.': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?',
    '-..-.': '/', '---...': ':',
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _safe_decode_bytes(b: bytes) -> Optional[str]:
    """Attempt UTF-8 decode, return None if result contains non-printable chars."""
    try:
        s = b.decode('utf-8')
        if all(c.isprintable() or c in '\n\r\t' for c in s):
            return s
        return None
    except Exception:
        return None


def _try_base64(s: str) -> Optional[str]:
    s = s.strip()
    padded = s + '=' * (-len(s) % 4)
    for variant in [padded, s]:
        try:
            decoded = base64.b64decode(variant, validate=True)
            result = _safe_decode_bytes(decoded)
            if result:
                return result
        except Exception:
            pass
    # URL-safe variant
    try:
        decoded = base64.urlsafe_b64decode(padded)
        result = _safe_decode_bytes(decoded)
        if result:
            return result
    except Exception:
        pass
    return None


def _try_base32(s: str) -> Optional[str]:
    s = s.strip().upper()
    padded = s + '=' * (-len(s) % 8)
    try:
        decoded = base64.b32decode(padded)
        return _safe_decode_bytes(decoded)
    except Exception:
        return None


def _try_base85(s: str) -> Optional[str]:
    s = s.strip()
    if len(s) < 5:
        return None
    try:
        decoded = base64.b85decode(s)
        return _safe_decode_bytes(decoded)
    except Exception:
        return None


def _try_base58(s: str) -> Optional[str]:
    """Bitcoin-style Base58 decode."""
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    s = s.strip()
    if not s or not all(c in ALPHABET for c in s):
        return None
    try:
        n = 0
        for char in s:
            n = n * 58 + ALPHABET.index(char)
        result_bytes = []
        while n > 0:
            result_bytes.append(n % 256)
            n //= 256
        leading_zeros = len(s) - len(s.lstrip('1'))
        result_bytes.extend([0] * leading_zeros)
        b = bytes(reversed(result_bytes))
        return _safe_decode_bytes(b)
    except Exception:
        return None


def _try_hex(s: str) -> Optional[str]:
    s = s.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    if not re.match(r'^[0-9a-fA-F]+$', s):
        return None
    if len(s) % 2 != 0:
        return None
    try:
        decoded = binascii.unhexlify(s)
        return _safe_decode_bytes(decoded)
    except Exception:
        return None


def _try_binary(s: str) -> Optional[str]:
    cleaned = s.strip().replace(' ', '')
    if not re.match(r'^[01]+$', cleaned):
        return None
    if len(cleaned) % 8 != 0:
        return None
    try:
        chars = [chr(int(cleaned[i:i+8], 2)) for i in range(0, len(cleaned), 8)]
        result = ''.join(chars)
        if all(c.isprintable() or c in '\n\r\t' for c in result):
            return result
        return None
    except Exception:
        return None


def _try_octal(s: str) -> Optional[str]:
    parts = s.strip().split()
    if len(parts) < 2:
        return None
    if not all(re.match(r'^[0-7]+$', p) for p in parts):
        return None
    try:
        chars = [chr(int(p, 8)) for p in parts]
        result = ''.join(chars)
        if all(c.isprintable() or c in '\n\r\t' for c in result):
            return result
        return None
    except Exception:
        return None


COMMON_ENGLISH_WORDS = {
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
    'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
    'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy',
    'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use', 'flag', 'ctf',
    'hello', 'world', 'secret', 'password', 'encode', 'decode', 'crypto',
}

def _is_more_english(decoded: str, original: str) -> bool:
    """Return True only if decoded has more common English word hits than original."""
    words_decoded = set(re.findall(r'[a-z]+', decoded.lower()))
    words_original = set(re.findall(r'[a-z]+', original.lower()))
    hits_decoded = len(words_decoded & COMMON_ENGLISH_WORDS)
    hits_original = len(words_original & COMMON_ENGLISH_WORDS)
    return hits_decoded > hits_original


def _try_rot13(s: str) -> Optional[str]:
    result = s.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))
    if result != s and any(c.isalpha() for c in result) and _is_more_english(result, s):
        return result
    return None


def _try_url(s: str) -> Optional[str]:
    decoded = urllib.parse.unquote(s)
    if decoded != s:
        return decoded
    return None


def _try_html_entities(s: str) -> Optional[str]:
    import html
    decoded = html.unescape(s)
    if decoded != s:
        return decoded
    return None


def _try_morse(s: str) -> Optional[str]:
    s = s.strip()
    if not re.match(r'^[.\- /]+$', s):
        return None
    words = s.split('  ')
    try:
        result = ' '.join(
            ''.join(MORSE_TO_CHAR.get(c, '?') for c in word.split(' ') if c)
            for word in words
        )
        if '?' not in result and result.strip():
            return result
        return None
    except Exception:
        return None


def _try_base62(s: str) -> Optional[str]:
    CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    s = s.strip()
    if not s or not all(c in CHARS for c in s):
        return None
    try:
        n = 0
        for c in s:
            n = n * 62 + CHARS.index(c)
        result_bytes = []
        while n > 0:
            result_bytes.append(n % 256)
            n //= 256
        b = bytes(reversed(result_bytes))
        return _safe_decode_bytes(b)
    except Exception:
        return None


# ─── Hash detection ───────────────────────────────────────────────────────────

def _detect_hash_algorithms(s: str) -> List[Dict[str, str]]:
    """Return list of possible hash algorithms matching this string."""
    s = s.strip()
    matches = []
    seen: set = set()
    for name, pattern, bits in HASH_PATTERNS:
        if re.match(pattern, s) and name not in seen:
            seen.add(name)
            matches.append({"algorithm": name, "bits": bits})
    return matches


# ─── Encoding detector pipeline ──────────────────────────────────────────────

def _is_base64_candidate(s: str) -> bool:
    s = s.strip()
    if len(s) < 4:
        return False
    return bool(re.match(r'^[A-Za-z0-9+/\-_]+=*$', s)) and len(s) % 4 in [0, 2, 3]


def _is_base32_candidate(s: str) -> bool:
    s = s.strip().upper()
    if len(s) < 8:
        return False
    return bool(re.match(r'^[A-Z2-7=]+$', s))


def _is_hex_candidate(s: str) -> bool:
    cleaned = s.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    return bool(re.match(r'^[0-9a-fA-F]+$', cleaned)) and len(cleaned) % 2 == 0 and len(cleaned) >= 4


def _is_binary_candidate(s: str) -> bool:
    cleaned = s.strip().replace(' ', '')
    return bool(re.match(r'^[01]+$', cleaned)) and len(cleaned) % 8 == 0 and len(cleaned) >= 8


def _is_octal_candidate(s: str) -> bool:
    parts = s.strip().split()
    return len(parts) >= 2 and all(re.match(r'^[0-7]+$', p) for p in parts)


def _is_morse_candidate(s: str) -> bool:
    return bool(re.match(r'^[.\- /]+$', s.strip())) and len(s.strip()) >= 3


def _is_base58_candidate(s: str) -> bool:
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    s = s.strip()
    return len(s) >= 4 and all(c in ALPHABET for c in s)


def _is_base62_candidate(s: str) -> bool:
    CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    s = s.strip()
    return len(s) >= 4 and all(c in CHARS for c in s)


# Ordered by specificity (most reliable first)
ENCODING_DETECTORS = [
    ("Morse Code",      _is_morse_candidate,   _try_morse),
    ("Hexadecimal",     _is_hex_candidate,     _try_hex),
    ("Binary",          _is_binary_candidate,  _try_binary),
    ("Octal",           _is_octal_candidate,   _try_octal),
    ("Base32",          _is_base32_candidate,  _try_base32),
    ("Base64",          _is_base64_candidate,  _try_base64),
    ("Base85",          lambda s: len(s.strip()) >= 5, _try_base85),
    ("Base58",          _is_base58_candidate,  _try_base58),
    ("Base62",          _is_base62_candidate,  _try_base62),
    ("URL Encoding",    lambda s: '%' in s,    _try_url),
    ("HTML Entities",   lambda s: '&' in s and ';' in s, _try_html_entities),
]


# ─── Single-layer analysis ────────────────────────────────────────────────────

def _detect_single_layer(text: str) -> Dict[str, Any]:
    """
    Detect encoding/hash type for one layer of text.
    Returns a dict with keys:
        type, encoding, decoded, is_hash, hash_algorithms, confidence, raw
    """
    text = text.strip()
    result: Dict[str, Any] = {
        "type": "unknown",
        "encoding": None,
        "decoded": None,
        "is_hash": False,
        "hash_algorithms": [],
        "confidence": "low",
        "raw": text,
    }

    is_pure_hex = bool(re.match(r'^[a-fA-F0-9]+$', text))
    hash_algos = _detect_hash_algorithms(text) if is_pure_hex else []

    # Try each encoding in order
    for enc_name, condition, decoder in ENCODING_DETECTORS:
        try:
            if not condition(text):
                continue
            decoded = decoder(text)
            if decoded and decoded != text:
                # For hex strings that also match hash lengths: prefer decode if output is printable
                result["type"] = "encoding"
                result["encoding"] = enc_name
                result["decoded"] = decoded
                result["confidence"] = "high"
                # Still annotate possible hash matches
                if hash_algos:
                    result["possible_hash_algorithms"] = hash_algos
                return result
        except Exception:
            continue

    # Pure hash (hex that couldn't be decoded to printable text)
    if hash_algos and is_pure_hex:
        result["type"] = "hash"
        result["encoding"] = "Hash (non-reversible)"
        result["is_hash"] = True
        result["hash_algorithms"] = hash_algos
        result["decoded"] = None
        result["confidence"] = "high"
        return result

    # ROT13 — always produces output, so apply last
    decoded_rot13 = _try_rot13(text)
    if decoded_rot13 and decoded_rot13 != text:
        result["type"] = "encoding"
        result["encoding"] = "ROT13"
        result["decoded"] = decoded_rot13
        result["confidence"] = "medium"
        return result

    # Plaintext fallback
    result["type"] = "plaintext"
    result["encoding"] = "None (plaintext)"
    result["decoded"] = text
    result["confidence"] = "medium"
    return result


# ─── Public API ───────────────────────────────────────────────────────────────

def analyze_hash_or_encoding(text: str, max_layers: int = 5) -> Dict[str, Any]:
    """
    Full multi-layer encoding/hash analysis.

    Returns:
    {
        "original": str,
        "is_double_encoded": bool,
        "encoding_layers": [ { layer, type, encoding, decoded, is_hash,
                                hash_algorithms, confidence, raw }, ... ],
        "final_decoded": str | None,
        "total_layers": int,
        "summary": str
    }
    """
    original = text.strip()
    layers: List[Dict[str, Any]] = []
    current = original
    seen_texts: set = {current}

    for layer_num in range(1, max_layers + 1):
        analysis = _detect_single_layer(current)
        analysis["layer"] = layer_num
        layers.append(analysis)

        # Stop on plaintext, hash, or unknown
        if analysis["type"] in ("plaintext", "hash", "unknown"):
            break

        decoded = analysis.get("decoded")
        if not decoded or decoded == current:
            break

        # Loop guard
        if decoded in seen_texts:
            break
        seen_texts.add(decoded)
        current = decoded

        # Check if next iteration would be plaintext — add it and stop
        next_check = _detect_single_layer(current)
        if next_check["type"] in ("plaintext", "unknown"):
            next_check["layer"] = layer_num + 1
            layers.append(next_check)
            break

    encoding_layer_count = sum(1 for l in layers if l.get("type") == "encoding")
    is_double_encoded = encoding_layer_count >= 2

    # Find final decoded value
    final_decoded: Optional[str] = None
    for l in reversed(layers):
        if l.get("decoded"):
            final_decoded = l["decoded"]
            break

    # Build summary
    encoding_names = [l["encoding"] for l in layers if l.get("type") == "encoding"]
    hash_algos_flat: List[str] = []
    for l in layers:
        for a in (l.get("hash_algorithms") or []):
            algo = a.get("algorithm", "") if isinstance(a, dict) else str(a)
            if algo not in hash_algos_flat:
                hash_algos_flat.append(algo)

    if hash_algos_flat:
        summary = f"Hash detected — possible algorithms: {', '.join(hash_algos_flat[:3])} (non-reversible)"
    elif is_double_encoded:
        summary = f"Double-encoded: {' → '.join(encoding_names)} → plaintext"
    elif encoding_names:
        preview = (final_decoded or '')[:80]
        summary = f"Encoded as {encoding_names[0]} → decoded: {preview}"
    elif layers and layers[0].get("type") == "plaintext":
        summary = "Plaintext — no encoding detected"
    else:
        summary = "Unknown encoding or format"

    return {
        "original": original,
        "is_double_encoded": is_double_encoded,
        "encoding_layers": layers,
        "final_decoded": final_decoded,
        "total_layers": len(layers),
        "summary": summary,
    }


def extract_encoded_strings(challenge_text: str) -> List[Dict[str, Any]]:
    """
    Scan challenge text for suspicious encoded/hashed substrings.
    Returns list of analysis dicts (only interesting ones).
    """
    candidates: set = set()

    # Quoted strings
    for m in re.finditer(r'"([^"]{4,})"', challenge_text):
        candidates.add(m.group(1))
    for m in re.finditer(r"'([^']{4,})'", challenge_text):
        candidates.add(m.group(1))

    # Long hex blobs (hashes or hex-encoded data)
    for m in re.finditer(r'\b([a-fA-F0-9]{16,})\b', challenge_text):
        candidates.add(m.group(1))

    # Base64-looking chunks
    for m in re.finditer(r'([A-Za-z0-9+/]{20,}={0,2})', challenge_text):
        candidates.add(m.group(1))

    # The whole challenge text
    candidates.add(challenge_text.strip())

    results: List[Dict[str, Any]] = []
    seen_originals: set = set()
    for cand in candidates:
        cand = cand.strip()
        if cand in seen_originals or len(cand) < 4:
            continue
        seen_originals.add(cand)
        analysis = analyze_hash_or_encoding(cand)
        # Only keep if something interesting was found
        if analysis["encoding_layers"] and analysis["encoding_layers"][0].get("type") not in ("plaintext", "unknown"):
            results.append(analysis)

    return results


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import base64 as _b64

    tests = [
        ("Base64 → plain",          _b64.b64encode(b"hello world").decode()),
        ("Hex → plain",             b"hello world".hex()),
        ("MD5 hash",                hashlib.md5(b"hello").hexdigest()),
        ("SHA-256 hash",            hashlib.sha256(b"hello").hexdigest()),
        ("Base32",                  base64.b32encode(b"Hello World").decode()),
        ("Double Base64",           _b64.b64encode(_b64.b64encode(b"flag{test}")).decode()),
        ("Base64 of hex",           _b64.b64encode(b"deadbeef").decode()),
        ("ROT13",                   "uryyb jbeyq"),
        ("Binary",                  ' '.join(format(c, '08b') for c in b"hi")),
        ("Morse",                   ".... . .-.. .-.. ---  .-- --- .-. .-.. -.."),
        ("URL encoded",             "hello%20world%21"),
        ("Plaintext",               "This is just plain text, nothing encoded."),
    ]

    print("=" * 70)
    print("🔎 hash_decoder.py — Self-test")
    print("=" * 70)
    all_pass = True
    for label, t in tests:
        r = analyze_hash_or_encoding(t)
        status = "✅" if r["encoding_layers"] else "⚠️"
        print(f"\n{status} [{label}]")
        print(f"   Input   : {t[:60]}{'…' if len(t)>60 else ''}")
        print(f"   Summary : {r['summary']}")
        print(f"   Layers  : {r['total_layers']}  |  Double: {r['is_double_encoded']}")
        print(f"   Decoded : {str(r['final_decoded'])[:80]}")
    print("\n" + "=" * 70)
    print("Self-test complete.")
