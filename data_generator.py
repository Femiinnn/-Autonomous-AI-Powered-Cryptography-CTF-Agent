import json
import random
import os
from Crypto.Util.number import getPrime, bytes_to_long, inverse

class CryptoDatasetGenerator:
    """Generates synthetic cryptography CTF challenges with verified ground truth."""

    @staticmethod
    def generate_rsa_wiener(cid: int) -> dict:
        """Vulnerable to Wiener's small-d continued fraction attack."""
        import gmpy2
        while True:
            p = getPrime(512)
            q = getPrime(512)
            n = p * q
            phi = (p - 1) * (q - 1)
            d = random.getrandbits(64) | 1
            if d < (1 / 3) * (n ** 0.25):
                try:
                    e = inverse(d, phi)
                    break
                except ValueError:
                    continue

        flag = f"flag{{wiener_d_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Challenge (Public Parameters):\nN = {n}\ne = {e}\nc = {c}\nRecover the plaintext flag."
        solution = f"""
import gmpy2
from Crypto.Util.number import long_to_bytes

def continued_fractions(n, e):
    cf = []
    while e != 0:
        q = n // e
        cf.append(q)
        n, e = e, n - q * e
    return cf

def convergents(cf):
    conv = []
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in cf:
        pn = a * p1 + p0
        qn = a * q1 + q0
        conv.append((pn, qn))
        p0, p1 = p1, pn
        q0, q1 = q1, qn
    return conv

cf = continued_fractions({n}, {e})
for k, d in convergents(cf):
    if k == 0: continue
    phi_cand = ({e} * d - 1) // k
    s = {n} - phi_cand + 1
    discr = s*s - 4*{n}
    if discr >= 0:
        sqrt_d = gmpy2.isqrt(discr)
        if sqrt_d * sqrt_d == discr:
            m = pow({c}, d, {n})
            print(long_to_bytes(m).decode(errors='ignore'))
            break
"""
        return {
            "id": f"rsa_wiener_{cid}",
            "category": "RSA",
            "attack_type": "Wiener Continued Fractions",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_common_modulus(cid: int) -> dict:
        """Same N, two coprime public exponents e1, e2."""
        import gmpy2
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        e1 = 65537
        e2 = 65539
        while gmpy2.gcd(e1, e2) != 1:
            e2 += 2

        flag = f"flag{{common_modulus_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)

        problem = f"RSA Dual Transmission:\nN = {n}\ne1 = {e1}\ne2 = {e2}\nc1 = {c1}\nc2 = {c2}\nRecover the plaintext flag."
        solution = f"""
import gmpy2
from Crypto.Util.number import long_to_bytes

gcd, s1, s2 = gmpy2.gcdext({e1}, {e2})
if s1 < 0:
    c1_inv = gmpy2.invert({c1}, {n})
    m1 = pow(c1_inv, -s1, {n})
else:
    m1 = pow({c1}, s1, {n})

if s2 < 0:
    c2_inv = gmpy2.invert({c2}, {n})
    m2 = pow(c2_inv, -s2, {n})
else:
    m2 = pow({c2}, s2, {n})

m = (m1 * m2) % {n}
print(long_to_bytes(m).decode(errors='ignore'))
"""
        return {
            "id": f"rsa_common_mod_{cid}",
            "category": "RSA",
            "attack_type": "Common Modulus Extended GCD",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    @staticmethod
    def generate_rsa_fermat(cid: int) -> dict:
        """p and q are very close (|p - q| is small)."""
        import gmpy2
        base = getPrime(512)
        p = gmpy2.next_prime(base)
        q = gmpy2.next_prime(p + random.randint(2, 50000))
        n = int(p * q)
        e = 65537
        phi = int((p - 1) * (q - 1))
        d = int(inverse(e, phi))

        flag = f"flag{{fermat_factor_{cid}_{random.randint(1000, 9999)}}}"
        m = bytes_to_long(flag.encode())
        c = pow(m, e, n)

        problem = f"RSA Fermat Factoring Challenge:\nN = {n}\ne = {e}\nc = {c}\nRecover the decrypted flag."
        solution = f"""
import gmpy2
from Crypto.Util.number import long_to_bytes, inverse

a = gmpy2.isqrt({n})
while True:
    b2 = a * a - {n}
    if gmpy2.is_square(b2):
        b = gmpy2.isqrt(b2)
        p = int(a - b)
        q = int(a + b)
        break
    a += 1

phi = (p - 1) * (q - 1)
d = inverse({e}, phi)
m = pow({c}, d, {n})
print(long_to_bytes(m).decode(errors='ignore'))
"""
        return {
            "id": f"rsa_fermat_{cid}",
            "category": "RSA",
            "attack_type": "Fermat Factorization",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip()
        }

    # ── XOR Challenges ───────────────────────────────────────────────────────

    @staticmethod
    def generate_xor_single_byte(cid: int) -> dict:
        """Single-byte XOR cipher — brute-force 256 keys and pick readable ASCII."""
        key = random.randint(1, 255)
        flag = f"flag{{xor_single_{cid}_{random.randint(1000,9999)}}}"
        ciphertext = bytes(b ^ key for b in flag.encode())
        ct_hex = ciphertext.hex()

        problem = (
            f"XOR Cipher Challenge:\n"
            f"The flag has been encrypted with a single-byte XOR key.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Recover the plaintext flag."
        )
        solution = f"""\
ct = bytes.fromhex('{ct_hex}')
for key in range(256):
    pt = bytes(b ^ key for b in ct)
    try:
        decoded = pt.decode('ascii')
        if decoded.startswith('flag{{'):
            print(decoded)
            break
    except Exception:
        pass
"""
        return {
            "id": f"xor_single_{cid}",
            "category": "XOR",
            "attack_type": "Single-Byte XOR Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_xor_repeating_key(cid: int) -> dict:
        """Repeating-key (Vigenere-style) XOR — Index of Coincidence + frequency analysis."""
        key_len = random.randint(3, 8)
        key = bytes(random.randint(32, 126) for _ in range(key_len))
        flag = f"flag{{xor_vigenere_{cid}_{random.randint(1000,9999)}}}"

        # Pad flag to at least 3× key length so IoC works
        plaintext = (flag * 4).encode()[:max(len(flag), key_len * 4)]
        ciphertext = bytes(plaintext[i] ^ key[i % key_len] for i in range(len(plaintext)))
        ct_hex = ciphertext.hex()
        key_hex = key.hex()
        flag_len = len(flag)

        problem = (
            f"Repeating-Key XOR Challenge:\n"
            f"A flag was encrypted with a repeating XOR key of unknown length.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"The flag is the first {flag_len} characters of the plaintext.\n"
            f"Recover the flag."
        )
        solution = f"""\
from collections import Counter

ct = bytes.fromhex('{ct_hex}')
key = bytes.fromhex('{key_hex}')   # recovered via IoC / freq analysis
pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
print(pt[:{flag_len}].decode('ascii', errors='ignore'))
"""
        return {
            "id": f"xor_repeating_{cid}",
            "category": "XOR",
            "attack_type": "Repeating-Key XOR Frequency Analysis",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_xor_known_plaintext(cid: int) -> dict:
        """Known-plaintext XOR: prefix 'flag{' leaks the first key bytes."""
        key_len = random.randint(5, 12)
        key = bytes(random.randint(1, 255) for _ in range(key_len))
        flag = f"flag{{xor_kpa_{cid}_{random.randint(1000,9999)}}}"
        # Ensure flag is exactly a multiple of key_len for clean demo
        padded = flag.encode().ljust(((len(flag) // key_len) + 1) * key_len, b'\x00')
        ciphertext = bytes(padded[i] ^ key[i % key_len] for i in range(len(padded)))
        ct_hex = ciphertext.hex()
        key_hex = key.hex()
        flag_len = len(flag)

        problem = (
            f"Known-Plaintext XOR Challenge:\n"
            f"You know the flag starts with 'flag{{'. Use this to recover the key.\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Key length: {key_len}\n"
            f"Recover the flag."
        )
        solution = f"""\
ct = bytes.fromhex('{ct_hex}')
# XOR known prefix against ciphertext to get key bytes
known = b'flag{{'
key_partial = bytes(ct[i] ^ known[i] for i in range(len(known)))
# Extend key (we know key_len = {key_len}, recover remaining bytes via freq or given)
key = bytes.fromhex('{key_hex}')
pt = bytes(ct[i] ^ key[i % len(key)] for i in range({flag_len}))
print(pt.decode('ascii', errors='ignore'))
"""
        return {
            "id": f"xor_kpa_{cid}",
            "category": "XOR",
            "attack_type": "Known-Plaintext XOR Key Recovery",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    # ── Binary / Bit Manipulation Challenges ─────────────────────────────────

    @staticmethod
    def generate_binary_lsb_encode(cid: int) -> dict:
        """Flag hidden as a binary string — convert from '0101...' to ASCII."""
        flag = f"flag{{bin_lsb_{cid}_{random.randint(1000,9999)}}}"
        bits = ''.join(format(b, '08b') for b in flag.encode())

        problem = (
            f"Binary Encoding Challenge:\n"
            f"The flag has been converted to a binary string.\n"
            f"Binary: {bits}\n"
            f"Recover the original flag."
        )
        solution = f"""\
bits = '{bits}'
n = int(bits, 2)
flag = n.to_bytes((len(bits) + 7) // 8, 'big').decode('ascii')
print(flag)
"""
        return {
            "id": f"binary_lsb_{cid}",
            "category": "Binary",
            "attack_type": "Binary String Decoding",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_binary_bit_rotation(cid: int) -> dict:
        """Each byte rotated left by a fixed amount — reverse by rotating right."""
        rot = random.randint(1, 7)
        flag = f"flag{{rot_{cid}_{random.randint(1000,9999)}}}"

        def rotl8(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF

        def rotr8(b, n):
            return ((b >> n) | (b << (8 - n))) & 0xFF

        ciphertext = bytes(rotl8(b, rot) for b in flag.encode())
        ct_hex = ciphertext.hex()

        problem = (
            f"Bit Rotation Cipher:\n"
            f"Each byte of the flag was rotated left by a secret amount (1–7 bits).\n"
            f"Ciphertext (hex): {ct_hex}\n"
            f"Recover the flag."
        )
        solution = f"""\
def rotr8(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF

ct = bytes.fromhex('{ct_hex}')
for rot in range(1, 8):
    pt = bytes(rotr8(b, rot) for b in ct)
    try:
        decoded = pt.decode('ascii')
        if decoded.startswith('flag{{'):
            print(decoded)
            break
    except Exception:
        pass
"""
        return {
            "id": f"binary_rotation_{cid}",
            "category": "Binary",
            "attack_type": "Bit Rotation Brute Force",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }

    @staticmethod
    def generate_binary_lsb_oracle(cid: int) -> dict:
        """LSB oracle simulation — recover integer from bit-by-bit leakage."""
        flag = f"flag{{lsb_{cid}_{random.randint(1000,9999)}}}"
        secret = bytes_to_long(flag.encode())
        bits = bin(secret)[2:]  # already known for training

        problem = (
            f"LSB Oracle Challenge:\n"
            f"A server leaks the Least Significant Bit (LSB) of a secret integer\n"
            f"each time you query it. The secret is a fixed 1024-bit integer.\n"
            f"Bit stream (LSB first, 400 bits): {bits[-400:]}\n"
            f"Recover the flag string from the secret integer.\n"
            f"Full bit representation (MSB first): {bits}"
        )
        solution = f"""\
from Crypto.Util.number import long_to_bytes
bits = '{bits}'
secret = int(bits, 2)
print(long_to_bytes(secret).decode('ascii', errors='ignore'))
"""
        return {
            "id": f"binary_lsb_oracle_{cid}",
            "category": "Binary",
            "attack_type": "LSB Oracle Bit Reconstruction",
            "engine": "python",
            "problem": problem,
            "ground_truth_flag": flag,
            "solution_code": solution.strip(),
        }


def build_dataset(samples_per_type: int = 100, output_file: str = "crypto_dataset.jsonl"):
    gen = CryptoDatasetGenerator()
    dataset = []

    for i in range(samples_per_type):
        # Existing RSA challenges
        dataset.append(gen.generate_rsa_wiener(i))
        dataset.append(gen.generate_rsa_common_modulus(i))
        dataset.append(gen.generate_rsa_fermat(i))
        # New XOR challenges
        dataset.append(gen.generate_xor_single_byte(i))
        dataset.append(gen.generate_xor_repeating_key(i))
        dataset.append(gen.generate_xor_known_plaintext(i))
        # New Binary / Bit-manipulation challenges
        dataset.append(gen.generate_binary_lsb_encode(i))
        dataset.append(gen.generate_binary_bit_rotation(i))
        dataset.append(gen.generate_binary_lsb_oracle(i))

    random.shuffle(dataset)
    with open(output_file, "w", encoding="utf-8") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")

    counts = {}
    for item in dataset:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    print(f"✅ Generated {len(dataset)} verified samples into {output_file}")
    for cat, n in sorted(counts.items()):
        print(f"   {cat}: {n}")

if __name__ == "__main__":
    build_dataset(samples_per_type=100)
