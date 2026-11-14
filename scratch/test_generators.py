import io, sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from data_generator import CryptoDatasetGenerator

gen = CryptoDatasetGenerator()

tests = [
    ('XOR Single-byte',   gen.generate_xor_single_byte),
    ('XOR Repeating',     gen.generate_xor_repeating_key),
    ('XOR KPA',           gen.generate_xor_known_plaintext),
    ('Binary Encode',     gen.generate_binary_lsb_encode),
    ('Binary Rotation',   gen.generate_binary_bit_rotation),
    ('Binary LSB Oracle', gen.generate_binary_lsb_oracle),
]

passed = 0
failed = 0

for name, fn in tests:
    item = fn(99)
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        exec(item['solution_code'], {})
    except Exception as e:
        sys.stdout = old_stdout
        print(f'FAIL [{name}]: {e}')
        failed += 1
        continue
    sys.stdout = old_stdout
    output = buf.getvalue().strip()
    expected = item['ground_truth_flag']
    if expected in output:
        print(f'PASS [{name}]: {output}')
        passed += 1
    else:
        print(f'FAIL [{name}]: expected={expected!r}, got={output[:80]!r}')
        failed += 1

print(f'\n{passed} passed, {failed} failed')
