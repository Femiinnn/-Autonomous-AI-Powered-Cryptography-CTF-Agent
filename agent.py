import os
import re
from typing import TypedDict, Optional
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from sandbox import DockerCryptoSandbox

# Load environment variables if .env is present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- Configuration ---
# Point to your local or cloud Llama-3 instance (Ollama, vLLM, LM Studio, or Groq)
LLAMA3_API_BASE = os.getenv("LLAMA3_API_BASE", "http://localhost:8000/v1")
LLAMA3_API_KEY = os.getenv("LLAMA3_API_KEY", "EMPTY")
LLAMA3_MODEL_NAME = os.getenv("LLAMA3_MODEL_NAME", "meta-llama/Meta-Llama-3.1-8B-Instruct")

sandbox = DockerCryptoSandbox(image="crypto-sandbox:latest", timeout=30)

llm = ChatOpenAI(
    model=LLAMA3_MODEL_NAME,
    openai_api_base=LLAMA3_API_BASE,
    openai_api_key=LLAMA3_API_KEY,
    temperature=0.1,
    max_tokens=2048
)

# --- State Definition ---
class CryptoAgentState(TypedDict):
    challenge: str
    category: Optional[str]
    attack_hypothesis: Optional[str]
    is_sage: bool
    generated_code: Optional[str]
    execution_stdout: Optional[str]
    execution_stderr: Optional[str]
    captured_flag: Optional[str]
    iteration: int
    max_retries: int
    # ── New: Hash / Encoding Analysis ──────────────────────────────
    hash_analysis: Optional[dict]   # full report from hash_decoder


# ── Hash / Encoding Detection Node ──────────────────────────────────────────
def detect_hash_or_encoding(state: CryptoAgentState) -> dict:
    """
    Pre-processing node: scans the challenge for encoded / hashed strings,
    decodes them, checks for double-encoding, and stores the analysis in state.
    This runs BEFORE the main classify node so its findings are available
    to the LLM as extra context.
    """
    print("\n🔎 [Pre-Step] Scanning for Hash / Encoding patterns…")
    try:
        from hash_decoder import analyze_hash_or_encoding, extract_encoded_strings
        challenge = state["challenge"]

        # 1. Analyse the whole challenge text
        full_analysis = analyze_hash_or_encoding(challenge)

        # 2. Also try to extract individual encoded substrings
        sub_analyses = extract_encoded_strings(challenge)

        analysis = {
            "full": full_analysis,
            "substrings": sub_analyses[:5],   # cap at 5 candidates
        }

        # Pretty-print summary
        summary = full_analysis.get("summary", "")
        total_layers = full_analysis.get("total_layers", 0)
        is_double = full_analysis.get("is_double_encoded", False)
        final_decoded = full_analysis.get("final_decoded", "")

        print(f"  📊 Summary      : {summary}")
        print(f"  🔢 Layers       : {total_layers}")
        print(f"  🔁 Double-enc   : {'Yes ⚠️' if is_double else 'No'}")
        if final_decoded and final_decoded != challenge.strip():
            print(f"  ✅ Decoded      : {final_decoded[:120]}")

        # Emit extra context for substring hits
        for idx, sub in enumerate(sub_analyses[:3], 1):
            print(f"  🔍 Substring #{idx}: [{sub['encoding_layers'][0]['encoding']}] "
                  f"→ {(sub.get('final_decoded') or '')[:80]}")

    except Exception as e:
        print(f"  ⚠️ Hash/Encoding detection error: {e}")
        analysis = {"full": {}, "substrings": [], "error": str(e)}

    return {"hash_analysis": analysis}


# --- Nodes ---
def classify_and_plan(state: CryptoAgentState) -> dict:
    attempt_num = state.get('iteration', 0)
    print(f"\n🔍 [Step 1] Classifying challenge (Pass {attempt_num + 1})...")

    previous_failure = ""
    if state.get("execution_stderr"):
        previous_failure = f"\nNote: The previous hypothesis '{state.get('attack_hypothesis')}' failed with error:\n{state.get('execution_stderr')}\nRe-evaluate parameters and choose an ALTERNATIVE attack."

    # Inject hash/encoding findings as extra context for the LLM
    hash_ctx = ""
    ha = state.get("hash_analysis") or {}
    full_ha = ha.get("full") or {}
    if full_ha.get("summary"):
        hash_ctx = f"\n[Hash/Encoding Pre-Analysis]\n{full_ha['summary']}"
        layers = full_ha.get("encoding_layers") or []
        if layers:
            for layer in layers:
                enc = layer.get("encoding", "")
                decoded = layer.get("decoded", "")
                is_hash = layer.get("is_hash", False)
                algos = layer.get("hash_algorithms", [])
                if is_hash and algos:
                    hash_ctx += f"\n  - Hash detected: possible algorithms: {', '.join(a['algorithm'] for a in algos[:3])}"
                elif decoded:
                    hash_ctx += f"\n  - Layer {layer.get('layer','')} [{enc}] decoded: {decoded[:100]}"
        if full_ha.get("is_double_encoded"):
            hash_ctx += "\n  ⚠️  DOUBLE ENCODING DETECTED — multiple decode passes required."
        for sub in (ha.get("substrings") or [])[:2]:
            fd = sub.get("final_decoded", "")
            enc0 = (sub.get("encoding_layers") or [{}])[0].get("encoding", "")
            if fd:
                hash_ctx += f"\n  - Extracted [{enc0}] substring decoded: {fd[:80]}"

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are an expert cryptographic security auditor and CTF player.
Analyze the given parameters and determine the vulnerability.

Key CTF Rules of Thumb:
RSA:
- If e is very large (hundreds of digits, comparable to N): Vulnerable to Wiener's Continued Fractions attack (small private exponent d < (1/3)*N^0.25) or Boneh-Durfee.
- If |p - q| is small: Fermat Factorization (a = isqrt(N)).
- If e is very small (e=3): Small public exponent / cube root attack.
- If multiple (e1, c1) and (e2, c2) share modulus N: Common modulus extended GCD.
XOR:
- If ciphertext XOR'd with a repeating or single-byte key: use frequency analysis or brute-force key.
- If two ciphertexts share the same key (many-time pad): XOR them together to cancel the key, then crib-drag.
- If a known plaintext prefix exists (e.g. "flag{{"): XOR it against ciphertext to recover key bytes.
- If key length is unknown: use Index of Coincidence or Kasiski test to find key length, then frequency analysis.
Binary / Bit Manipulation:
- If challenge involves LSB (Least Significant Bit) manipulation: reconstruct value bit by bit via oracle.
- If challenge involves bitwise rotation or permutation: reverse the bit operations.
- If data is encoded in binary strings or bit arrays: use int(bits, 2) and bitwise ops to decode.
- If challenge uses bit-shift cipher or custom binary encoding: reverse the shift/XOR sequence.
Hash / Encoding:
- If input is Base64, Hex, ROT13, Binary, Octal, URL-encoded, Morse, Base32, Base58, Base62, or Base85: decode it.
- If double-encoded: apply decoding twice (or more) in correct order.
- If input is a hash (MD5/SHA1/SHA256/SHA512/bcrypt etc): identify algorithm and attempt hash cracking or rainbow table lookup in generated code.
General:
- If SageMath is unavailable: Implement the attack in standard Python 3 using gmpy2, sympy, or pycryptodome.<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Challenge:
{state['challenge']}
{hash_ctx}
{previous_failure}

Analyze:
1. Category (RSA, AES, ECC, Lattice, PRNG, Hash, XOR, Binary, Encoding)
2. Underlying Mathematical Flaw / Attack
3. Engine: "python" or "sage"

Format:
CATEGORY: <category>
ATTACK: <attack name>
ENGINE: <python or sage>
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    resp = llm.invoke([HumanMessage(content=prompt)]).content

    cat_match = re.search(r"CATEGORY:\s*(.*)", resp, re.IGNORECASE)
    att_match = re.search(r"ATTACK:\s*(.*)", resp, re.IGNORECASE)
    eng_match = re.search(r"ENGINE:\s*(.*)", resp, re.IGNORECASE)

    is_sage = bool(eng_match and "sage" in eng_match.group(1).lower())
    attack = att_match.group(1).strip() if att_match else "Direct Computation"
    cat = cat_match.group(1).strip() if cat_match else "Crypto"

    print(f"🎯 Category: {cat} | Attack: {attack} | Engine: {'SageMath' if is_sage else 'Python'}")

    return {
        "category": cat,
        "attack_hypothesis": attack,
        "is_sage": is_sage,
        "iteration": state.get("iteration", 0),
        "max_retries": 4
    }

def extract_clean_code(resp: str) -> str:
    """Robustly extracts executable code from LLM responses."""
    code_match = re.search(r"```(?:python|sage)?\s*\n(.*?)(?:```|$)", resp, re.DOTALL | re.IGNORECASE)
    raw = code_match.group(1) if code_match else resp
    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("```") or stripped.endswith("```"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()

def generate_solver(state: CryptoAgentState) -> dict:
    print(f"\n⚙️ [Step 2] Generating exploit script (Attempt {state.get('iteration', 0) + 1}/{state['max_retries']})...")
    feedback = ""
    if state.get("execution_stderr"):
        feedback = f"\nPrevious attempt failed:\n[STDERR]: {state['execution_stderr']}\n[STDOUT]: {state.get('execution_stdout', '')}\nFix the logic or syntax error."

    engine_name = "SageMath (.sage)" if state.get("is_sage") else "Python 3 (.py)"

    # Inject hash analysis hints into the solver prompt
    hash_hint = ""
    ha = state.get("hash_analysis") or {}
    full_ha = ha.get("full") or {}
    if full_ha.get("summary") and full_ha.get("encoding_layers"):
        layers = full_ha["encoding_layers"]
        enc_steps = []
        for layer in layers:
            enc = layer.get("encoding", "")
            decoded = layer.get("decoded", "")
            is_hash = layer.get("is_hash", False)
            algos = layer.get("hash_algorithms", [])
            if is_hash and algos:
                enc_steps.append(f"Hash ({', '.join(a['algorithm'] for a in algos[:2])}) — crack or lookup")
            elif decoded:
                enc_steps.append(f"Decode {enc}")
        if enc_steps:
            hash_hint = f"\n[Encoding/Hash Hint] Required decode steps: {' → '.join(enc_steps)}"
            if full_ha.get("is_double_encoded"):
                hash_hint += "\n⚠️ This is DOUBLE ENCODED — apply decoding in the correct sequence."
            fd = full_ha.get("final_decoded", "")
            if fd and fd != state["challenge"].strip():
                hash_hint += f"\nPre-decoded value available: {fd[:200]}"

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are a solver generator for cryptographic CTFs.
Write a standalone, self-contained {engine_name} script that executes the exploit and prints the flag.
Return ONLY valid executable code inside a single ```python or ```sage block.<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Challenge:
{state['challenge']}

Attack Strategy: {state.get('attack_hypothesis')}
{hash_hint}
{feedback}

Output the code block:
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    resp = llm.invoke([HumanMessage(content=prompt)]).content
    code = extract_clean_code(resp)

    return {"generated_code": code}

def execute_in_docker(state: CryptoAgentState) -> dict:
    print("🚀 [Step 3] Executing solver in sandbox...")
    code = state["generated_code"]
    
    # Only use sage if explicitly requested and has import sage or sage commands, not substring of 'message'
    has_sage_keyword = bool(re.search(r"\b(import\s+sage|from\s+sage|IntegerRing|PolynomialRing|Zmod)\b", code))
    is_sage = state.get("is_sage", False) and has_sage_keyword

    res = sandbox.execute(code=code, is_sage=is_sage, allow_network=False)
    stdout = res["stdout"]
    stderr = res["stderr"]

    if stdout.strip():
        print(f"📄 Output:\n{stdout.strip()}")
    if stderr.strip():
        print(f"⚠️ Error:\n{stderr.strip()}")

    flag_match = re.search(r"(flag\{.*?\}|CTF\{.*?\})", stdout, re.IGNORECASE)
    flag = flag_match.group(1) if flag_match else None

    if flag:
        print(f"🚩 FLAG CAPTURED: {flag}")
    else:
        print("❌ No flag captured on this attempt.")

    return {
        "execution_stdout": stdout,
        "execution_stderr": stderr if (res["exit_code"] != 0 or not flag) else "",
        "captured_flag": flag,
        "iteration": state["iteration"] + 1
    }

def evaluation_router(state: CryptoAgentState) -> str:
    if state.get("captured_flag"):
        return END
    if state["iteration"] >= state["max_retries"]:
        return END
    if state["iteration"] == 2:
        # Re-evaluate hypothesis if previous attempts hit a dead end
        return "classify"
    return "generate_solver"

# --- Graph Assembly ---
builder = StateGraph(CryptoAgentState)
builder.add_node("hash_detect",    detect_hash_or_encoding)   # ← NEW pre-step
builder.add_node("classify",       classify_and_plan)
builder.add_node("generate_solver",generate_solver)
builder.add_node("execute_docker", execute_in_docker)

builder.set_entry_point("hash_detect")                        # ← starts here now
builder.add_edge("hash_detect",    "classify")                # ← then classify
builder.add_edge("classify",       "generate_solver")
builder.add_edge("generate_solver","execute_docker")
builder.add_conditional_edges("execute_docker", evaluation_router, {
    "generate_solver": "generate_solver",
    "classify":        "classify",
    END:               END
})

crypto_solver_agent = builder.compile()

if __name__ == "__main__":
    from data_generator import CryptoDatasetGenerator
    challenge_data = CryptoDatasetGenerator.generate_rsa_fermat(42)
    print("=" * 60)
    print("🎯 Target Challenge:")
    print(challenge_data["problem"])
    print("🔑 Expected Flag:", challenge_data["ground_truth_flag"])
    print("=" * 60)

    initial_state = {"challenge": challenge_data["problem"]}
    result = crypto_solver_agent.invoke(initial_state)
    print("\n" + "=" * 60)
    print("🏆 Final Result:", result.get("captured_flag") or "Failed to solve within retry limit")
    print("=" * 60)
