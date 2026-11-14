<div align="center">

# 🔐 Crypto CTF Agent

### An Autonomous Cryptanalysis Agent powered by LangGraph, Llama-3, and a Dockerized SageMath Sandbox

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2%2B-orange)](https://github.com/langchain-ai/langgraph)
[![Llama-3](https://img.shields.io/badge/Llama--3.1-8B%20Instruct-purple?logo=meta)](https://llama.meta.com/)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-blue?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 🎯 Aim

**Crypto CTF Agent** is a fully autonomous AI system designed to **identify and exploit cryptographic vulnerabilities** in Capture The Flag (CTF) competition challenges — without human intervention.

Given a raw challenge description (problem statement, ciphertext, public parameters), the agent will:

1. **Classify** the cryptographic category and pinpoint the underlying mathematical flaw
2. **Generate** a targeted exploit script in Python or SageMath
3. **Execute** the script inside an isolated Docker sandbox
4. **Recover and return** the hidden flag (`flag{...}`)

The agent is built on a **reinforcement learning foundation**: a GRPO (Group Relative Policy Optimization) fine-tuning pipeline trains Llama-3 to solve challenges with verifiable Docker execution rewards — no human-annotated preference data needed.

> The core insight is treating **code execution correctness as a reward signal** — if the Docker sandbox extracts the flag, the model's reasoning is rewarded; if it crashes, the error is fed back for self-correction.

---

## 🏗️ Architecture

The agent is a **LangGraph state machine** with three nodes arranged in a self-correcting retry loop:

```
 ┌─────────────────────────────────────────────────────────┐
 │                   CryptoAgentState                      │
 │   challenge · category · attack · is_sage               │
 │   generated_code · stdout · stderr · flag · iteration   │
 └─────────────────────────────────────────────────────────┘
            │
            ▼
  ┌──────────────────┐
  │  1. classify     │  ◄──────────────────────────┐
  │  Llama-3 reads   │                             │ re-classify
  │  challenge,      │                             │ (iteration==2)
  │  picks attack    │                             │
  └────────┬─────────┘                             │
           │                                       │
           ▼                                       │
  ┌──────────────────┐       error/retry           │
  │  2. generate     │ ◄───────────────────────────┤
  │  Llama-3 writes  │                             │
  │  exploit code    │                             │
  └────────┬─────────┘                             │
           │                                       │
           ▼                                       │
  ┌──────────────────┐                             │
  │  3. execute      │                             │
  │  DockerSandbox   │                             │
  │  runs the script │                             │
  └────────┬─────────┘                             │
           │                                       │
           ▼                                       │
    ┌─────────────┐    flag found      ┌──────┐    │
    │  evaluation │ ─────────────────► │  END │    │
    │  router     │    max retries     └──────┘    │
    └─────────────┘ ─────────────────► END         │
           │                                       │
           └───────────────────────────────────────┘
```

### Node Details

#### `classify_and_plan`
- Sends the challenge text to **Llama-3** (Llama-3.1-8B-Instruct) using an expert cryptanalysis system prompt
- Extracts: `CATEGORY`, `ATTACK`, `ENGINE` (python or sage)
- On retry: injects the previous error and failed hypothesis as negative context so the model picks an alternative strategy

#### `generate_solver`
- Sends the challenge + attack strategy to Llama-3 and requests a **standalone executable exploit script**
- Cleans and extracts code from the markdown code block response
- On retry: attaches `[STDERR]` and `[STDOUT]` from the failed run as feedback

#### `execute_in_docker`
- Calls `DockerCryptoSandbox.execute()` which runs the script in an **ephemeral Docker container** with:
  - `--network=none` (no internet access)
  - `--memory=1g` and `--cpus=1.5` limits
  - 30-second timeout
  - Native Python fallback if Docker is unavailable
- Scans stdout for `flag{...}` or `CTF{...}` patterns

#### Evaluation Router
| Condition | Action |
|---|---|
| `flag` found | → `END` ✅ |
| `iteration == 2` (stuck) | → `classify` (rethink attack) |
| `iteration < max_retries` | → `generate_solver` (fix code) |
| `iteration >= 4` | → `END` ❌ |

---

## 🔓 Supported Cryptographic Attacks

| Attack | Trigger Condition | Engine |
|---|---|---|
| **Wiener Continued Fractions** | `e` is very large (small private `d`) | Python + gmpy2 |
| **Fermat Factorization** | `p ≈ q` (primes are close together) | Python + gmpy2 |
| **Common Modulus (Extended GCD)** | Same `N`, two `(e₁,c₁)` and `(e₂,c₂)` pairs | Python + gmpy2 |
| **Small Public Exponent (e=3)** | Small `m`, no padding — integer cube root | Python |
| **Boneh-Durfee / Lattice** | Large `e` beyond Wiener bound | SageMath |
| **ECC / PRNG / Hash** | General category classification | Python / SageMath |

---

## 🧠 GRPO Fine-Tuning Pipeline

The model is trained using **Group Relative Policy Optimization (GRPO)** — a reinforcement learning algorithm that ranks a group of candidate outputs without needing a separate critic model.

```
  crypto_dataset.jsonl  (300 verified challenges)
           │
           ▼
  prepare_llama3_dataset()
  Format as Llama-3 chat prompts
           │
           ▼
  ┌──────────────────────────────────┐
  │  GRPOTrainer                     │
  │  Llama-3.1-8B + LoRA (r=16)      │
  │  4 candidate exploits / challenge│
  └──────────────┬───────────────────┘
                 │  for each candidate
                 ▼
  docker_crypto_reward_func()
  ┌────────────────────────────────┐
  │  Run in Docker sandbox         │
  │  +1.0  → exact flag match      │
  │  +0.2  → valid execution       │
  │   0.0  → crash / empty output  │
  └────────────────────────────────┘
                 │
                 ▼
  llama3-crypto-grpo-final/   (saved LoRA adapter)
```

**Why GRPO?**
- No need for human preference labels
- The Docker sandbox is an **objective, automated verifier**
- Multiple candidates per challenge allow relative ranking without a reward model

**LoRA Config:** rank=16, alpha=32, all attention and MLP projection layers, dropout=0.05

---

## 📁 Repository Structure

```
crypto-ctf-agent/
├── agent.py              # LangGraph state machine — core reasoning loop
├── solve.py              # CLI entry point: reads inputs/, launches agent
├── sandbox.py            # Docker execution engine with native fallback
├── data_generator.py     # Synthetic RSA challenge factory (Wiener/Fermat/Common Modulus)
├── train_llama3_grpo.py  # GRPO RL fine-tuning pipeline with Docker rewards
├── scratch_solve.py      # Quick one-off LLM query script (Groq/OpenAI compatible)
├── search_ctf.py         # (Utility) CTF challenge search helper
├── Dockerfile            # SageMath + gmpy2 + pwntools + z3 + pycryptodome sandbox image
├── requirements.txt      # Host Python dependencies
├── .env.example          # LLM backend configuration template
├── inputs/
│   └── prompt.txt        # Drop your challenge here
└── outputs/
    ├── exploit.py        # Last generated exploit script
    └── flag.txt          # Recovered flag
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- Docker (recommended) or a local Python environment with gmpy2 + pycryptodome
- A running Llama-3 endpoint: **Ollama**, **vLLM**, **LM Studio**, or **Groq Cloud**

---

### 1. Clone & Install

```bash
git clone https://github.com/Femiinnn/Autonomous-AI-Powered-Cryptography-CTF-Agent.git
cd Autonomous-AI-Powered-Cryptography-CTF-Agent
pip install -r requirements.txt
```

---

### 2. Configure the LLM Backend

Copy `.env.example` to `.env` and fill in your backend:

```bash
cp .env.example .env
```

```env
# Option A: Local Ollama
LLAMA3_API_BASE=http://localhost:11434/v1
LLAMA3_API_KEY=ollama
LLAMA3_MODEL_NAME=llama3.1:8b

# Option B: Local vLLM
LLAMA3_API_BASE=http://localhost:8000/v1
LLAMA3_API_KEY=EMPTY
LLAMA3_MODEL_NAME=meta-llama/Meta-Llama-3.1-8B-Instruct

# Option C: Groq Cloud (free tier available)
LLAMA3_API_BASE=https://api.groq.com/openai/v1
LLAMA3_API_KEY=gsk_your_groq_key_here
LLAMA3_MODEL_NAME=llama-3.1-8b-instant
```

---

### 3. Build the Docker Sandbox

```bash
docker build -t crypto-sandbox:latest .
```

> If Docker is unavailable, the sandbox automatically falls back to native Python/SageMath execution.

---

### 4. Solve a Challenge

**Option A — Drop it in a file:**
```bash
echo "RSA Challenge:\nN = 1234...\ne = 56789...\nc = 9876...\nRecover the flag." > inputs/prompt.txt
python solve.py
```

**Option B — Pass it as a CLI argument:**
```bash
python solve.py "RSA Challenge: N=... e=... c=... Recover the flag."
```

**Option C — Interactive input:**
```bash
python solve.py
# Paste your challenge, type DONE when finished
```

Results are saved to `outputs/flag.txt` and `outputs/exploit.py`.

---

### 5. Generate Training Dataset

```bash
python data_generator.py
# → crypto_dataset.jsonl  (300 verified RSA challenges)
```

---

### 6. Run GRPO Fine-Tuning *(GPU required)*

```bash
# Start your Llama-3 vLLM server or use HuggingFace Hub
python train_llama3_grpo.py
# → llama3-crypto-grpo-final/   (trained LoRA adapter)
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Agent Framework | [LangGraph](https://github.com/langchain-ai/langgraph) |
| LLM | [Meta Llama-3.1-8B-Instruct](https://llama.meta.com/) |
| LLM Serving | Ollama / vLLM / LM Studio / Groq |
| Code Execution | Docker (SageMath + Python 3) |
| Cryptographic Libraries | `gmpy2`, `pycryptodome`, `sympy`, `z3-solver`, `pwntools` |
| RL Training | [TRL GRPO](https://huggingface.co/docs/trl/grpo_trainer) |
| Fine-Tuning Method | [LoRA via PEFT](https://github.com/huggingface/peft) |
| Data Format | JSONL with verified ground-truth flags |

---

## 📊 How the Dataset is Generated

`data_generator.py` creates **mathematically verified** RSA challenges where the ground-truth flag is embedded in the ciphertext before generation — guaranteeing every sample is solvable:

```
flag = "flag{wiener_d_42_7391}"
m = bytes_to_long(flag.encode())         # plaintext integer
c = pow(m, e, n)                         # encrypt with vulnerable key
challenge = { problem: "N=..., e=..., c=..." , ground_truth_flag: flag }
```

Three attack classes × 100 samples = **300 total challenges** per dataset.

---

## 🤝 Contributing

Pull requests are welcome! Ideas for contribution:

- Add new challenge generators (AES-ECB, CBC Padding Oracle, ECC Pohlig-Hellman, PRNG reseeding)
- Build an `eval.py` harness to benchmark solve rate per attack type
- Add CTFtime/CTFd API integration to fetch real live challenges
- Improve the GRPO reward with partial-credit substring matching

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
