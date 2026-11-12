
An Autonomous AI-Powered Cryptanalysis Agent

Crypto CTF Agent is an AI-powered cryptanalysis system designed to analyze and solve cryptography-based Capture The Flag (CTF) challenges using automated reasoning, mathematical analysis, and code execution.

 🚀 Technology Stack

- Python 3.10+ – Core development
- LangGraph – Agent orchestration and workflow management
- Llama 3.1 8B Instruct – AI-powered reasoning and analysis
- Docker – Isolated execution environment
- SageMath – Advanced mathematical and cryptographic operations
- CrackStation - Detect and decode hash

 🎯 Project Aim

The primary objective is to develop an autonomous AI agent capable of identifying cryptographic algorithms, analyzing vulnerabilities, and solving cryptography-related CTF challenges with minimal human intervention.

Given a challenge description, ciphertext, or public cryptographic parameters, the agent aims to:

1. Identify – Detect the cryptographic algorithm and challenge category.
2. Analyze – Examine potential weaknesses and mathematical vulnerabilities.
3. Generate – Develop Python or SageMath scripts for cryptanalysis.
4. Execute – Run generated scripts inside an isolated Docker sandbox.
5. Recover – Analyze execution results and attempt to recover the CTF flag.

 🧠 Core Architecture

The agent uses a structured AI workflow to coordinate challenge analysis, code generation, execution, and result validation.

Its architecture combines LLM-based reasoning, LangGraph orchestration, and mathematical tools to automate cryptographic problem-solving.

 ⚙️ Key Features

- Automated cipher identification
- Classical cryptography analysis
- RSA cryptanalysis
- Hash identification and analysis
- Encoding and decoding detection
- Multi-layer encryption analysis
- Python and SageMath script generation
- Docker-based isolated execution
- Error analysis and iterative problem-solving

 🔒 Security

Generated scripts are executed within an isolated Docker environment to reduce risks associated with automated code execution.

 


This project is licensed under the MIT License.
