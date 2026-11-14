# Cryptography & SageMath Docker Sandbox for CTF Execution
FROM sagemath/sagemath:latest

USER root

# Install system dependencies for cryptographic libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    python3-dev \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install CTF and cryptanalysis packages directly into Sage's Python environment
RUN sage -pip install --no-cache-dir \
    pycryptodome \
    gmpy2 \
    z3-solver \
    pwntools \
    cryptography \
    sympy

USER sage
WORKDIR /home/sage
