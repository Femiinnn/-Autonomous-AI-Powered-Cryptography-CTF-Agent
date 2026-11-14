import os
import requests
from dotenv import load_dotenv

load_dotenv(r"C:\Users\FEMINTEE\crypto-ctf-agent\.env")

prompt = """
You are a world-class CTF cryptography expert.
Solve this CTF challenge:

Prompt:
"Pie. Pie. Pie. 1 r34lly l1k3 p13s, thr33 0f th3m, t0 b3 3x4ct!

Ciphertext = 73665d1406069b625aa34884e219d0c2ec5bf3957acb92ffde"

Analyze the clues:
1. "Pie. Pie. Pie."
2. "1 r34lly l1k3 p13s, thr33 0f th3m, t0 b3 3x4ct!"
3. Ciphertext is 50 hex chars (25 bytes).

Determine the exact encryption algorithm, key, and decrypt it to find the flag.
Show your full reasoning and recovered plaintext.
"""

url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {os.getenv('LLAMA3_API_KEY')}",
    "Content-Type": "application/json"
}
payload = {
    "model": "openai/gpt-oss-120b",
    "messages": [{"role": "user", "content": prompt}],
    "max_tokens": 2048,
    "temperature": 0.2
}

res = requests.post(url, headers=headers, json=payload)
data = res.json()
if "choices" in data:
    msg = data["choices"][0]["message"]
    print("CONTENT:", msg.get("content"))
    print("REASONING:", msg.get("reasoning"))
else:
    print("Error:", data)
