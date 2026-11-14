import os
import sys
import glob
import shutil
from pathlib import Path
from PIL import Image
from agent import crypto_solver_agent

INPUTS_DIR = Path(__file__).parent / "inputs"
OUTPUTS_DIR = Path(__file__).parent / "outputs"

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}
TEXT_EXTENSIONS = {".txt", ".py", ".sage", ".c", ".cpp", ".json", ".enc", ".pem", ".log"}

def inspect_image(filepath: Path) -> str:
    """Extracts metadata from image files for cryptanalysis/stego."""
    try:
        with Image.open(filepath) as img:
            info = f"File: {filepath.name} | Format: {img.format} | Size: {img.size} | Mode: {img.mode}\n"
            exif = img.getexif()
            if exif:
                info += f"EXIF Tags: {dict(exif)}\n"
            info += f"Note: This image is saved in the working directory as '{filepath.name}'. Your solver script can open it using `PIL.Image.open('{filepath.name}')`."
            return info
    except Exception as e:
        return f"File: {filepath.name} (Error reading image: {e})"

def gather_challenge_context() -> str:
    """Scans the inputs/ folder for prompt, code files, and images."""
    context_parts = []
    
    # 1. Check for command-line text argument
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        cli_input = " ".join(sys.argv[1:])
        context_parts.append(f"Challenge Description:\n{cli_input}\n")

    # 2. Check for inputs/prompt.txt or inputs/challenge.txt
    for main_file in ["prompt.txt", "challenge.txt", "problem.txt"]:
        p = INPUTS_DIR / main_file
        if p.exists() and p.stat().st_size > 0:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                if content:
                    context_parts.append(f"Challenge Prompt ({main_file}):\n{content}\n")

    # 3. Check for accompanying files in inputs/
    other_files = [f for f in INPUTS_DIR.iterdir() if f.is_file() and f.name not in ["prompt.txt", "challenge.txt", "problem.txt", ".gitkeep"]]
    
    for f in other_files:
        ext = f.suffix.lower()
        if ext in TEXT_EXTENSIONS:
            with open(f, "r", encoding="utf-8", errors="ignore") as tf:
                context_parts.append(f"--- Attached File: {f.name} ---\n{tf.read().strip()}\n")
        elif ext in IMAGE_EXTENSIONS:
            # Copy image to current working directory so solver script can access it
            shutil.copy(f, Path(__file__).parent / f.name)
            img_info = inspect_image(f)
            context_parts.append(f"--- Attached Image ---\n{img_info}\n")
        else:
            context_parts.append(f"--- Attached Binary File: {f.name} ({f.stat().st_size} bytes) available in working directory ---")

    # 4. If nothing was found, ask interactively
    if not context_parts:
        print("=" * 60)
        print("No input found in 'inputs/' or CLI arguments.")
        print("Paste your challenge prompt below. Type 'DONE' on a new line when finished:")
        print("=" * 60)
        lines = []
        while True:
            try:
                line = input()
                if line.strip() == "DONE":
                    break
                lines.append(line)
            except EOFError:
                break
        user_text = "\n".join(lines).strip()
        if user_text:
            context_parts.append(f"Challenge Prompt:\n{user_text}\n")
            # Save it to inputs/prompt.txt for convenience
            with open(INPUTS_DIR / "prompt.txt", "w", encoding="utf-8") as f:
                f.write(user_text)

    return "\n".join(context_parts)

def main():
    OUTPUTS_DIR.mkdir(exist_ok=True)
    INPUTS_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("🛡️  Autonomous Crypto CTF & Bug Bounty Solver")
    print("=" * 60)

    challenge_text = gather_challenge_context()

    if not challenge_text.strip():
        print("❌ Error: No challenge text or files provided.")
        sys.exit(1)

    print("\n📦 Loaded Challenge Context:")
    print("-" * 60)
    print(challenge_text[:500] + ("\n... [truncated]" if len(challenge_text) > 500 else ""))
    print("-" * 60)

    # Launch agent
    state = {"challenge": challenge_text}
    result = crypto_solver_agent.invoke(state)

    flag = result.get("captured_flag")
    exploit_code = result.get("generated_code")

    print("\n" + "=" * 60)
    if flag:
        print(f"🎉 SUCCESS! Captured Flag:\n   {flag}")
        # Save flag to outputs/flag.txt
        with open(OUTPUTS_DIR / "flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")
    else:
        print("⚠️ Failed to capture flag within retry limit.")

    # Save generated exploit code
    if exploit_code:
        exploit_file = OUTPUTS_DIR / "exploit.py"
        with open(exploit_file, "w", encoding="utf-8") as f:
            f.write(exploit_code)
        print(f"💾 Exploit script saved to: {exploit_file}")
    print("=" * 60)

if __name__ == "__main__":
    main()
