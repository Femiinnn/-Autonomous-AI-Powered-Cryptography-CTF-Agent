import os
import json
import time
import queue
import threading
import re
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'inputs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

ALLOWED_EXTENSIONS = {
    'txt', 'py', 'sage', 'json', 'pem', 'enc', 'log', 'c', 'cpp',
    'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp'
}
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp'}

# In-memory job store: job_id -> Queue
_job_queues: dict[str, queue.Queue] = {}


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_image(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in IMAGE_EXTENSIONS


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/solve', methods=['POST'])
def solve():
    challenge_text = request.form.get('challenge', '').strip()
    category       = request.form.get('category', 'auto').strip()
    attack         = request.form.get('attack', 'auto').strip()

    # ── Handle uploaded file ──────────────────────────────────────────────────
    uploaded = request.files.get('challenge_file')
    file_info = ''
    if uploaded and uploaded.filename and allowed_file(uploaded.filename):
        fname = secure_filename(uploaded.filename)
        save_path = app.config['UPLOAD_FOLDER'] / fname
        app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
        uploaded.save(save_path)

        if is_image(fname):
            # Provide image metadata as context
            try:
                from PIL import Image
                with Image.open(save_path) as img:
                    file_info = (
                        f"\n--- Attached Image: {fname} ---\n"
                        f"Format: {img.format} | Size: {img.size} | Mode: {img.mode}\n"
                        f"Your solver can open it with PIL.Image.open('{fname}')\n"
                    )
            except Exception as e:
                file_info = f"\n--- Attached Image: {fname} (could not read metadata: {e}) ---\n"
        else:
            # Read text-based file content
            try:
                with open(save_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    file_info = f"\n--- Attached File: {fname} ---\n{fh.read().strip()}\n"
            except Exception:
                file_info = f"\n--- Attached File: {fname} ({save_path.stat().st_size} bytes) ---\n"

    # Merge text + file content
    full_challenge = challenge_text
    if file_info:
        full_challenge = (full_challenge + '\n' + file_info).strip()

    if not full_challenge:
        return jsonify({'error': 'Please provide a challenge description or upload a file.'}), 400

    # Inject user-selected hints so the agent respects them
    hints = []
    if category and category.lower() not in ('auto', ''):
        hints.append(f"[Category Hint: {category}]")
    if attack and attack.lower() not in ('auto', ''):
        hints.append(f"[Attack Hint: {attack}]")
    if hints:
        full_challenge = '\n'.join(hints) + '\n' + full_challenge

    # ── Spawn background agent thread ─────────────────────────────────────────
    job_id = f"{int(time.time() * 1000)}"
    q: queue.Queue = queue.Queue()
    _job_queues[job_id] = q

    def run_agent():
        import sys

        class _QWriter:
            def write(self, text):
                stripped = text.strip()
                if stripped:
                    q.put({'type': 'log', 'message': stripped})
            def flush(self):
                pass

        old_stdout = sys.stdout
        sys.stdout = _QWriter()
        try:
            from agent import crypto_solver_agent
            result = crypto_solver_agent.invoke({'challenge': full_challenge})
            flag = result.get('captured_flag')
            code = result.get('generated_code', '')
            stdout_out = result.get('execution_stdout', '')
            # ── Hash / Encoding analysis (new) ──────────────────────────────
            ha = result.get('hash_analysis') or {}
            full_ha = ha.get('full') or {}
            hash_info = {
                'summary':          full_ha.get('summary', ''),
                'is_double_encoded':full_ha.get('is_double_encoded', False),
                'total_layers':     full_ha.get('total_layers', 0),
                'final_decoded':    full_ha.get('final_decoded', ''),
                'layers': [
                    {
                        'layer':     l.get('layer', 0),
                        'type':      l.get('type', ''),
                        'encoding':  l.get('encoding', ''),
                        'decoded':   l.get('decoded', ''),
                        'is_hash':   l.get('is_hash', False),
                        'hash_algos':[a.get('algorithm','') for a in (l.get('hash_algorithms') or [])],
                        'confidence':l.get('confidence', ''),
                    }
                    for l in (full_ha.get('encoding_layers') or [])
                ],
                'substrings': [
                    {
                        'original': s.get('original', ''),
                        'summary':  s.get('summary', ''),
                        'final_decoded': s.get('final_decoded', ''),
                        'is_double_encoded': s.get('is_double_encoded', False),
                        'encoding': (s.get('encoding_layers') or [{}])[0].get('encoding', ''),
                    }
                    for s in (ha.get('substrings') or [])
                ]
            }
            q.put({'type': 'result', 'flag': flag, 'code': code, 'stdout': stdout_out,
                   'hash_info': hash_info})
        except Exception as exc:
            q.put({'type': 'error', 'message': str(exc)})
        finally:
            sys.stdout = old_stdout
            q.put({'type': 'done'})

    t = threading.Thread(target=run_agent, daemon=True)
    t.start()

    return jsonify({'job_id': job_id})


@app.route('/stream/<job_id>')
def stream(job_id: str):
    """Server-Sent Events endpoint — streams live logs and final result."""
    def generate():
        q = _job_queues.get(job_id)
        if not q:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
            return
        while True:
            try:
                msg = q.get(timeout=90)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') in ('done', 'error'):
                    _job_queues.pop(job_id, None)
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)
