import os
import time
import shutil
import hashlib
import threading
import math
import subprocess
import tempfile

from flask import Flask, render_template
from flask_socketio import SocketIO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Folder config
WATCHED_FOLDER = "watched_folder"
BACKUP_FOLDER = "backup"
QUARANTINE_FOLDER = "quarantine"
HASH_STORE_FILE = "file_hashes.txt"

# Flask app and SocketIO setup
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')  # Fixed to allow real-time emit

# Emit logs to the web UI
def emit_log(message, level="info"):
    print(f"[{level.upper()}] {message}")
    socketio.emit("log", {"message": message, "level": level})

def log_warn(message):
    emit_log(message, "warn")

# Entropy calculation
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

# Hashing function
def sha256_hash(filepath):
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        emit_log(f"Error hashing {filepath}: {e}", "error")
        return None

# Load stored hashes
def load_hashes():
    hashes = {}
    if os.path.exists(HASH_STORE_FILE):
        with open(HASH_STORE_FILE, "r") as f:
            for line in f:
                try:
                    path, filehash = line.strip().split("||")
                    hashes[path] = filehash
                except:
                    continue
    return hashes

# Save hashes to file
def save_hashes(hashes):
    with open(HASH_STORE_FILE, "w") as f:
        for path, filehash in hashes.items():
            f.write(f"{path}||{filehash}\n")

# Run the file inside Docker sandbox
def run_sandbox(file_path):
    filename = os.path.basename(file_path)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            suspect_file_path = os.path.join(tmpdir, "suspect_file")
            shutil.copy2(file_path, suspect_file_path)
            os.chmod(suspect_file_path, 0o755)

            emit_log(f"\U0001f6e1️ Running sandbox container on {filename}...", "info")

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/sandbox:rw",
                "ransomware-sandbox",
                "/sandbox/suspect_file"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            emit_log(f"\U0001f4be Sandbox stdout:\n{result.stdout.strip()}", "info")
            if result.stderr.strip():
                emit_log(f"⚠ Sandbox stderr:\n{result.stderr.strip()}", "warn")

            for log_file, label in [
                ("strace.log", "📝 Syscall trace"),
                ("tcpdump.pcap", "🌐 Network capture"),
                ("inotify.log", "📂 Filesystem events"),
            ]:
                log_path = os.path.join(log_dir, log_file)
                if os.path.exists(log_path):
                    if log_file.endswith(".pcap"):
                        try:
                            output = subprocess.run(["tcpdump", "-nn", "-tt", "-r", log_path],
                                                    capture_output=True, text=True, timeout=10)
                            emit_log(f"{label}:\n{output.stdout[:2000]}", "info")
                        except Exception as e:
                            emit_log(f"Error reading pcap: {e}", "error")
                    else:
                        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                            emit_log(f"{label}:\n{f.read()[:2000]}", "info")

    except subprocess.TimeoutExpired:
        emit_log(f"⚠️ Sandbox timed out for {filename}", "warn")
    except Exception as e:
        emit_log(f"❌ Sandbox execution failed: {e}", "error")

# Common file handler
def handle_file(path):
    filename = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            data = f.read()

        entropy = calculate_entropy(data)
        emit_log(f"⚠ Entropy for {filename}: {entropy:.2f}", "warn")

        if entropy > 4.5 or 'test_exec' in filename:
            log_warn(f"⚠ Entropy for {filename}: {entropy:.2f} (forced run: {'test_exec' in filename})")
            emit_log(f"🚨 High entropy or suspicious filename detected in {filename}, moving to quarantine.", "warn")

            quarantine_path = os.path.join(QUARANTINE_FOLDER, filename)
            shutil.move(path, quarantine_path)
            emit_log(f"[QUARANTINED] {filename}", "warn")

            run_sandbox(quarantine_path)
            return

    except Exception as e:
        emit_log(f"Entropy check failed for {filename}: {e}", "error")

# File system event handler
class RansomwareWatcher(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = load_hashes()
        os.makedirs(BACKUP_FOLDER, exist_ok=True)
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

    def backup_file(self, src_path):
        try:
            filename = os.path.basename(src_path)
            backup_path = os.path.join(BACKUP_FOLDER, filename)
            shutil.copy2(src_path, backup_path)
            emit_log(f"✅ Backed up file: {filename}", "info")
        except Exception as e:
            emit_log(f"Backup failed for {src_path}: {e}", "error")

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        filename = os.path.basename(path)
        emit_log(f"[CREATED] {filename}", "info")
        self.backup_file(path)
        handle_file(path)

        file_hash = sha256_hash(path)
        if file_hash:
            self.file_hashes[path] = file_hash
            save_hashes(self.file_hashes)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        filename = os.path.basename(path)
        emit_log(f"[MODIFIED] {filename}", "info")
        self.backup_file(path)
        handle_file(path)

        new_hash = sha256_hash(path)
        old_hash = self.file_hashes.get(path)

        if new_hash and old_hash and new_hash != old_hash:
            emit_log(f"⚠ FILE TAMPERING DETECTED: {filename}", "warn")
        elif new_hash and old_hash is None:
            emit_log(f"Tracking new file hash: {filename}", "info")

        if new_hash:
            self.file_hashes[path] = new_hash
            save_hashes(self.file_hashes)

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        filename = os.path.basename(path)
        emit_log(f"[DELETED] {filename}", "warn")
        if path in self.file_hashes:
            del self.file_hashes[path]
            save_hashes(self.file_hashes)

# Flask route
@app.route('/')
def index():
    return render_template("index.html")

# Start the background file monitor
def start_watcher():
    os.makedirs(WATCHED_FOLDER, exist_ok=True)
    event_handler = RansomwareWatcher()
    observer = Observer()
    observer.schedule(event_handler, WATCHED_FOLDER, recursive=False)
    observer.start()
    emit_log(f"\U0001f6e1️ Monitoring '{WATCHED_FOLDER}' for changes...", "info")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Entry point
if __name__ == "__main__":
    socketio.start_background_task(start_watcher)
    socketio.run(app, host='0.0.0.0', port=5000)

