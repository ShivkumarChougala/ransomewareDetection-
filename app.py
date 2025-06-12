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
socketio = SocketIO(app)

# Emit logs to the web UI
def emit_log(message, level="info"):
    print(f"[{level.upper()}] {message}")  # Print to terminal (optional)
    socketio.emit("log", {"message": message, "level": level})

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

# Run the file inside Docker sandbox with detailed monitoring
def run_sandbox(file_path):
    filename = os.path.basename(file_path)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            suspect_file_path = os.path.join(tmpdir, "suspect_file")
            shutil.copy2(file_path, suspect_file_path)

            emit_log(f"🛡️ Running sandbox container on {filename}...", "info")

            result = subprocess.run([
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/sandbox",
                "ransomware-sandbox",
                "/sandbox/suspect_file"
            ], capture_output=True, text=True, timeout=60)

            emit_log(f"🧾 Sandbox stdout:\n{result.stdout}", "info")
            emit_log(f"⚠️ Sandbox stderr:\n{result.stderr}", "warn")

            def read_log(name, path, limit=2000):
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        emit_log(f"{name}:\n{f.read()[:limit]}", "info")

            read_log("📂 Filesystem Events", os.path.join(log_dir, "inotify.log"))
            read_log("📝 Syscalls", os.path.join(log_dir, "strace.log"))

            pcap = os.path.join(log_dir, "tcpdump.pcap")
            if os.path.exists(pcap):
                try:
                    p = subprocess.run(["tcpdump", "-nn", "-tt", "-r", pcap],
                                       capture_output=True, text=True, timeout=10)
                    emit_log(f"🌐 Network:\n{p.stdout[:2000]}", "info")
                except Exception as e:
                    emit_log(f"❌ Failed to read pcap: {e}", "error")

    except subprocess.TimeoutExpired:
        emit_log(f"⏰ Sandbox timeout for {filename}", "warn")
    except Exception as e:
        emit_log(f"❌ Sandbox error: {e}", "error")

# Main Watcher Class
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
            emit_log(f"[ERROR] Backup failed for {src_path}: {e}", "error")

    def quarantine_file(self, src_path):
        try:
            filename = os.path.basename(src_path)
            quarantine_path = os.path.join(QUARANTINE_FOLDER, filename)
            shutil.move(src_path, quarantine_path)
            emit_log(f"[QUARANTINED] {filename}", "warn")
            return quarantine_path
        except Exception as e:
            emit_log(f"[ERROR] Quarantine failed for {src_path}: {e}", "error")
            return None

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        filename = os.path.basename(path)
        emit_log(f"[CREATED] {filename}", "info")
        self.backup_file(path)

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

        try:
            with open(path, "rb") as f:
                data = f.read()
            entropy = calculate_entropy(data)
            emit_log(f"⚠️ Entropy for {filename}: {entropy:.2f}", "warn")

            if entropy > 7.5:
                emit_log(f"🚨 High entropy detected in {filename}, moving to quarantine.", "warn")
                quarantined_path = self.quarantine_file(path)
                if quarantined_path:
                    run_sandbox(quarantined_path)
                return

        except Exception as e:
            emit_log(f"[ERROR] Entropy calc failed for {filename}: {e}", "error")

        self.backup_file(path)

        new_hash = sha256_hash(path)
        old_hash = self.file_hashes.get(path)

        if new_hash and old_hash and new_hash != old_hash:
            emit_log(f"⚠️ FILE TAMPERING DETECTED: {filename}", "warn")
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

# Background watcher
def start_watcher():
    os.makedirs(WATCHED_FOLDER, exist_ok=True)
    event_handler = RansomwareWatcher()
    observer = Observer()
    observer.schedule(event_handler, WATCHED_FOLDER, recursive=False)
    observer.start()
    emit_log(f"🛡️ Monitoring '{WATCHED_FOLDER}' for changes...", "info")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Entry point
if __name__ == "__main__":
    watcher_thread = threading.Thread(target=start_watcher)
    watcher_thread.daemon = True
    watcher_thread.start()
    socketio.run(app, host='0.0.0.0', port=5000)
