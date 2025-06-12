import os
import time
import shutil
import hashlib
import subprocess
import threading
import math
from flask import Flask, render_template
from flask_socketio import SocketIO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Folder configuration
WATCHED_FOLDER = "watched_folder"
BACKUP_FOLDER = "backup"
QUARANTINE_FOLDER = "quarantine"
HASH_STORE_FILE = "file_hashes.txt"

# Flask app setup
app = Flask(__name__)
socketio = SocketIO(app)

# Utility to calculate Shannon entropy
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    for x in set(data):
        p_x = data.count(x) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

# Backup original file
def backup_file(file_path):
    shutil.copy2(file_path, os.path.join(BACKUP_FOLDER, os.path.basename(file_path)))
    print(f"[INFO] ✅ Backed up file: {os.path.basename(file_path)}")

# Quarantine suspicious file
def quarantine_file(file_path):
    shutil.move(file_path, os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path)))
    print(f"[WARN] [QUARANTINED] {os.path.basename(file_path)}")

# Run sandbox analysis using Docker
def run_sandbox_analysis(file_path):
    sandbox_file = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
    os.chmod(sandbox_file, 0o755)  # Ensure the file is executable

    # Optional: check if the file starts with ELF magic bytes
    with open(sandbox_file, "rb") as f:
        magic = f.read(4)
        if not magic.startswith(b'\x7fELF'):
            print("[INFO] 🧼 Not a Linux executable, skipping execution.")
            return

    print("[INFO] 🛡 Running sandbox container on", os.path.basename(file_path))
    try:
        result = subprocess.run([
            "docker", "run", "--rm", "-v",
            f"{os.path.abspath(QUARANTINE_FOLDER)}:/sandbox",
            "sandbox-image"
        ], capture_output=True, text=True)

        print("[INFO] 🧾 Sandbox stdout:")
        print(result.stdout)
        print("[WARN] ⚠ Sandbox stderr:")
        print(result.stderr)
    except Exception as e:
        print("[ERROR] Sandbox execution failed:", str(e))

# File event handler class
class FileEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def process(self, file_path):
        filename = os.path.basename(file_path)
        print(f"[INFO] [MODIFIED] {filename}")

        try:
            with open(file_path, "rb") as f:
                data = f.read()
                entropy = calculate_entropy(data)
                print(f"[WARN] ⚠ Entropy for {filename}: {entropy:.2f}")

                backup_file(file_path)

                if entropy > 2.5:
                    print(f"[WARN] 🚨 High entropy detected in {filename}, moving to quarantine.")
                    quarantine_file(file_path)
                    run_sandbox_analysis(file_path)
                    os.remove(file_path)
                    print(f"[WARN] [DELETED] {filename}")
        except Exception as e:
            print(f"[ERROR] Failed to process {filename}: {str(e)}")

# Start file monitoring
@app.route('/')
def index():
    return render_template('index.html')

def start_monitoring():
    print(f"[INFO] 🛡 Monitoring '{WATCHED_FOLDER}' for changes...")
    observer = Observer()
    event_handler = FileEventHandler()
    observer.schedule(event_handler, WATCHED_FOLDER, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Main entry point
if __name__ == '__main__':
    os.makedirs(WATCHED_FOLDER, exist_ok=True)
    os.makedirs(BACKUP_FOLDER, exist_ok=True)
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()

    socketio.run(app, host='0.0.0.0', port=5000)
