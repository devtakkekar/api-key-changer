import time
import threading
import secrets
import os
import stat
import logging
import signal
import sys
import tempfile
from datetime import datetime
from cryptography.fernet import Fernet

# ── Config ──────────────────────────────────────────────────────────────────
ENV_FILE       = ".env"
KEY_NAME       = "API_KEY"
FERNET_KEY_FILE = ".rotation_master.key"   # encrypts the stored API key
MIN_INTERVAL   = 60                        # enforce minimum 1-minute rotation
LOG_FILE       = "key_rotation_audit.log"
# ────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)

stop_event = threading.Event()


# Master key for encrypting the stored API key
def load_or_create_fernet_key() -> Fernet:
    """Load the master encryption key from disk, creating it if absent."""
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            master_key = f.read().strip()
    else:
        master_key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(master_key)
        _restrict_permissions(FERNET_KEY_FILE)
        logging.info("Master encryption key created.")
    return Fernet(master_key)


# Secure key generation
def generate_new_key(length: int = 40) -> str:
    """
    Generate a cryptographically secure random API key.
    `secrets` uses OS-level randomness (urandom), far stronger than uuid4.
    """
    return "key_" + secrets.token_urlsafe(length)


# File hardening
def _restrict_permissions(path: str) -> None:
    """Owner read/write only (chmod 600)."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# Atomic encrypted write
def update_env_file(new_key: str, fernet: Fernet) -> None:
    """
    Atomically update the .env file.
    - Encrypts the API key value before writing.
    - Uses a temp file + os.replace() to avoid partial-write corruption.
    - Locks file permissions to 600 after write.
    """
    encrypted_key = fernet.encrypt(new_key.encode()).decode()
    lines = []

    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            lines = f.readlines()

    found = False
    new_lines = []
    for line in lines:
        if line.startswith(f"{KEY_NAME}="):
            new_lines.append(f"{KEY_NAME}={encrypted_key}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{KEY_NAME}={encrypted_key}\n")

    # Write to a temp file in the same directory, then atomically replace
    dir_name = os.path.dirname(os.path.abspath(ENV_FILE))
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tmp:
        tmp.writelines(new_lines)
        tmp_path = tmp.name

    _restrict_permissions(tmp_path)
    os.replace(tmp_path, ENV_FILE)          # atomic on POSIX systems
    _restrict_permissions(ENV_FILE)


# Key reader (for your app to call) 
def read_current_key(fernet: Fernet) -> str:
    """Decrypt and return the current API key from .env."""
    if not os.path.exists(ENV_FILE):
        raise FileNotFoundError(".env file not found.")
    with open(ENV_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{KEY_NAME}="):
                encrypted_value = line.strip().split("=", 1)[1]
                return fernet.decrypt(encrypted_value.encode()).decode()
    raise KeyError(f"{KEY_NAME} not found in {ENV_FILE}.")


# Rotation logic
def rotate_key(interval: int, fernet: Fernet) -> None:
    """Rotate the key and schedule the next rotation unless stopped."""
    if stop_event.is_set():
        return

    new_key = generate_new_key()
    update_env_file(new_key, fernet)

    # Audit log: record rotation time but NEVER log the key itself
    logging.info("API key rotated successfully. Next rotation in %ds.", interval)
    print(f"[{datetime.now().isoformat()}] Key rotated. Next in {interval}s.")

    timer = threading.Timer(interval, rotate_key, [interval, fernet])
    timer.daemon = True          # won't block process exit
    timer.start()


# Graceful shutdown
def _shutdown(signum, frame):
    print("\n[SHUTDOWN] Signal received. Stopping key rotation...")
    logging.info("Rotation scheduler stopped via signal %d.", signum)
    stop_event.set()
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# Entry point
def main():
    fernet = load_or_create_fernet_key()

    try:
        minutes  = float(input("Enter key rotation interval (in minutes): "))
        interval = max(int(minutes * 60), MIN_INTERVAL)   # enforce floor
        if interval != int(minutes * 60):
            print(f"[WARN] Interval too short — clamped to {MIN_INTERVAL}s.")
    except ValueError:
        print("Invalid input. Defaulting to 5 minutes.")
        interval = 300

    print(f"[INFO] Rotation every {interval}s. Press Ctrl+C to stop.")
    logging.info("Key rotation started. Interval=%ds.", interval)

    rotate_key(interval, fernet)

    # Park the main thread without busy-waiting
    stop_event.wait()


if __name__ == "__main__":
    main()