import time
import threading
import secrets
import os
import stat
import logging
import signal
import sys
import tempfile
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ── Config ───────────────────────────────────────────────────────────────────
ENV_FILE        = ".env"
KEY_NAME        = "API_KEY"
MASTER_KEY_FILE = ".aes_master.key"    # stores derived AES-256 key
MIN_INTERVAL    = 60
LOG_FILE        = "key_rotation_audit.log"
AES_KEY_BITS    = 256
AES_KEY_BYTES   = AES_KEY_BITS // 8   # 32 bytes
PBKDF2_ITERS    = 600_000             # OWASP 2024 recommended minimum
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)

stop_event = threading.Event()


# ── AES-256 Key Management ────────────────────────────────────────────────────
def derive_aes_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    600k iterations meets OWASP 2024 guidance for PBKDF2-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password)


def load_or_create_master_key(password: str) -> bytes:
    """
    Load AES-256 key from disk (derived from password + stored salt),
    or create a new salt and derive + persist the key on first run.

    Stored file format (JSON):
        { "salt": "<base64>", "iterations": 600000 }
    The key itself is NEVER written to disk — only the salt is stored.
    """
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "r") as f:
            data = json.load(f)
        salt       = base64.b64decode(data["salt"])
        iterations = data.get("iterations", PBKDF2_ITERS)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES,
            salt=salt,
            iterations=iterations,
        )
        aes_key = kdf.derive(password.encode())
        logging.info("AES-256 master key derived from existing salt.")
    else:
        salt    = secrets.token_bytes(32)   # 256-bit random salt
        aes_key = derive_aes_key(password.encode(), salt)

        payload = {
            "salt":       base64.b64encode(salt).decode(),
            "iterations": PBKDF2_ITERS
        }
        dir_name = os.path.dirname(os.path.abspath(MASTER_KEY_FILE))
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tmp:
            json.dump(payload, tmp)
            tmp_path = tmp.name

        _restrict_permissions(tmp_path)
        os.replace(tmp_path, MASTER_KEY_FILE)
        _restrict_permissions(MASTER_KEY_FILE)
        logging.info("New AES-256 salt generated and stored.")

    return aes_key


# ── AES-256-GCM Encrypt / Decrypt ────────────────────────────────────────────
def aes_encrypt(plaintext: str, aes_key: bytes) -> str:
    """
    Encrypt with AES-256-GCM.
    - Generates a fresh 96-bit (12-byte) nonce per encryption (GCM best practice).
    - GCM tag (16 bytes) is automatically appended by the library.
    - Returns base64( nonce || ciphertext+tag ) as a single storable string.
    """
    nonce      = secrets.token_bytes(12)          # 96-bit nonce, unique per call
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    blob       = nonce + ciphertext               # nonce(12) + ct + tag(16)
    return base64.b64encode(blob).decode()


def aes_decrypt(encoded: str, aes_key: bytes) -> str:
    """
    Decrypt AES-256-GCM blob.
    - Splits nonce from ciphertext+tag.
    - GCM authentication tag is verified automatically; raises on tampering.
    """
    blob       = base64.b64decode(encoded)
    nonce      = blob[:12]
    ciphertext = blob[12:]
    aesgcm     = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# ── File Hardening ────────────────────────────────────────────────────────────
def _restrict_permissions(path: str) -> None:
    """Owner read/write only — chmod 600."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# ── Atomic Encrypted Write ────────────────────────────────────────────────────
def update_env_file(new_key: str, aes_key: bytes) -> None:
    """
    Atomically rewrite .env with the AES-256-GCM encrypted API key.
    Uses tempfile + os.replace() to prevent partial writes.
    """
    encrypted = aes_encrypt(new_key, aes_key)
    lines     = []

    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r") as f:
            lines = f.readlines()

    found     = False
    new_lines = []
    for line in lines:
        if line.startswith(f"{KEY_NAME}="):
            new_lines.append(f"{KEY_NAME}={encrypted}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{KEY_NAME}={encrypted}\n")

    dir_name = os.path.dirname(os.path.abspath(ENV_FILE))
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False) as tmp:
        tmp.writelines(new_lines)
        tmp_path = tmp.name

    _restrict_permissions(tmp_path)
    os.replace(tmp_path, ENV_FILE)
    _restrict_permissions(ENV_FILE)


# ── Key Reader ────────────────────────────────────────────────────────────────
def read_current_key(aes_key: bytes) -> str:
    """Decrypt and return the live API key. Call this from your app."""
    if not os.path.exists(ENV_FILE):
        raise FileNotFoundError(".env not found.")
    with open(ENV_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{KEY_NAME}="):
                encrypted = line.strip().split("=", 1)[1]
                return aes_decrypt(encrypted, aes_key)
    raise KeyError(f"{KEY_NAME} not found in {ENV_FILE}.")


# ── Secure Key Generation ─────────────────────────────────────────────────────
def generate_new_key(length: int = 40) -> str:
    """Cryptographically secure API key via OS-level randomness."""
    return "key_" + secrets.token_urlsafe(length)


# ── Rotation Logic ────────────────────────────────────────────────────────────
def rotate_key(interval: int, aes_key: bytes) -> None:
    if stop_event.is_set():
        return

    new_key = generate_new_key()
    update_env_file(new_key, aes_key)

    # Audit log — the actual key is NEVER written here
    logging.info("API key rotated. Next rotation in %ds.", interval)
    print(f"[{datetime.now().isoformat()}] Key rotated. Next in {interval}s.")

    timer = threading.Timer(interval, rotate_key, [interval, aes_key])
    timer.daemon = True
    timer.start()


# ── Graceful Shutdown ─────────────────────────────────────────────────────────
def _shutdown(signum, frame):
    print("\n[SHUTDOWN] Stopping key rotation...")
    logging.info("Scheduler stopped via signal %d.", signum)
    stop_event.set()
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    # Securely collect password (hidden input)
    import getpass
    password = getpass.getpass("Enter master password for AES-256 key derivation: ")
    if len(password) < 12:
        print("[ERROR] Password must be at least 12 characters.")
        sys.exit(1)

    aes_key = load_or_create_master_key(password)

    try:
        minutes  = float(input("Enter rotation interval (minutes): "))
        interval = max(int(minutes * 60), MIN_INTERVAL)
        if interval != int(minutes * 60):
            print(f"[WARN] Clamped to minimum {MIN_INTERVAL}s.")
    except ValueError:
        print("Invalid input. Defaulting to 5 minutes.")
        interval = 300

    print(f"[INFO] AES-256-GCM active. Rotating every {interval}s.")
    logging.info("Rotation started. Interval=%ds.", interval)

    rotate_key(interval, aes_key)
    stop_event.wait()


if __name__ == "__main__":
    main()