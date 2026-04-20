# Secure API Key Changer

A lightweight, cryptographically secure Python utility that automatically and periodically rotates your `API_KEY`. It uses AES-256-GCM encryption for the key stored locally, writes it atomically to your `.env` file, and hardens file permissions. This is designed to keep your application running with securely rotated API keys, mitigating risks of key exposure or exhaustion. 

By default, the utility generates a cryptographically secure random key (`key_<token>`) using Python's `secrets` module. It also provides a helper function to decrypt and read the key in your own application using a master password.

## Features

- **AES-256-GCM Encryption:** API keys are encrypted using AES-256 in Galois/Counter Mode before being written to the `.env` file.
- **OWASP 2024 Compliant Key Derivation:** Uses PBKDF2-HMAC-SHA256 with 600,000 iterations to derive the AES key from a master password.
- **Zero-Knowledge Architecture:** The master password and the derived AES key are never written to disk. Only the salt and iterations are stored in `.aes_master.key`.
- **Cryptographically Secure Generation:** Uses OS-level randomness (`secrets`) instead of standard UUIDs for key generation.
- **Atomic File Updates:** Avoids partial-write corruption by using temp file substitution when updating the `.env` file.
- **File Hardening:** Automatically restricts read/write permissions on the `.env` and `.aes_master.key` files to the file owner (chmod 600).
- **Audit Logging:** Keeps track of key rotations in `key_rotation_audit.log` without logging the actual API keys.
- **Graceful Shutdown:** Safely stops background processes upon receiving SIGINT/SIGTERM.
- **Enforced Minimums:** Enforces a minimum of 1-minute intervals between rotations to prevent rapid cycling.

## Getting Started

### Prerequisites

- Python 3.6 or higher.
- `cryptography` Python package.

### Installation

1. Clone or download this project to your machine.
2. Ensure you are in the project root directory.
3. Install the required dependency:
   ```bash
   pip install cryptography
   ```

### Usage

1. Run the Python script:
   ```bash
   python apikeychanger.py
   ```
2. You will be prompted to enter a master password:
   ```text
   Enter master password for AES-256 key derivation:
   ```
   *Note: The password must be at least 12 characters long.*
3. You will be prompted to enter a rotation interval:
   ```text
   Enter rotation interval (minutes):
   ```
4. Enter the number of minutes (e.g., `5` to rotate every 5 minutes). The script enforces a minimum of `1` minute.
5. The script will immediately generate an API key, create the `salt` and store it in `.aes_master.key`, and output the AES-encrypted API key into the `.env` file.
6. The rotation process runs continuously in the background. Press `Ctrl + C` to shut down the process gracefully.

## Integrating into Your Application

Since the API key inside your `.env` file is now encrypted, you cannot read it as plain text. You should use the provided helper function inside `apikeychanger.py` to decrypt it when loading into your application. You will need to provide the same master password that the rotation script is using.

```python
import getpass
from apikeychanger import load_or_create_master_key, read_current_key

# 1. Ask for (or provide) the master password
password = getpass.getpass("Enter master password to load API key: ")

# 2. Derive the master AES key 
aes_key = load_or_create_master_key(password)

# 3. Extract and decrypt your API key
try:
    api_key = read_current_key(aes_key)
    print("Successfully loaded the API key!")
    # Use api_key for your application logic...
except Exception as e:
    print(f"Error reading key: {e}")
```

## Customizing Key Generation

Currently, the script generates cryptographically secure strings to act as API keys.

To integrate this script with a real API key provider, open `apikeychanger.py` and modify the `generate_new_key()` function to include your authentication request:

```python
def generate_new_key(length: int = 40) -> str:
    """
    Replace this with real API call if your provider supports it.
    """
    # Example logic:
    # response = requests.post("https://provider.com/api/v1/rotate", headers={"Auth": "..."})
    # return response.json().get("new_key")
    return "key_" + secrets.token_urlsafe(length)
```

## Security Best Practices

Ensure your repository includes an appropriate `.gitignore` file (like the one implemented) so that you don't accidentally commit your secrets or logs:

```gitignore
.env
.aes_master.key
key_rotation_audit.log
```

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check out the project code and submit a pull request if you want to extend its capabilities.
