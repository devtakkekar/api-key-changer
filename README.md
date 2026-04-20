# Secure API Key Changer

A lightweight, cryptographically secure Python utility that automatically and periodically rotates your `API_KEY`. It encrypts the key locally, writes it atomically to your `.env` file, and hardens file permissions. This is designed to keep your application running with securely rotated API keys, mitigating risks of key exposure or exhaustion. 

By default, the utility generates a cryptographically secure random key (`key_<token>`) using Python's `secrets` module. It also provides a helper function to decrypt and read the key in your own application.

## Features

- **Fernet Encryption:** API keys are encrypted before being written to the `.env` file using a master key (`.rotation_master.key`).
- **Cryptographically Secure Generation:** Uses OS-level randomness (`secrets`) instead of standard UUIDs for key generation.
- **Atomic File Updates:** Avoids partial-write corruption by using temp file substitution when updating the `.env` file.
- **File Hardening:** Automatically restricts read/write permissions on the `.env` and master key files to the file owner (chmod 600).
- **Audit Logging:** Keeps track of key rotations in `key_rotation_audit.log` without logging the actual API keys.
- **Graceful Shutdown:** Safely stops background processes upon receiving SIGINT/SIGTERM.
- **Enforced Minimums:** Enforces a minimum of 1-minute intervals between rotations to prevent rapid cycling.

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
2. You will be prompted to enter a rotation interval:
   ```text
   Enter key rotation interval (in minutes):
   ```
3. Enter the number of minutes (e.g., `5` to rotate every 5 minutes). The script enforces a minimum of `1` minute.
4. The script will immediately generate an API key, create the encryption master key (`.rotation_master.key`), and output the encrypted API key into a `.env` file.
5. The rotation process runs continuously in the background. Press `Ctrl + C` to shut down the process gracefully.

## Integrating into Your Application

Since the API key inside your `.env` file is now encrypted, you cannot read it as plain text. You should use the provided helper function inside `apikeychanger.py` to decrypt it when loading into your application.

```python
from apikeychanger import load_or_create_fernet_key, read_current_key

# 1. Load the master encryption key
fernet = load_or_create_fernet_key()

# 2. Extract and decrypt your API key
try:
    api_key = read_current_key(fernet)
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

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check out the project code and submit a pull request if you want to extend its capabilities.
