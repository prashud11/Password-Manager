# Password Manager - Starter

A minimal desktop password manager in Python with Tkinter and SQLite. 
Secrets are encrypted with a key derived from a master password using PBKDF2-HMAC-SHA256. 
Entry data is encrypted with Fernet (AES-128 in CBC with HMAC, provided by `cryptography`).

## How to run
1. `python -m venv .venv && source .venv/bin/activate` (or use Windows venv)
2. `pip install -r requirements.txt`
3. `python main.py`

## Notes
- The master password is never stored. Only a salted hash of the derived key is stored for verification.
- There is no recovery if the master password is lost.
- This starter is for learning. For production, consider a more robust design and audits.
