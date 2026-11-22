# Secure File Sharing with Time-Based Access Control

A Flask-based secure file sharing system with advanced cryptographic features.

**Team:** Abhishek Kumar, Amit Patil, Anand, Aditya  
**Subject:** Cryptography & Network Security (BE 5th Sem)

## Features

### Core
- AES-256-CBC file encryption with random key per file
- RSA-2048 key pair generation per user
- RSA-OAEP key wrapping (AES key encrypted with receiver's public key)
- RSA-PSS digital signatures on file hashes
- SHA-256 file integrity verification
- Time-based access control with automatic expiry
- Role-based access (Admin/User)

### Security
- PBKDF2 password hashing
- TOTP two-factor authentication (RFC 6238) with QR code
- HMAC-SHA256 tamper-proof audit logs
- Password entropy-based strength checking
- Optional file-level password protection

### UI
- File preview (images, text, PDF)
- Admin panel with user/file/log management
- Cryptographic info page (view your RSA keys)
- Real-time password strength meter
- Bootstrap 5 responsive design

## Setup (GitHub Codespaces)

1. Create a new Codespace
2. Upload the project files
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run:
   ```bash
   python app.py
   ```
5. Open the forwarded port (5000) in browser

## Default Admin
- Username: `admin`
- Password: `Admin@123`

## Cryptographic Flow

```
Upload:
  File → AES-256-CBC Encrypt → Store ciphertext
  AES Key → RSA-OAEP Encrypt (receiver's public key) → Store wrapped key
  File Hash → RSA-PSS Sign (owner's private key) → Store signature

Download:
  Wrapped Key → RSA-OAEP Decrypt (receiver's private key) → AES Key
  Ciphertext → AES-256-CBC Decrypt → Plaintext
  Verify SHA-256 hash → Verify RSA-PSS signature
```

## Tech Stack
- Python Flask
- PyCryptodome (AES, RSA, HMAC, SHA-256)
- SQLite
- Bootstrap 5
