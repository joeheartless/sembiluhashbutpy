# One-Time Encrypted Message Tool

## Overview
This tool allows you to securely encrypt and share one-time messages that automatically expire after a set time or after being read. It ensures data integrity using HMAC verification and prevents brute-force attacks with a retry limit.

## Features
- **AES-256 Encryption (CBC Mode)**: Uses a strong encryption algorithm with random IV for security.
- **One-Time Message**: Once decrypted successfully, the message is deleted permanently.
- **Automatic Expiration**: Messages expire in **10 minutes** (configurable via `TTL`).
- **Integrity Check**: Ensures that stored data has not been tampered with using HMAC-SHA256.
- **Short Code Generation**: Generates a unique 6-character code for each message.
- **File Locking**: Prevents race conditions while reading/writing storage.
- **Brute-Force Protection**: Limits failed decryption attempts before deleting the message.

## Installation
Ensure you have Python 3 installed. Install required dependencies:
```sh
pip install pycryptodome
```

## Usage

### Encrypt a Message
```sh
python script.py encode --data "Your secret message" --password "your_strong_password"
```
- Returns a **short code** that can be used to decrypt the message.
- Password must be at least **12 characters long**.

### Decrypt a Message
```sh
python script.py decode --code YOUR_SHORT_CODE --password "your_strong_password"
```
- If the password is correct, the message will be decrypted and then **deleted permanently**.
- If incorrect, the system logs a failed attempt.

### Clear All Stored Messages
```sh
python script.py clear
```
- Deletes all stored encrypted messages.

## Security Notes
- **Use Strong Passwords**: Since the encryption key is derived from the password, use a strong and unique password.
- **Avoid Sharing the Password**: Only share the short code, never the encryption password.

## Future Improvements
- Add support for **PBKDF2** for better password security.
- Implement a **secure API** for remote message sharing.
- Add optional **custom expiration times** for messages.

---
Feel free to contribute or suggest improvements! 🚀

