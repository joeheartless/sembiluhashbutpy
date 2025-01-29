import os
import json
import hashlib
import base64
import argparse
import time
import hmac
import fcntl  # Import buat file locking
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEYS_FILE = "storage.json"
TTL = 600  # 10 menit dalam detik (600 detik)
INTEGRITY_SECRET = os.getenv("INTEGRITY_SECRET", b"default_secret_salt")  # Ambil dari env var

def load_storage():
    """Load storage with file lock"""
    if not os.path.exists(KEYS_FILE):
        return {}
    
    with open(KEYS_FILE, "r") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_SH)  # Shared lock (baca)
            data = json.load(f)
            fcntl.flock(f, fcntl.LOCK_UN)  # Unlock
            return data
        except json.JSONDecodeError:
            return {}

def save_storage(data):
    """Save storage with file lock"""
    with open(KEYS_FILE, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock (tulis)
        json.dump(data, f, indent=4)
        fcntl.flock(f, fcntl.LOCK_UN)  # Unlock

def generate_key(password):
    """Generate 32-byte AES key from password."""
    return hashlib.sha256(password.encode()).digest()

def encrypt_aes(data, password):
    """Encrypt data using AES CBC mode."""
    key = generate_key(password)
    iv = os.urandom(16)  # Generate random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_aes(encrypted_data, password):
    """Decrypt AES encrypted data."""
    key = generate_key(password)
    raw_data = base64.b64decode(encrypted_data)
    iv, encrypted_data = raw_data[:16], raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
    except ValueError:
        return None  # Password salah

def generate_integrity_check(encrypted_data):
    """Bikin hash integrity buat memastikan data gak diubah."""
    return hmac.new(INTEGRITY_SECRET, encrypted_data.encode(), hashlib.sha256).hexdigest()

def cleanup_expired_messages():
    """Remove expired messages from storage."""
    storage = load_storage()
    current_time = time.time()
    expired_codes = [code for code, data in storage.items() if data["expires_at"] < current_time]

    if expired_codes:
        for code in expired_codes:
            del storage[code]
        save_storage(storage)
        print(f"🗑️ {len(expired_codes)} expired message(s) deleted.")

def encode(data, password):
    """Encrypt data, generate a short code, and store it with expiration time."""
    if len(password) < 12:
        print("❌ Error: Password too short! Must be at least 12 characters long.")
        return
    
    cleanup_expired_messages()
    storage = load_storage()
    short_code = hashlib.sha256(os.urandom(16)).hexdigest()[:6]  # 6 karakter unik
    encrypted_data = encrypt_aes(data, password)
    integrity_check = generate_integrity_check(encrypted_data)

    expires_at = time.time() + TTL
    storage[short_code] = {
        "encrypted_data": encrypted_data,
        "expires_at": expires_at,
        "failed_attempts": 0,
        "integrity_check": integrity_check
    }
    save_storage(storage)
    print(f"✅ Encoded! Your short code: {short_code} (Expires in 10 minutes)")

def decode(short_code, password):
    """Decrypt data using short code and remove it if password is correct."""
    cleanup_expired_messages()
    storage = load_storage()

    if short_code not in storage:
        print("❌ Error: Code not found or expired.")
        return

    entry = storage[short_code]
    if time.time() > entry["expires_at"]:
        del storage[short_code]
        save_storage(storage)
        print("❌ Error: Code has expired.")
        return

    if generate_integrity_check(entry["encrypted_data"]) != entry["integrity_check"]:
        del storage[short_code]
        save_storage(storage)
        print("❌ Error: Data integrity check failed. Possible tampering detected!")
        return

    decrypted_data = decrypt_aes(entry["encrypted_data"], password)
    if decrypted_data is None:
        storage[short_code]["failed_attempts"] += 1
        save_storage(storage)
        print("❌ Error: Wrong password. Message will expire in 10 minutes.")
    else:
        del storage[short_code]
        save_storage(storage)
        print("🔓 Decoded message:")
        print(decrypted_data) 
        print("\n(Message deleted after successful decode)")

def clear():
    """Clear all stored data."""
    save_storage({})
    print("🗑️ Storage cleared.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="One-time encrypted message tool with auto-delete after successful decode.")
    parser.add_argument("action", choices=["encode", "decode", "clear"], help="Action to perform")
    parser.add_argument("--data", help="Data to encode")
    parser.add_argument("--password", help="Password for encryption/decryption")
    parser.add_argument("--code", help="Short code for decoding")

    args = parser.parse_args()

    if args.action == "encode":
        if not args.data or not args.password:
            print("❌ Error: You must provide --data and --password.")
        else:
            encode(args.data, args.password)

    elif args.action == "decode":
        if not args.code or not args.password:
            print("❌ Error: You must provide --code and --password.")
        else:
            decode(args.code, args.password)

    elif args.action == "clear":
        clear()

