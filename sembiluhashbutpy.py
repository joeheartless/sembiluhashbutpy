from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import os
import random
import string

app = Flask(__name__)
CORS(app)
KEYS_FILE = ".keys"

def to_ascii(text):
    """Convert string to ASCII hex."""
    return text.encode().hex()

def from_ascii(hex_string):
    """Convert ASCII hex to original string."""
    try:
        return bytes.fromhex(hex_string).decode()
    except ValueError:
        return None

def generate_code(data):
    """Generate a short code from input data."""
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # Random 8-char salt
    ascii_input = to_ascii(data)
    
    hash_value = hashlib.sha256((ascii_input + salt).encode()).hexdigest()
    short_code = hash_value[:12]  # Ambil 12 karakter pertama

    with open(KEYS_FILE, "a") as f:
        f.write(f"{short_code}|{ascii_input}|{salt}|{hash_value}\n")

    return short_code

def decode_code(short_code):
    """Decode a short code and remove it from storage."""
    if not os.path.exists(KEYS_FILE):
        return None, "No stored data found."

    lines = []
    found_data = None
    with open(KEYS_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if parts[0] == short_code:
                ascii_input = parts[1]
                salt = parts[2]
                stored_hash = parts[3]

                check_hash = hashlib.sha256((ascii_input + salt).encode()).hexdigest()
                if check_hash != stored_hash:
                    return None, "Data integrity check failed."

                found_data = from_ascii(ascii_input)
                continue  # Skip storing this entry (remove it)

            lines.append(line)

    # Update storage file
    if found_data:
        with open(KEYS_FILE, "w") as f:
            f.writelines(lines)

    return found_data, None if found_data else "Code not found."

@app.route("/encode", methods=["POST"])
def encode():
    """API endpoint to encode data."""
    data = request.json.get("data")
    if not data:
        return jsonify({"error": "Missing 'data' field"}), 400
    
    short_code = generate_code(data)
    return jsonify({"short_code": short_code})

@app.route("/decode/<short_code>", methods=["GET"])
def decode(short_code):
    """API endpoint to decode a short code."""
    decoded_data, error = decode_code(short_code)
    if error:
        return jsonify({"error": error}), 404
    
    return jsonify({"decoded_data": decoded_data})

@app.route("/clear", methods=["DELETE"])
def clear():
    """API endpoint to clear all stored data."""
    open(KEYS_FILE, "w").close()
    return jsonify({"message": "All stored codes have been erased."})

@app.route("/")
def home():
    return jsonify({"message": "Short Code API is running!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
