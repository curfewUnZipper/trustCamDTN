"""
TrustCam-DTN Backend Verification & Decryption Module
Single-file Flask app (non-modular) implementing:
- Bundle reception
- AES-GCM decryption
- ECDSA + SHA-256 verification (simplified)
- Transparency hash-chain logging
This is a reference implementation for college project use.
"""

from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature

import os
import json
import time
import hashlib
from datetime import datetime

# ------------------------- CONFIGURATION -------------------------

# AES-GCM parameters – must match ESP32 firmware
AES_KEY = b'\x15\x2B\x4C\x0C\x5A\x16\x0B\x36\x63\x20\x13\xC8\x2C\x37\x42\x4D'
IV      = b'\x09\x08\x07\x06\x05\x04\x03\x02\x01\x16\x21\x2C'   # 12 bytes

# Output directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE_DIR = os.path.join(BASE_DIR, "received_images")
LOG_FILE = os.path.join(BASE_DIR, "transparency_log.jsonl")

os.makedirs(IMAGE_DIR, exist_ok=True)

# ECDSA public key (secp256r1) – placeholder: replace with actual device public key.
# For demo purposes, we'll generate an in-memory keypair on first run.
ECDSA_PRIVATE_KEY_FILE = os.path.join(BASE_DIR, "ecdsa_private_key.pem")
ECDSA_PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "ecdsa_public_key.pem")


def init_ecdsa_keys():
    """
    Generate or load ECDSA keypair for demo.
    In your real system, you will NOT generate here.
    You will hardcode or load the device public key only.
    """
    if os.path.exists(ECDSA_PRIVATE_KEY_FILE) and os.path.exists(ECDSA_PUBLIC_KEY_FILE):
        with open(ECDSA_PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ECDSA_PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(ECDSA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(ECDSA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key, public_key


ECDSA_PRIVATE_KEY, ECDSA_PUBLIC_KEY = init_ecdsa_keys()


# ------------------------- TRANSPARENCY LOG -------------------------

def get_last_log_entry():
    """Return last log entry dict or None if log is empty."""
    if not os.path.exists(LOG_FILE):
        return None
    last = None
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    return last


def append_log_entry(event_hash_hex, device_id, timestamp, metadata):
    """
    Append a new hash-chained log entry.
    event_hash_hex: hex string of current event hash (SHA-256)
    """
    last = get_last_log_entry()
    prev_hash = last["event_hash"] if last else "0" * 64

    entry = {
        "index": (last["index"] + 1) if last else 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "device_timestamp": timestamp,
        "device_id": device_id,
        "event_hash": event_hash_hex,
        "prev_hash": prev_hash,
        "metadata": metadata,
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return entry


def verify_log_chain():
    """
    Basic integrity check of the entire log.
    Returns (ok: bool, message: str)
    """
    if not os.path.exists(LOG_FILE):
        return True, "Log empty (no entries yet)."

    prev_hash = "0" * 64
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry["index"] != idx:
                return False, f"Index mismatch at line {idx}: got {entry['index']}"
            if entry["prev_hash"] != prev_hash:
                return False, f"Hash chain broken at line {idx}"
            prev_hash = entry["event_hash"]
    return True, "Log chain consistent."


# ------------------------- CRYPTO HELPERS -------------------------

def compute_sha256(data: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.digest()


def verify_ecdsa_signature(public_key, message_digest: bytes, signature_bytes: bytes) -> bool:
    """
    Verify ECDSA signature over a SHA-256 digest.
    Expects 'signature_bytes' as raw (r||s) 64-byte format from micro-ecc or similar.
    """
    if len(signature_bytes) != 64:
        # Not in expected format
        return False

    r = int.from_bytes(signature_bytes[:32], byteorder="big")
    s = int.from_bytes(signature_bytes[32:], byteorder="big")
    der_sig = encode_dss_signature(r, s)

    try:
        public_key.verify(
            der_sig,
            message_digest,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


def decrypt_aes_gcm(ciphertext_with_tag: bytes) -> bytes:
    """
    Decrypt AES-GCM ciphertext + tag.
    ESP32 should send: [ciphertext][auth_tag]
    """
    aesgcm = AESGCM(AES_KEY)
    plaintext = aesgcm.decrypt(IV, ciphertext_with_tag, None)
    return plaintext


# ------------------------- FLASK APP -------------------------

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "ok",
        "message": "TrustCam-DTN Backend running",
        "endpoints": {
            "POST /receive": "Upload encrypted bundle",
            "GET /images": "List decrypted images",
            "GET /images/<filename>": "Download specific image",
            "GET /log": "View transparency log",
            "GET /log/verify": "Run log chain integrity check",
        }
    })


@app.route("/receive", methods=["POST"])
def receive():
    """
    Receive encrypted bundle from ESP32 / DTN gateway.
    Expected multipart/form-data:
      - data: encrypted bytes (AES-GCM ciphertext + tag)
      - signature: 64-byte raw ECDSA signature over hash(enc)
      - metadata: JSON string containing device_id, timestamp, etc.
    """
    print("FILES:", request)
    print("FORM:", request.form)
    if "data" not in request.files:
        return jsonify({"error": "Missing 'data' file field"}), 400

    enc = request.files["data"].read()

    sig = b""
    if "signature" in request.files:
        sig = request.files["signature"].read()

    metadata = {}
    if "metadata" in request.form:
        try:
            metadata = json.loads(request.form["metadata"])
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in 'metadata'"}), 400

    device_id = metadata.get("device_id", "unknown-device")
    device_timestamp = metadata.get("timestamp", "unknown-time")

    # Step 1: compute hash of encrypted payload
    digest = compute_sha256(enc)
    digest_hex = digest.hex()
    print(">> Hash computed:", digest_hex)

    # Step 2: verify ECDSA signature (if provided)
    sig_ok = None
    if sig:
        sig_ok = verify_ecdsa_signature(ECDSA_PUBLIC_KEY, digest, sig)
        print(">> Signature verification result:", sig_ok)
    else:
        print(">> No signature provided (skipping verification).")

    # Step 3: update transparency log
    log_entry = append_log_entry(
        event_hash_hex=digest_hex,
        device_id=device_id,
        timestamp=device_timestamp,
        metadata=metadata
    )
    print(">> Transparency log updated, index:", log_entry["index"])

    # Step 4: decrypt AES-GCM
    try:
        plaintext = decrypt_aes_gcm(enc)
    except Exception as e:
        print("!! Decryption failed:", e)
        return jsonify({
            "error": "Decryption failed",
            "log_entry": log_entry,
            "signature_ok": sig_ok
        }), 400

    # Step 5: save image
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{device_id}_{ts}.jpg"
    out_path = os.path.join(IMAGE_DIR, filename)
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(">> File saved:", out_path)
   

    return jsonify({
        "status": "ok",
        "message": "Bundle received and processed",
        "file": filename,
        "log_entry": log_entry,
        "signature_ok": sig_ok
    })



@app.route("/images", methods=["GET"])
def list_images():
    """List decrypted images saved on server."""
    files = sorted(os.listdir(IMAGE_DIR))
    return jsonify({
        "count": len(files),
        "files": files
    })


@app.route("/images/<path:filename>", methods=["GET"])
def get_image(filename):
    """Download a specific image file."""
    return send_from_directory(IMAGE_DIR, filename, as_attachment=True)


@app.route("/log", methods=["GET"])
def get_log():
    """Return entire transparency log as JSON list."""
    entries = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return jsonify({
        "count": len(entries),
        "entries": entries
    })


@app.route("/log/verify", methods=["GET"])
def log_verify():
    ok, message = verify_log_chain()
    return jsonify({
        "ok": ok,
        "message": message
    })


if __name__ == "__main__":
    # For production use, run via gunicorn/uwsgi instead.
    app.run(host="0.0.0.0", port=5000, debug=True)
