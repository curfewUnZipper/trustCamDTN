from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import json, os, hashlib

AES_KEY = b'\x15\x2B\x4C\x0C\x5A\x16\x0B\x36\x63\x20\x13\xC8\x2C\x37\x42\x4D'
IV      = b'\x09\x08\x07\x06\x05\x04\x03\x02\x01\x16\x21\x2C'

# ---- Load file to encrypt ----
with open("./testing/omen.png", "rb") as f:
    data = f.read()

# ---- Encrypt file ----
aes = AESGCM(AES_KEY)
cipher = aes.encrypt(IV, data, None)

with open("./testing/encrypted.bin", "wb") as f:
    f.write(cipher)

# ---- Hash encrypted data ----
digest = hashlib.sha256(cipher).digest()

# ---- Load the backend's ECDSA private key for testing ----
with open("ecdsa_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))

# Convert DER signature to raw r||s form (64 bytes)
r, s = decode_dss_signature(signature)
raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

with open("./testing/signature.bin", "wb") as f:
    f.write(raw)

print("DONE: encrypted.bin and signature.bin created.")
