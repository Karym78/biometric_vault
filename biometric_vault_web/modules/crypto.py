import hashlib
import json
from pathlib import Path
from uuid import uuid4

from Crypto.Cipher import AES

from modules.paths import DECRYPTED_DIR, ENCRYPTED_DIR


MAGIC = b"BVWEB1"


def derive_key(username: str, fingerprint_hash: str) -> bytes:
    return hashlib.sha256(f"web-vault|{username}|{fingerprint_hash}".encode("utf-8")).digest()


def encrypt_file(source_path: str | Path, username: str, fingerprint_hash: str) -> Path:
    source = Path(source_path)
    cipher = AES.new(derive_key(username, fingerprint_hash), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(source.read_bytes())
    header = {
        "algorithm": "AES-256-GCM",
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "original_filename": source.name,
    }
    header_bytes = json.dumps(header).encode("utf-8")
    destination = ENCRYPTED_DIR / f"{source.stem}_{uuid4().hex[:10]}.vault"
    destination.write_bytes(MAGIC + len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext)
    return destination


def decrypt_file(encrypted_path: str | Path, username: str, fingerprint_hash: str) -> Path:
    payload = Path(encrypted_path).read_bytes()
    if not payload.startswith(MAGIC):
        raise ValueError("Invalid vault file.")
    header_size = int.from_bytes(payload[len(MAGIC) : len(MAGIC) + 4], "big")
    header_start = len(MAGIC) + 4
    header_end = header_start + header_size
    header = json.loads(payload[header_start:header_end].decode("utf-8"))
    ciphertext = payload[header_end:]
    cipher = AES.new(derive_key(username, fingerprint_hash), AES.MODE_GCM, nonce=bytes.fromhex(header["nonce"]))
    plaintext = cipher.decrypt_and_verify(ciphertext, bytes.fromhex(header["tag"]))
    destination = DECRYPTED_DIR / f"{Path(header['original_filename']).stem}_{uuid4().hex[:10]}{Path(header['original_filename']).suffix}"
    destination.write_bytes(plaintext)
    return destination
