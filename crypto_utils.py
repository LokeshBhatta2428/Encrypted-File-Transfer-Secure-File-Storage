from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac
import hashlib

BLOCK_SIZE = 16


def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    # PKCS7: always pads, even if already aligned (pad_len is 1–16)
    return data + bytes([pad_len]) * pad_len


def unpad(data):
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    # FIX: Validate padding length before using it
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding length: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    return iv + encrypted


def decrypt(data, key):
    if len(data) < 32:  # FIX: Must have at least IV (16) + one block (16)
        raise ValueError("Data too short to decrypt")
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted))


def generate_hmac(data, key):
    # FIX: was hmac.new() — correct call is hmac.new() with keyword args
    return hmac.new(key, msg=data, digestmod=hashlib.sha256).digest()


def verify_hmac(data, mac, key):
    return hmac.compare_digest(generate_hmac(data, key), mac)