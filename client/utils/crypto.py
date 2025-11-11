import base64
import bcrypt
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

KDF_ROUNDS = 300

def derive_aes_key(password: str, salt: bytes, rounds: int = KDF_ROUNDS) -> bytes:
    return bcrypt.kdf(
        password=password.encode(),
        salt=salt,
        desired_key_bytes=32,
        rounds=rounds,
    )

def encrypt_gcm(key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag

def decrypt_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def b64_block_from_bytes(ciphertext: bytes, nonce: bytes, tag: bytes):
    return {
        "enc": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }

def bytes_from_b64_block(block: dict):
    return (
        base64.b64decode(block["enc"]),
        base64.b64decode(block["nonce"]),
        base64.b64decode(block["tag"]),
    )

def generate_userkey_pair():
    key = RSA.generate(2048)
    private_bytes = key.export_key(format="DER")
    public_bytes = key.publickey().export_key(format="DER")
    return public_bytes, private_bytes
