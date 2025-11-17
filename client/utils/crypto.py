import hmac, hashlib, base64, json, bcrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

KDF_ROUNDS = 300

def canonical_json(obj: dict) -> str:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False)

def hmac_b64(key: bytes, data: bytes) -> str:
    return base64.b64encode(hmac.new(key, data, hashlib.sha256).digest()).decode('ascii')

def derive_master_key(password: str, salt: bytes, rounds: int = KDF_ROUNDS) -> bytes:
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

def encrypt_b64_block(key: bytes, plaintext: bytes):
    ciphertext, nonce, tag = encrypt_gcm(key, plaintext)
    return b64_block_from_bytes(ciphertext, nonce, tag)

def decrypt_b64_block(key: bytes, block: dict):
    enc, nonce, tag = b64_block_from_bytes(block)
    return decrypt_gcm(key, enc, nonce, tag)

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

# ============================================================
#  vault.py
# ============================================================

def sign_vault_key(private_key_der: bytes, vault_key: bytes) -> bytes:
    digest = SHA256.new(vault_key)
    return pkcs1_15.new(RSA.import_key(private_key_der)).sign(digest)

def wrap_vault_key(public_key_der: bytes, vault_key: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key_der))
    return cipher.encrypt(vault_key)

def unwrap_vault_key(private_key_der: bytes, vault_key_enc: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key_der))
    return cipher.decrypt(vault_key_enc)

