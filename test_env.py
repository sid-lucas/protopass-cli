# test_env.py
import bcrypt
from Crypto.Cipher import AES
import pyotp
import requests

print("Les bibliothèques principales sont installées et fonctionnent.")

# Test de hachage bcrypt
password = b"test123"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(f"Hash bcrypt : {hashed}")

# Test de chiffrement AES
key = b"0123456789abcdef"
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(b"Message secret")
print(f"Chiffrement AES OK : {ciphertext}")

# Test de génération TOTP
totp = pyotp.TOTP(pyotp.random_base32())
print(f"Code TOTP simulé : {totp.now()}")

# Test de requête HTTP
response = requests.get("https://api.simplelogin.io")
print(f"Requête HTTP : {response.status_code} ✅")
