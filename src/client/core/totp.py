import time
import pyotp

def generate_secret():
    return pyotp.random_base32()

def current_code(secret: str):
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = int(totp.interval - (time.time() % totp.interval))
    return code, remaining

def validate_secret(secret: str) -> bool:
    try:
        pyotp.TOTP(secret)
        return True
    except Exception:
        return False
