import json
from pathlib import Path

USERS_PATH = Path(__file__).resolve().parent / "server_data" / "users.json"

def _ensure_db():
    # crée data/users.json si absent
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not USERS_PATH.exists() or USERS_PATH.stat().st_size == 0:
        USERS_PATH.write_text("{}")

def _load():
    # lit et retourne le dict Python en mémoire
    _ensure_db()
    return json.loads(USERS_PATH.read_text())

def _save(data: dict):
    # écrit le dict sur disque (joli format)
    USERS_PATH.write_text(json.dumps(data, indent=2))

# récupère les infos d'un user
def get_user(username: str):
    data = _load()
    return data.get(username)

# crée un nouveau user complet (SRP + user_key obligatoires)
def add_user(username: str, salt_b64: str, vkey_b64: str,
             public_key: str, private_key_enc: str, nonce: str, tag: str):

    # Vérif : champs obligatoires
    if not all([username, salt_b64, vkey_b64, public_key, private_key_enc, nonce, tag]):
        raise KeyError("missing required fields")

    # charge la DB
    data = _load()

    # Vérif : user déjà existant
    if username in data:
        raise ValueError("username already exists")

    data[username] = {
        "salt": salt_b64,
        "vkey": vkey_b64,
        "user_key": {
            "public_key": public_key,
            "private_key_enc": private_key_enc,
            "nonce": nonce,
            "tag": tag,
        }
    }

    _save(data)
    return True