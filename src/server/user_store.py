import json
from pathlib import Path

APP_DIR = Path.home() / ".protopass" / "server_data"
USERS_PATH = APP_DIR / "users.json"

def _ensure_db():
    # crée data/users.json si absent
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        USERS_PATH.parent.chmod(0o700)
    except Exception:
        pass
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

# intégrations chiffrées (blob opaque)
def get_integrations(username: str):
    data = _load()
    user = data.get(username) or {}
    return user.get("integrations")

def set_integrations(username: str, block: dict):
    if not isinstance(block, dict):
        raise ValueError("integrations block must be a dict")

    required = {"data", "nonce", "tag"}
    if not required.issubset(block.keys()):
        raise ValueError("missing fields in integrations block")

    data = _load()
    if username not in data:
        raise ValueError("user not found")

    user = data[username]
    user["integrations"] = {
        "data": block["data"],
        "nonce": block["nonce"],
        "tag": block["tag"],
    }

    _save(data)
    return True
