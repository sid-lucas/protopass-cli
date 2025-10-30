import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "server_data" / "users.json"

def _ensure_db():
    # crée data/users.json si absent
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        DB_PATH.write_text("{}")

def _load():
    # lit et retourne le dict Python en mémoire
    _ensure_db()
    return json.loads(DB_PATH.read_text())

def _save(data: dict):
    # écrit le dict sur disque (joli format)
    DB_PATH.write_text(json.dumps(data, indent=2))

# récupère les infos d'un user
def get_user(username: str):
    data = _load()
    return data.get(username)

# crée un nouveau user (si le nom n'existe pas deja)
def add_user(username: str, salt_b64: str, vkey_b64: str):
    data = _load()
    if username in data:
        return False
    data[username] = {"salt": salt_b64, "vkey": vkey_b64}
    _save(data)
    return True
