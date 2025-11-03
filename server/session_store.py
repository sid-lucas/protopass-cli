import json, os, time, secrets

PATH = os.path.join(os.path.dirname(__file__), "server_data", "sessions.json")

def _load():
    if not os.path.exists(PATH):
        return {}
    try:
        with open(PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}  # fichier vide -> on repart à zéro
            return json.loads(content)
    except json.JSONDecodeError:
        # fichier corrompu -> on repart aussi à zéro
        return {}


def _save(data):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    with open(PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def create_session(username: str, ttl_seconds: int = 900) -> str:
    sid = secrets.token_urlsafe(32)  # id opaque, imprévisible
    data = _load()
    data[sid] = {"username": username, "exp": time.time() + ttl_seconds} # session valide 15 minutes
    _save(data)
    return sid

def get_session(sid: str):
    data = _load()
    s = data.get(sid)
    if not s: 
        return None
    if s["exp"] < time.time():
        # nettoyage lazy
        del data[sid]; _save(data)
        return None
    return s

def revoke_session(sid: str) -> bool:
    data = _load()
    if sid in data:
        del data[sid]
        _save(data)
        return True
    return False

def is_valid(sid: str) -> bool:
    data = _load()
    s = data.get(sid)
    if not s:
        return False
    if s["exp"] < time.time():
        # nettoyage lazy des expirées
        del data[sid]
        _save(data)
        return False
    return True
