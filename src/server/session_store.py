import json, os, time, secrets
from pathlib import Path
from typing import Optional

APP_DIR = Path.home() / ".protopass" / "server_data"
SESSIONS_PATH = APP_DIR / "sessions.json"

def _load():
    if not SESSIONS_PATH.exists():
        return {}
    try:
        with open(SESSIONS_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}  # fichier vide -> on repart à zéro
            return json.loads(content)
    except json.JSONDecodeError:
        # fichier corrompu -> on repart aussi à zéro
        return {}


def _save(data):
    SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        SESSIONS_PATH.parent.chmod(0o700)
    except Exception:
        pass
    with open(SESSIONS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def create_session(username: str, ttl_seconds: int = 900) -> str:
    sid = secrets.token_urlsafe(32)  # id opaque, imprévisible
    data = _load()
    data[sid] = {"username": username, "exp": time.time() + ttl_seconds} # session valide 15 minutes
    _save(data)
    return sid

def get_session(sid: str, u_hash: Optional[str] = None):
    data = _load()
    s = data.get(sid)
    if not s: 
        return None
    if s["exp"] < time.time():
        # nettoyage lazy
        del data[sid]; _save(data)
        return None
    if u_hash and s["username"] != u_hash:
        return None
    return s

def revoke_session(sid: str) -> bool:
    data = _load()
    if sid in data:
        del data[sid]
        _save(data)
        return True
    return False

def is_valid(sid: str, u_hash: Optional[str] = None) -> bool:
    data = _load()
    s = data.get(sid)
    if not s:
        return False
    if s["exp"] < time.time():
        # nettoyage lazy des expirées
        del data[sid]
        _save(data)
        return False
    if u_hash and s["username"] != u_hash:
        return False
    return True
