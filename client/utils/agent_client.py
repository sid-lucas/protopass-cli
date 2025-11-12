import json, socket, uuid
from pathlib import Path

APP_DIR = Path.home() / ".protopass"
SOCK_PATH = APP_DIR / "agent.sock"

class AgentClient:
    """Client léger pour communiquer avec le protopass-agent via socket UNIX."""

    def __init__(self, sock_path: Path = SOCK_PATH):
        self.sock_path = Path(sock_path)

    def _send(self, op: str, data: dict | None = None) -> dict:
        """Envoie une requête JSON et renvoie la réponse décodée."""
        if not self.sock_path.exists():
            raise ConnectionError("Agent non détecté (socket introuvable).")

        payload = {
            "op": op,
            "id": str(uuid.uuid4()),
            "data": data or {}
        }

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(self.sock_path))
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            resp_raw = s.recv(1 << 20)
            if not resp_raw:
                raise RuntimeError("Réponse vide de l'agent.")
            resp = json.loads(resp_raw.decode("utf-8"))
            return resp


# ============================================================
#  API publique (utilisées par le CLI)
# ============================================================

def status(self):
    """Retourne l'état courant de l'agent."""
    return self._send("status")

def start(self, username: str, password: str, salt_b64: str):
    """Démarre la session agent (dérive et garde la clé AES)."""
    return self._send("start", {"username": username, "password": password, "salt": salt_b64})

def shutdown(self):
    """Arrête l'agent (auto-effacement et fermeture)."""
    return self._send("shutdown")

def encrypt(self, plaintext: str | bytes):
    """Chiffre une donnée avec la clé AES stockée dans l'agent."""
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode("utf-8", "ignore")
    return self._send("encrypt", {"plaintext": plaintext})

def decrypt(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str):
    """Déchiffre une donnée AES-GCM via la clé de l'agent."""
    return self._send("decrypt", {"ciphertext": ciphertext_b64, "nonce": nonce_b64, "tag": tag_b64})

