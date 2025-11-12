import os, json, socket, uuid
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

    # --- API publique ---
    def status(self): return self._send("status")
    def unlock(self, username: str): return self._send("unlock", {"username": username})
    def lock(self): return self._send("lock")
    def shutdown(self): return self._send("shutdown")
