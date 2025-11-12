import json, socket, uuid, base64
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
            raise ConnectionError("No agent detected (socket not found)")

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
                raise RuntimeError("Empty response from agent")
            resp = json.loads(resp_raw.decode("utf-8"))
            return resp


    # ============================================================
    #  API publique (utilisées par le CLI)
    # ============================================================

    def status(self, logger=None):
        """
        Vérifie si l'agent répond au socket.
        Retourne True si actif, False sinon.
        """
        try:
            resp = self._send("status")
            return resp.get("status") == "ok"
        except Exception as e:
            if logger:
                logger.warning(f"Agent status check failed: {e}")
        return False

    def start(self, username: str, password: str, salt_b64: str, logger=None):
        """Démarre la session agent (dérive et garde la clé AES)."""
        try:
            resp = self._send("start", {"username": username, "password": password, "salt": salt_b64})
            if resp.get("status") == "ok":
                if logger: logger.debug("Agent started (master_key en mémoire)")
                return True
            if logger: logger.error(f"Agent start failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent start exception: {e}")
        return False

    def shutdown(self, logger=None):
        """Arrête l'agent (auto-effacement et fermeture)."""
        try:
            resp = self._send("shutdown")
            if resp.get("status") == "ok":
                if logger: logger.debug("Agent shutdown successful")
                return True
            if logger: logger.error(f"Agent shutdown failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent shutdown exception: {e}")
        return False

    def encrypt(self, plaintext: str | bytes, logger=None):
        """Chiffre une donnée avec la clé AES stockée dans l'agent. Retourne un dict ou None."""
        try:
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8", "ignore")
            resp = self._send("encrypt", {"plaintext": plaintext})
            if resp.get("status") == "ok":
                return resp["data"]
            if logger: logger.error(f"Agent encrypt failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent encrypt exception: {e}")
        return None

    def decrypt(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str, logger=None):
        """Déchiffre une donnée AES-GCM via la clé de l'agent. Retourne un dict ou None."""
        try:
            resp = self._send("decrypt", {"ciphertext": ciphertext_b64, "nonce": nonce_b64, "tag": tag_b64})
            if resp.get("status") == "ok":
                return resp["data"]
            if logger: logger.error(f"Agent decrypt failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent decrypt exception: {e}")
        return None

    def hmac(self, payload_bytes: bytes, logger=None):
        """Calcule HMAC-SHA256(payload) via l'agent, renvoie {'hmac': base64} ou None."""
        try:
            payload_b64 = base64.b64encode(payload_bytes).decode()
            resp = self._send("hmac", {"payload_b64": payload_b64})
            if resp.get("status") == "ok":
                return resp["data"]
            if logger: logger.error(f"Agent hmac failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent hmac exception: {e}")
        return None
