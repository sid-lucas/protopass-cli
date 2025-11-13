import base64
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

APP_DIR = Path.home() / ".protopass"
SOCK_PATH = APP_DIR / "agent.sock"

class AgentClient:
    """Client léger pour communiquer avec le protopass-agent via socket UNIX."""

    CONNECT_RETRIES = 5
    CONNECT_DELAY = 0.2

    def __init__(self, sock_path: Path = SOCK_PATH, autostart: bool = True, boot_timeout: float = 5.0):
        self.sock_path = Path(sock_path)
        self.autostart = autostart
        self.boot_timeout = boot_timeout

    def _clear_socket_file(self):
        try:
            self.sock_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _ensure_agent(self, logger=None, force=False):
        """Ensure the agent socket exists, optionally bootstrapping the daemon."""
        if self.sock_path.exists() and not force:
            return

        if not self.autostart:
            raise ConnectionError("No agent detected (socket not found)")

        if force:
            self._clear_socket_file()

        APP_DIR.mkdir(mode=0o700, exist_ok=True)
        os.chmod(APP_DIR, 0o700)

        cmd = [sys.executable, "-m", "client.agent.protopass_agent"]
        try:
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=Path(__file__).resolve().parents[2],  # run from repository root
            )
            if logger:
                logger.debug("Agent daemon spawned via subprocess")
        except Exception as exc:
            raise RuntimeError(f"Unable to spawn agent daemon: {exc}") from exc

        deadline = time.monotonic() + self.boot_timeout
        while time.monotonic() < deadline:
            if self.sock_path.exists():
                time.sleep(0.05)  # small delay to let server listen
                return
            time.sleep(0.05)

        raise TimeoutError("Agent daemon did not create socket in time")

    def _send(self, op: str, data: dict | None = None, logger=None) -> dict:
        """Envoie une requête JSON et renvoie la réponse décodée."""
        try:
            self._ensure_agent(logger)
        except Exception as exc:
            raise ConnectionError(str(exc)) from exc

        payload = {
            "op": op,
            "id": str(uuid.uuid4()),
            "data": data or {}
        }

        last_err = None
        for _ in range(self.CONNECT_RETRIES):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(str(self.sock_path))
                    s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                    resp_raw = s.recv(1 << 20)
                    if not resp_raw:
                        raise RuntimeError("Empty response from agent")
                    return json.loads(resp_raw.decode("utf-8"))
            except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError) as err:
                last_err = err
                time.sleep(self.CONNECT_DELAY)
                try:
                    self._ensure_agent(logger, force=True)
                except Exception:
                    break

        raise ConnectionError(f"Unable to communicate with agent: {last_err}")


    # ============================================================
    #  API publique (utilisées par le CLI)
    # ============================================================

    def status(self, logger=None):
        """
        Vérifie si l'agent répond au socket.
        Retourne True si actif, False sinon.
        """
        try:
            resp = self._send("status", logger=logger)
            return resp.get("status") == "ok"
        except Exception as e:
            if logger:
                logger.warning(f"Agent status check failed: {e}")
        return False

    def start(self, username: str, password: str, salt_b64: str, logger=None):
        """Démarre la session agent (dérive et garde la clé AES)."""
        try:
            resp = self._send("start", {"username": username, "password": password, "salt": salt_b64}, logger=logger)
            if resp.get("status") == "ok":
                if logger: logger.debug("Agent started (master_key en mémoire)")
                return True
            if logger: logger.error(f"Agent start failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent start exception: {e}")
        return False

    def shutdown(self, logger=None):
        """Arrête l'agent (auto-effacement et fermeture)."""
        if not self.sock_path.exists():
            if logger:
                logger.debug("No existing agent to shut down")
            return True
        
        try:
            resp = self._send("shutdown", logger=logger)
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
            resp = self._send("encrypt", {"plaintext": plaintext}, logger=logger)
            if resp.get("status") == "ok":
                return resp["data"]
            if logger: logger.error(f"Agent encrypt failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent encrypt exception: {e}")
        return None

    def decrypt(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str, logger=None):
        """Déchiffre une donnée AES-GCM via la clé de l'agent. Retourne un dict ou None."""
        try:
            resp = self._send("decrypt", {"ciphertext": ciphertext_b64, "nonce": nonce_b64, "tag": tag_b64}, logger=logger)
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
            resp = self._send("hmac", {"payload_b64": payload_b64}, logger=logger)
            if resp.get("status") == "ok":
                return resp["data"]
            if logger: logger.error(f"Agent hmac failed: {resp}")
        except Exception as e:
            if logger: logger.warning(f"Agent hmac exception: {e}")
        return None
