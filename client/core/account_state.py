import getpass
import base64
import json
import os
from pathlib import Path
from client.utils.logger import log_client
from client.utils.network import api_post, handle_resp
from Crypto.Cipher import AES
import bcrypt

class AccountState:
    """
    Stocke l'état local du compte : informations persistantes associées à l'utilisateur
    (username, session_id, clé publique, etc.).
    """

    # Champs mémoire volatile (non sauvegardés) utile pour le shell interactif
    _cached_username = None  # Pour des questions de performance (évite de relire le fichier à chaque fois)
    _cached_session_id = None  # idem
    _cached_public_key = None  # idem
    _private_key = None  # Pour des questions de sécurité

    PATH = Path(__file__).resolve().parents[1] / "client_data" / "account_state.json"

    # ============================================================
    # Lecture et écriture de l'état du compte (fichier local)
    # ============================================================
    @classmethod
    def _read(cls):
        if not cls.PATH.exists():
            return None
        try:
            return json.loads(cls.PATH.read_text())
        except Exception:
            return None

    @classmethod
    def save(cls, username, session_id, public_key, private_key_enc, nonce, tag, salt):
        cls.PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "username": username,
            "session_id": session_id,
            "public_key": public_key,
            "private_key": private_key_enc,
            "nonce": nonce,
            "tag": tag,
            "salt": salt
        }
        # Écriture atomique du fichier avec permissions restreintes
        try:
            payload_json = json.dumps(payload, indent=2)
            fd = os.open(str(cls.PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload_json)
        except Exception as e:
            log_client("error", "AccountState", f"unable to persist account state: {e}")
            return False
        
        # Mise à jour du cache mémoire
        cls._cached_username = username
        cls._cached_session_id = session_id
        cls._cached_public_key = public_key
        return True

    @classmethod
    def clear(cls):
        if cls.PATH.exists():
            cls.PATH.unlink()
        cls._cached_username = None
        cls._cached_session_id = None
        cls._cached_public_key = None
        cls.clear_private_key()

    # ============================================================
    # Gestion de session et récupération des infos utilisateur
    # ============================================================
    @classmethod
    def valid(cls):
        """Vérifie si la session locale existe et est encore valide côté serveur."""
        sid = cls.session_id()
        if not sid:
            return False

        data = handle_resp(
            api_post("/session/verify", {"session_id": sid}),
            required_fields=["username"],
            context="Session verify"
        )
        if data is None:
            cls.clear()

        return bool(data)

    @classmethod
    def username(cls):
        if cls._cached_username is not None:
            return cls._cached_username
        data = cls._read()
        if not data:
            return None
        cls._cached_username = data.get("username")
        return cls._cached_username

    @classmethod
    def session_id(cls):
        if cls._cached_session_id is not None:
            return cls._cached_session_id
        data = cls._read()
        if not data:
            return None
        cls._cached_session_id = data.get("session_id")
        return cls._cached_session_id

    @classmethod
    def public_key(cls):
        if cls._cached_public_key is not None:
            return cls._cached_public_key
        data = cls._read()
        if not data:
            return None
        public_key_b64 = data.get("public_key")
        if not public_key_b64:
            return None
        try:
            cls._cached_public_key = base64.b64decode(public_key_b64)
            return cls._cached_public_key
        except Exception as e:
            log_client("error", "AccountState", f"invalid public key encoding in account_state.json: {e}")
            return None
        
    # ============================================================
    # Gestion de la clé privée : mémoire, cache et déchiffrement
    # ============================================================
    @classmethod
    def _decrypt_private_key(cls, password: str, private_key_enc: bytes, nonce: bytes, tag: bytes, salt: bytes):
        """
        Déchiffre la clé privée user key avec la clé dérivée bcrypt.
        """
        try:
            # Dérivation de la clé AES via bcrypt
            aes_key = bcrypt.kdf(
                password=password.encode(),
                salt=salt,
                desired_key_bytes=32,
                rounds=200  # facteur de coût (à partir de 200 pour de la sécurité basique)
            )
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(private_key_enc, tag)
        except Exception as e:
            log_client("error", "Decrypt", f"unable to decrypt user key: {e}")
            return None

    @classmethod
    def set_private_key(cls, key_bytes):
        cls._private_key = bytearray(key_bytes)

    @classmethod
    def private_key(cls):
        if cls._private_key is not None:
            return bytes(cls._private_key) 
        return cls._load_private_key_in_mem()

    @classmethod
    def clear_private_key(cls):
        if cls._private_key is not None:
            key_obj = cls._private_key
            if isinstance(key_obj, bytearray):
                for i in range(len(key_obj)):
                    key_obj[i] = 0
        cls._private_key = None

    @classmethod
    def _load_private_key_in_mem(cls):
        """
        Si la private_key n'est plus en mémoire, redemande le mot de passe pour la déchiffrer localement.
        """
        if cls._private_key is not None:
            return bytes(cls._private_key) 

        data = cls._read()
        if not data:
            log_client("error", "AccountState", "no local account state found.")
            return None

        for key in ["private_key", "nonce", "tag", "salt"]:
            if key not in data:
                log_client("error", "AccountState", f"missing field '{key}' in local account state.")
                return None

        password = getpass.getpass("Enter your password: ")

        try:
            private_key_enc = base64.b64decode(data["private_key"])
            nonce = base64.b64decode(data["nonce"])
            tag = base64.b64decode(data["tag"])
            salt = base64.b64decode(data["salt"])
        except Exception as e:
            log_client("error", "AccountState", f"error decoding stored fields: {e}")
            return None

        decrypted = cls._decrypt_private_key(password, private_key_enc, nonce, tag, salt)
        if decrypted is None:
            return None

        cls.set_private_key(decrypted)
        return bytes(cls._private_key) 
