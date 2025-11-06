import getpass
import base64
import json
import os
from pathlib import Path
from utils import logger as log
from utils.logger import CTX
from utils.network import api_post, handle_resp
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
    _vault_keys = {}  # Cache mémoire des clés de vault déchiffrées

    PATH = Path(__file__).resolve().parents[1] / "client_data" / "account_state.json"

    # ============================================================
    # Lecture et écriture de l'état du compte (fichier local)
    # ============================================================
    @classmethod
    def _read(cls):
        logger = log.get_logger(CTX.ACCOUNT_STATE, user="")
        if not cls.PATH.exists():
            logger.debug("Local account_state.json is missing.")
            return None
        try:
            return json.loads(cls.PATH.read_text())
        except Exception:
            logger.error("Unable to decode account_state.json, file may be corrupted.")
            return None

    @classmethod
    def save(cls, username, session_id, public_key, private_key_enc, nonce, tag, salt):
        logger = log.get_logger(CTX.ACCOUNT_STATE, username)
        cls.PATH.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "username": username,
            "session_id": session_id,
            "public_key": public_key,
            "private_key_enc": private_key_enc,
            "nonce": nonce,
            "tag": tag,
            "salt": salt,
        }

        try:
            payload_json = json.dumps(payload, indent=2)
            fd = os.open(str(cls.PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload_json)
        except Exception as exc:
            logger.error(f"Unable to persist account state: {exc}")
            return False

        cls._cached_username = username
        cls._cached_session_id = session_id
        try:
            cls._cached_public_key = base64.b64decode(public_key)
        except Exception as exc:
            cls._cached_public_key = None
            logger.warning(f"Unable to cache public key: {exc}")
        return True

    @classmethod
    def clear(cls):
        if cls.PATH.exists():
            cls.PATH.unlink()
        cls._cached_username = None
        cls._cached_session_id = None
        cls._cached_public_key = None
        cls.clear_private_key()
        cls.clear_vault_keys()

    # ============================================================
    # Gestion de session et récupération des infos utilisateur
    # ============================================================
    @classmethod
    def valid(cls):
        """Vérifie si la session locale existe et est encore valide côté serveur."""
        current_user = cls.username()
        logger = log.get_logger(CTX.SESSION_VERIFY, current_user)
        sid = cls.session_id()
        if not sid:
            logger.debug("No local session ID available. Session is considered invalid.")
            return False

        # Vérifie auprès du serveur
        data = handle_resp(
            api_post("/session/verify", {"session_id": sid}, user=current_user),
            required_fields=["username"],
            context=CTX.SESSION_VERIFY,
            user=current_user
        )
        if data is None:
            logger.warning(f"Local session '{sid[:8]}' invalid according to server, clearing local data.")
            cls.clear()

        return bool(data)

    @classmethod
    def username(cls):
        # Récupère le username du cache si existe
        if cls._cached_username is not None:
            return cls._cached_username
        
        # Sinon lis le username stocké sur le disque
        data = cls._read()
        if not data:
            return None

        username = data.get("username")
        if not username:
            return None
        cls._cached_username = username
        return cls._cached_username

    @classmethod
    def session_id(cls):
        if cls._cached_session_id is not None:
            return cls._cached_session_id
        data = cls._read()
        if not data:
            return None
        session_id = data.get("session_id")
        if not session_id:
            return None
        cls._cached_session_id = session_id
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
            log.get_logger(CTX.ACCOUNT_STATE, user=cls._cached_username or "").error(
                f"Invalid public key encoding in account_state.json: {e}"
            )
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
            log.get_logger(CTX.DECRYPT, cls.username()).error(f"Unable to decrypt private key: {e}")
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
        logger = log.get_logger(CTX.ACCOUNT_STATE, cls.username())
        data = cls._read()
        if not data:
            logger.error("No local account state found.")
            return None

        for key in ["private_key_enc", "nonce", "tag", "salt"]:
            if key not in data:
                logger.error(f"Missing field '{key}' in local account state.")
                return None

        logger.info("Reloading private key from disk.")
        password = getpass.getpass("Enter your password: ")

        try:
            private_key_enc = base64.b64decode(data["private_key_enc"])
            nonce = base64.b64decode(data["nonce"])
            tag = base64.b64decode(data["tag"])
            salt = base64.b64decode(data["salt"])
        except Exception as e:
            logger.error(f"Error decoding stored fields: {e}")
            return None

        decrypted = cls._decrypt_private_key(password, private_key_enc, nonce, tag, salt)
        if decrypted is None:
            logger.warning("Private key decryption aborted.")
            return None

        cls.set_private_key(decrypted)
        return bytes(cls._private_key) 

    # ============================================================
    # Gestion des clés de vault (cache mémoire uniquement)
    # ============================================================
    @classmethod
    def set_vault_key(cls, vault_id: str, key_bytes: bytes):
        cls._vault_keys[vault_id] = bytearray(key_bytes)

    @classmethod
    def vault_key(cls, vault_id: str):
        key = cls._vault_keys.get(vault_id)
        if key is None:
            return None
        return bytes(key)

    @classmethod
    def clear_vault_keys(cls):
        if not cls._vault_keys:
            return
        for value in cls._vault_keys.values():
            if isinstance(value, bytearray):
                for idx in range(len(value)):
                    value[idx] = 0
        cls._vault_keys.clear()
