import base64, json, os
from pathlib import Path
from Crypto.Hash import SHA256
from ..utils import logger as log
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.crypto import canonical_json
from ..utils.agent_client import AgentClient

"""
Structure de account_state.json :

{
  "username": "...",          // string (en clair)
  "salt": "...",              // b64
  "public_key": "...",        // b64
  "private_key": {
    "enc": "...",             // b64
    "nonce": "...",           // b64
    "tag": "..."              // b64
  },
  "session": {
    "enc": "...",             // b64
    "nonce": "...",           // b64
    "tag": "..."              // b64
  }
}
"""

MAX_UNLOCK_ATTEMPTS = 3

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
    _current_vault_id = None


    PATH = Path(__file__).resolve().parents[1] / "client_data" / "account_state.json"

    # ============================================================
    # Lecture et écriture de l'état du compte (fichier local)
    # ============================================================

    @classmethod
    def _read(cls):
        logger = log.get_logger(CTX.ACCOUNT_STATE, user="")
        if not cls.PATH.exists():
            return None

        try:
            data = json.loads(cls.PATH.read_text())
        except Exception:
            cls.clear()
            logger.error("Unable to decode account_state.json, file inexistant or corrupted")
            notify_user("Local session data is invalid. Please log in again.")
            return None

        # Vérification de l'intégrité du fichier via l'agent
        integrity = data.get("integrity")
        if integrity and "value" in integrity:
            agent = AgentClient()
            if not agent.status():
                logger.warning("Agent unavailable for integrity check")
                cls.clear()
                return data

            data_no_integrity = {k: v for k, v in data.items() if k != "integrity"}
            mac_data = canonical_json(data_no_integrity).encode()

            # Comparaison de l'intégrité, si c'est pas bon, clear
            computed = agent.hmac(mac_data, logger)
            if not computed or computed.get("hmac") != integrity["value"]:
                logger.error("Integrity check failed for account_state.json")
                notify_user("Local account data is corrumpted. You have been logged out.")
                cls.clear()
                return None

        return data
            


    @classmethod
    def save(cls, username, salt, public_key, private_key_block, session_block, pwd):
        logger = log.get_logger(CTX.ACCOUNT_STATE, username)
        cls.PATH.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "username": username,
            "public_key": public_key,
            "salt": salt,
            "private_key": private_key_block,
            "session": session_block,
        }

        # Signature via l'agent actif
        agent = AgentClient()
        mac_data = canonical_json(payload).encode()
        mac_resp = agent.hmac(mac_data, logger)
        mac_value = mac_resp.get("hmac") if mac_resp else None

        if not mac_value:
            logger.error("Failed to compute integrity MAC via agent")
            return False

        payload["integrity"] = {"value": mac_value, "algo": "HMAC-SHA256"}

        # Création du fichier .json
        try:
            payload_json = json.dumps(payload, indent=2)
            fd = os.open(str(cls.PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload_json)
        except Exception as exc:
            logger.error(f"Unable to persist account state: {exc}")
            return False

        # Sauvegarde de certaine valeur en cache
        cls._cached_username = username
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
        cls._cached_public_key = None
        cls._cached_session_id = None # Ne nettoie pas les bytes en mémoire comme la clé privée... cela peut être une amélioration
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
            logger.debug("No local session ID available. Session is considered invalid")
            return False

        session_payload = cls.session_payload()
        if session_payload is None:
            logger.debug("Unable to build session payload. Session is considered invalid")
            return False

        # Vérifie auprès du serveur
        data = handle_resp(
            api_post("/session/verify", session_payload, user=current_user),
            required_fields=["username"],
            context=CTX.SESSION_VERIFY,
            user=current_user
        )
        if data is None:
            logger.warning(f"Local session '{sid[:8]}' invalid according to server, clearing local data")
            notify_user("Session invalid or expired. Please log in again.")
            cls.clear()
            return False

        server_username_hash = data.get("username")
        expected_hash = session_payload.get("username_hash")
        if expected_hash and server_username_hash and expected_hash != server_username_hash:
            logger.error("Session username mismatch detected; clearing local data")
            notify_user("Local session data is inconsistent. Please log in again.")
            cls.clear()
            return False

        return True

    @classmethod
    def username(cls):
        """getter du nom d'utilisateur"""
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
    def public_key(cls):
        """getter de la clé publique"""
        # Récupère la clé publique en cache
        if cls._cached_public_key is not None:
            return cls._cached_public_key
        
        # Sinon lit la clé pub stockée sur le disque
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
        
    @classmethod
    def session_payload(cls):
        session_id = cls.session_id()
        if not session_id:
            notify_user("No active session. Please log in.")
            return None
        payload = {"session_id": session_id}
        username = cls.username()
        if username:
            payload["username_hash"] = SHA256.new(username.encode()).hexdigest()
        return payload
        
    # ============================================================
    # Gestion de la clé privée : mémoire, cache et déchiffrement
    # ============================================================

    @classmethod
    def private_key(cls):
        """getter de la clé privée"""
        if cls._private_key is not None:
            return bytes(cls._private_key) 
        return cls._load_private_key_in_mem()
    
    @classmethod
    def set_private_key(cls, key_bytes):
        """setter de la clé privée"""
        cls._private_key = bytearray(key_bytes)

    @classmethod
    def clear_private_key(cls):
        """Clean propre de la clé privée en mémoire"""
        if cls._private_key is not None:
            key_obj = cls._private_key
            if isinstance(key_obj, bytearray):
                for i in range(len(key_obj)):
                    key_obj[i] = 0
        cls._private_key = None

    @classmethod
    def _load_private_key_in_mem(cls):
        """
        Recharge la clé privée chiffée du le disque lorsque le cache est vide.
        """
        return cls._load_secret_from_disk(
            field_name="private_key",
            cache_setter=cls.set_private_key,
            cache_value_transform=lambda decrypted: decrypted,
            return_transform=lambda: bytes(cls._private_key)
        )

    # ============================================================
    # Gestion de la session : cache et déchiffrement
    # ============================================================

    @classmethod
    def session_id(cls):
        """getter de l'id de session"""
        if cls._cached_session_id is not None:
            return cls._cached_session_id
        return cls._load_session_id_in_mem()

    @classmethod
    def set_session_id(cls, session_id: str):
        """setter de l'id de session"""
        cls._cached_session_id = session_id

    @classmethod
    def _load_session_id_in_mem(cls):
        """
        Recharge la session chiffrée du le disque lorsque le cache est vide.
        """
        return cls._load_secret_from_disk(
            field_name="session",
            cache_setter=cls.set_session_id,
            cache_value_transform=lambda decrypted: decrypted.decode(),
            return_transform=lambda: cls._cached_session_id
        )



    # ============================================================
    # Helpers cryptographiques & autres
    # ============================================================

    @classmethod
    def decrypt_secret(cls, enc_block_b64):
        """Déchiffre un bloc via l'agent actif."""
        agent = AgentClient()

        resp = agent.decrypt(
            enc_block_b64["enc"],
            enc_block_b64["nonce"],
            enc_block_b64["tag"]
        )
        if not resp or "plaintext" not in resp: return None

        return base64.b64decode(resp["plaintext"])
        
    @classmethod
    def encrypt_secret(cls, plaintext: bytes):
        """Chiffre un bloc via l'agent actif."""
        agent = AgentClient()
        payload = base64.b64encode(plaintext).decode()

        resp = agent.encrypt(payload)
        if not resp: return None

        return {
            "enc": resp["ciphertext"],
            "nonce": resp["nonce"],
            "tag": resp["tag"],
        }
    
    @classmethod
    def _load_secret_from_disk(cls, field_name, cache_setter, cache_value_transform, return_transform):
        """
        Mutualise la lecture/déchiffrement d'un secret stocké sur disque.
        """
        logger = log.get_logger(CTX.ACCOUNT_STATE, cls.username())
        data = cls._read()
        if not data:
            logger.debug("No local account state found")
            return None

        secret_block = data.get(field_name)
        if not secret_block:
            logger.error(f"Missing encrypted {field_name} in local account state")
            return None

        # Vérifie que l'agent est dispo
        if not AgentClient().status():
            logger.error("Agent is not running")
            notify_user("Secure agent is not running. Please log in again.")
            return None

        # Déchiffre via l'agent actif
        plaintext = cls.decrypt_secret(secret_block)
        if not plaintext:
            logger.error(f"Decryption failed for {field_name}. Session likely expired")
            notify_user("Secure agent session expired. Please log in again.")
            return None

        cache_value = cache_value_transform(plaintext)
        cache_setter(cache_value)
        cls._warm_related_secrets(data, field_name)
        return return_transform()

    @classmethod
    def _warm_related_secrets(cls, data, loaded_field):
        """
        Utilise le même mot de passe pour charger l'autre secret si nécessaire, afin d'éviter une seconde saisie utilisateur.
        """
        def _maybe_load(field_name, loader):
            secret_block = data.get(field_name)
            if not secret_block:
                return
            try:
                plaintext = cls.decrypt_secret(secret_block)
                loader(plaintext)
            except Exception:
                log.get_logger(CTX.DECRYPT, cls.username()).warning(
                    f"Unable to preload {field_name} from disk"
                )

        if loaded_field != "private_key" and cls._private_key is None:
            _maybe_load("private_key", cls.set_private_key)

        if loaded_field != "session" and cls._cached_session_id is None:
            def _set_session(plaintext):
                cls.set_session_id(plaintext.decode())
            _maybe_load("session", _set_session)

    # ============================================================
    # Gestion des vaults (cache mémoire uniquement)
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

    @classmethod
    def set_current_vault(cls, vault_id: str):
        cls._current_vault_id = vault_id

    @classmethod
    def clear_current_vault(cls):
        cls._current_vault_id = None

    @classmethod
    def current_vault(cls):
        return cls._current_vault_id

