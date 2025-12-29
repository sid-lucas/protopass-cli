import getpass, os, requests, json, uuid
from datetime import datetime, timezone
from . import integrations
from .. import vault
from ..account_state import AccountState
from ..item_schema import Type
from ...utils import logger as log
from ...utils.logger import CTX, notify_user
from ...utils.crypto import encrypt_b64_block
from ...utils.network import api_post, handle_resp

SIMPLELOGIN_API_URL = os.getenv("SIMPLELOGIN_API_URL", "https://api.simplelogin.io")

def _api_headers(api_key: str) -> dict:
    return {
        "Authentication": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _build_url(path: str) -> str:
    base = SIMPLELOGIN_API_URL.rstrip("/")
    return f"{base}/{path.lstrip('/')}"


def get_api_key():
    """
    Retourne la clé SimpleLogin depuis le cache RAM (None si absente).
    """
    integrations_data = integrations.get_cached()
    key = integrations_data.get("simplelogin", {}).get("api_key")
    if isinstance(key, str):
        key = key.strip()
    return key


def set_api_key(api_key: str):
    """
    Met à jour la clé SimpleLogin : recharge les intégrations,
    modifie le dict, rechiffre et pousse côté serveur.
    """
    if api_key:
        api_key = api_key.strip()
    if not api_key:
        notify_user("API key cannot be empty.")
        return False

    # Recharge le dernier état serveur pour éviter les collisions
    integrations.load_all()
    integrations_data = integrations.get_cached()
    simplelogin_data = integrations_data.get("simplelogin") or {}
    simplelogin_data["api_key"] = api_key
    integrations_data["simplelogin"] = simplelogin_data

    ok = integrations.update_all(integrations_data)
    if not ok:
        notify_user("Failed to update SimpleLogin API key.")
        return False

    logger = log.get_logger(CTX.SIMPLELOGIN, AccountState.username())
    logger.info("SimpleLogin API key updated")
    return True


def prompt_set_api_key(args=None):
    """
    Demande la clé SimpleLogin en entrée cachée et la stocke chiffrée.
    Si une valeur est fournie en argument, elle est utilisée directement.
    """
    # Vérifie si une clé est fournie en argument ou si on passe en prompt interactif
    provided = getattr(args, "api_key", None) if args else None
    api_key = provided or getpass.getpass("Enter SimpleLogin API key: ")
    if api_key:
        api_key = api_key.strip()
    if not api_key:
        notify_user("No API key provided.")
        return
    if set_api_key(api_key):
        notify_user("SimpleLogin API key updated.")


def clear_api_key():
    """
    Supprime la clé SimpleLogin de l'utilisateur et nettoie le bloc d'intégrations.
    """
    integrations.load_all()
    data = integrations.get_cached()

    if "simplelogin" not in data:
        notify_user("No SimpleLogin API key to remove.")
        return False

    data.pop("simplelogin", None)

    if integrations.update_all(data):
        notify_user("SimpleLogin API key removed.")
        return True

    notify_user("Failed to remove SimpleLogin API key.")
    return False


def _create_alias_item(alias_email: str, alias_id: str | None, note: str | None):
    """
    Crée un item de type alias dans le vault courant avec les champs essentiels.
    """
    logger = log.get_logger(CTX.ITEM_CREATE, AccountState.username())

    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>.")
        return False

    vault_key = vault.ensure_vault_key(vault_id, logger)
    if vault_key is None:
        notify_user("Vault key not available. Try selecting the vault again.")
        return False

    now = datetime.now(timezone.utc).isoformat()
    plaintext = {
        "type": Type.ALIAS.value,
        "name": alias_email,
        "email": alias_email,
        "created_at": now,
        "updated_at": now,
    }
    if note:
        plaintext["notes"] = note
    if alias_id:
        plaintext["alias_id"] = alias_id

    plaintext_json = json.dumps(plaintext).encode()

    item_id = str(uuid.uuid4())
    item_key = os.urandom(32)

    key_block = encrypt_b64_block(vault_key, item_key)
    content_block = encrypt_b64_block(item_key, plaintext_json)

    payload = {
        **AccountState.session_payload(),
        "vault_id": vault_id,
        "item": {
            "item_id": item_id,
            "key": key_block,
            "content": content_block
        }
    }
    resp = api_post("/item/create", payload)
    data = handle_resp(resp, required_fields=["item_id"], context=CTX.ITEM_CREATE)

    if data is None:
        notify_user("Alias creation failed.")
        return False

    notify_user(f"Alias '{alias_email}' created in vault.")
    return True


def create_alias(_args=None):
    """
    Crée un alias SimpleLogin aléatoire via /api/alias/random/new
    et le stocke comme item alias (alias, alias_id).
    """
    # Recharge le bloc d'intégrations si nécessaire
    if not integrations.get_cached():
        integrations.load_all()

    api_key = get_api_key()
    if not api_key:
        notify_user("No SimpleLogin API key configured.\nUse: integration simplelogin set-key <api_key>")
        return
    api_key = api_key.strip()
    if not api_key:
        notify_user("Stored SimpleLogin API key is empty or invalid. Please set it again.")
        return

    logger = log.get_logger(CTX.SIMPLELOGIN, AccountState.username())

    url = _build_url("api/alias/random/new")
    payload = {}

    try:
        resp = requests.post(url, headers=_api_headers(api_key), json=payload, timeout=10)
    except Exception as exc:
        logger.error(f"Failed to contact SimpleLogin API: {exc}")
        notify_user("Unable to reach SimpleLogin API.")
        return

    if resp.status_code not in (200, 201):
        logger.error(f"SimpleLogin create alias failed with HTTP {resp.status_code}: {resp.text}")
        notify_user(f"Failed to create alias on SimpleLogin (HTTP {resp.status_code}).")
        return

    try:
        data = resp.json()
    except Exception as exc:
        logger.error(f"Invalid JSON from SimpleLogin create alias: {exc}")
        notify_user("Failed to parse SimpleLogin response.")
        return

    alias_email = None
    alias_id = None
    if isinstance(data, dict):
        alias_email = data.get("email") or data.get("alias")
        alias_id = data.get("id")
        if not alias_email and isinstance(data.get("alias"), dict):
            alias_email = data["alias"].get("email")
            alias_id = data["alias"].get("id", alias_id)

    if not alias_email:
        notify_user("SimpleLogin did not return an alias email.")
        return

    _create_alias_item(alias_email, alias_id, None)
