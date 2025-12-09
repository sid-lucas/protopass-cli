import getpass, os, requests
from . import integrations
from ..account_state import AccountState
from ...utils import logger as log
from ...utils.logger import CTX, notify_user

SIMPLELOGIN_API_URL = os.getenv("SIMPLELOGIN_API_URL", "https://api.simplelogin.io/api/v2")

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


def list_mailboxes(_args=None):
    """
    Liste les mailboxes disponibles via l'API SimpleLogin.
    """
    api_key = get_api_key()
    if not api_key:
        notify_user("No SimpleLogin API key configured.\nUse: integration simplelogin set-key <api_key>")
        return
    api_key = api_key.strip()
    if not api_key:
        notify_user("Stored SimpleLogin API key is empty or invalid. Please set it again.")
        return

    logger = log.get_logger(CTX.SIMPLELOGIN, AccountState.username())
    url = _build_url("mailboxes")

    try:
        resp = requests.get(url, headers=_api_headers(api_key), timeout=10)
    except Exception as exc:
        logger.error(f"Failed to contact SimpleLogin API: {exc}")
        notify_user("Unable to reach SimpleLogin API.")
        return

    if resp.status_code != 200:
        logger.error(f"SimpleLogin mailboxes failed with HTTP {resp.status_code}: {resp.text}")
        notify_user("Failed to list mailboxes. Check your API key.")
        return

    try:
        payload = resp.json()
    except Exception as exc:
        logger.error(f"Invalid JSON from SimpleLogin: {exc}")
        notify_user("Failed to parse SimpleLogin response.")
        return

    mailboxes = payload.get("mailboxes")
    if mailboxes is None:
        # fallback if API returns a list directly
        mailboxes = payload if isinstance(payload, list) else []

    if not mailboxes:
        notify_user("No mailboxes found on SimpleLogin.")
        return

    print("Mailboxes:")
    for mbox in mailboxes:
        mid = mbox.get("id", "-")
        email = mbox.get("email", "-")
        name = mbox.get("name") or mbox.get("label") or ""
        enabled = mbox.get("enabled")
        enabled_disp = "enabled" if enabled or enabled is None else "disabled"
        print(f" - {mid}: {email} {f'({name})' if name else ''} [{enabled_disp}]")
