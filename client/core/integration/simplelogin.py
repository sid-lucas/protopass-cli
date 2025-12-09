import getpass
from . import integrations
from ..account_state import AccountState
from ...utils import logger as log
from ...utils.logger import CTX, notify_user


def get_api_key():
    """
    Retourne la clé SimpleLogin depuis le cache RAM (None si absente).
    """
    integrations_data = integrations.get_cached()
    return integrations_data.get("simplelogin", {}).get("api_key")


def set_api_key(api_key: str):
    """
    Met à jour la clé SimpleLogin : recharge les intégrations,
    modifie le dict, rechiffre et pousse côté serveur.
    """
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


def prompt_set_api_key(_args=None):
    """Demande la clé SimpleLogin en entrée cachée et la stocke chiffrée."""
    api_key = getpass.getpass("Enter SimpleLogin API key: ")
    if not api_key:
        notify_user("No API key provided.")
        return
    if set_api_key(api_key):
        notify_user("SimpleLogin API key updated.")
