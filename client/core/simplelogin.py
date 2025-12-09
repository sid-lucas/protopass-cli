import json, getpass
from .account_state import AccountState
from ..utils import logger as log
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.agent_client import AgentClient

# ============================================================
#  Intégration SimpleLogin (bloc chiffré unique)
# ============================================================

def load_integrations():
    """
    Récupère le blob chiffré des intégrations, le déchiffre via l'agent
    et alimente le cache en RAM (AccountState).
    """
    session_payload = AccountState.session_payload()
    if session_payload is None:
        return

    current_user = AccountState.username()
    logger = log.get_logger(CTX.INTEGRATIONS, current_user)

    # Récupère le bloc chiffré depuis le serveur
    data = handle_resp(
        api_post("/integrations/get", session_payload, user=current_user),
        context=CTX.INTEGRATIONS,
        user=current_user,
    )
    block = data.get("integrations") if data else None

    # Aucun bloc => pas d'intégrations configurées
    if not block:
        AccountState.set_cached_integrations({})
        return

    # Extraction des champs chiffrés attendus
    ciphertext_b64 = block.get("data")
    nonce_b64 = block.get("nonce")
    tag_b64 = block.get("tag")
    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        logger.error("Incomplete integrations block from server")
        AccountState.set_cached_integrations({})
        return

    # Déchiffre via l'agent (master_key)
    agent = AgentClient(autostart=False)
    if not agent.status(logger):
        notify_user("Secure agent is not running. Please log in again.")
        AccountState.set_cached_integrations({})
        return

    resp = agent.decrypt(ciphertext_b64, nonce_b64, tag_b64, logger)
    if not resp or "plaintext" not in resp:
        logger.error("Failed to decrypt integrations block via agent")
        AccountState.set_cached_integrations({})
        return

    # Parse le JSON déchiffré
    try:
        integrations = json.loads(resp["plaintext"])
        if not isinstance(integrations, dict):
            raise ValueError("integrations is not a dict")
    except Exception as exc:
        logger.error(f"Invalid integrations payload: {exc}")
        AccountState.set_cached_integrations({})
        return

    AccountState.set_cached_integrations(integrations)


def get_simplelogin_api_key():
    """
    Retourne la clé SimpleLogin depuis le cache RAM (None si absente).
    """
    integrations = AccountState.get_cached_integrations()
    return integrations.get("simplelogin", {}).get("api_key")


def set_simplelogin_api_key(api_key: str):
    """
    Met à jour la clé SimpleLogin : recharge les intégrations,
    modifie le dict, rechiffre et pousse côté serveur.
    """
    if not api_key:
        notify_user("API key cannot be empty.")
        return False

    session_payload = AccountState.session_payload()
    if session_payload is None:
        return False

    current_user = AccountState.username()
    logger = log.get_logger(CTX.SIMPLELOGIN, current_user)

    # Recharge le dernier état serveur pour éviter les collisions
    load_integrations()
    integrations = AccountState.get_cached_integrations()
    simplelogin_data = integrations.get("simplelogin") or {}
    simplelogin_data["api_key"] = api_key
    integrations["simplelogin"] = simplelogin_data

    # Chiffre le JSON des intégrations avec la master_key via l'agent
    agent = AgentClient(autostart=False)
    if not agent.status(logger):
        notify_user("Secure agent is not running. Please log in again.")
        return False

    plaintext = json.dumps(integrations)
    enc = agent.encrypt(plaintext, logger)
    if not enc:
        logger.error("Agent encryption failed for integrations block")
        notify_user("Unable to secure integrations data. Please log in again.")
        return False

    block = {"data": enc["ciphertext"], "nonce": enc["nonce"], "tag": enc["tag"]}
    payload = {**session_payload, "integrations": block}

    # Push du bloc chiffré côté serveur
    result = handle_resp(
        api_post("/integrations/set", payload, user=current_user),
        context=CTX.SIMPLELOGIN,
        user=current_user,
    )
    if result is None:
        notify_user("Failed to update SimpleLogin API key.")
        return False

    AccountState.set_cached_integrations(integrations)
    return True


def prompt_simplelogin_api_key(_args=None):
    """Demande la clé SimpleLogin en entrée cachée et la stocke chiffrée."""
    api_key = getpass.getpass("Enter SimpleLogin API key: ")
    if not api_key:
        notify_user("No API key provided.")
        return
    if set_simplelogin_api_key(api_key):
        notify_user("SimpleLogin API key updated.")
