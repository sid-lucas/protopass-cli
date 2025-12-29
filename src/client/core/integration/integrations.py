import json
from ..account_state import AccountState
from ...utils import logger as log
from ...utils.logger import CTX, notify_user
from ...utils.network import api_post, handle_resp
from ...utils.agent_client import AgentClient


def load_all():
    """
    Récupère le blob chiffré des intégrations, le déchiffre via l'agent
    et alimente le cache en RAM (AccountState).
    """
    current_user = AccountState.username()
    logger = log.get_logger(CTX.INTEGRATIONS, current_user)

    # 1) Tente d'utiliser le bloc chiffré local si présent
    block = AccountState.integrations_block()

    # 2) Sinon, récupère le bloc chiffré depuis le serveur
    if block is None:
        session_payload = AccountState.session_payload()
        if session_payload is None:
            return
        data = handle_resp(
            api_post("/integrations/get", session_payload, user=current_user),
            context=CTX.INTEGRATIONS,
            user=current_user,
        )
        block = data.get("integrations") if data else None
        # Persist localement le bloc chiffré reçu (pour éviter re-fetch)
        if block:
            AccountState.set_integrations_block(block)

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


def update_all(integrations: dict) -> bool:
    """
    Chiffre et pousse le dictionnaire complet d'intégrations.
    """
    if not isinstance(integrations, dict):
        notify_user("Invalid integrations data.")
        return False

    session_payload = AccountState.session_payload()
    if session_payload is None:
        return False

    current_user = AccountState.username()
    logger = log.get_logger(CTX.INTEGRATIONS, current_user)

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
        context=CTX.INTEGRATIONS,
        user=current_user,
    )
    if result is None:
        notify_user("Failed to update integrations.")
        return False

    AccountState.set_cached_integrations(integrations)
    AccountState.set_integrations_block(block)
    return True


def get_cached() -> dict:
    return AccountState.get_cached_integrations()
