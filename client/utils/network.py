import requests
from client.utils import logger as log
from client.utils.logger import CTX

SERVER_URL = "http://127.0.0.1:5000"

# Format des réponses JSON attendues du serveur :
#{
#  "status": "ok" | "error",
#  "context": "Register" | "SRP start" | "SRP verify" | "Session" | "UserKey",
#  "message": "Texte détaillant une erreur ou un succès",
#  "data": { ... optionnel ... }
#}


def api_post(endpoint, payload=None, user=None):
    """
    Envoie une requête POST au serveur et gère les logs réseau.

    Args:
        endpoint (str): Route API cible.
        payload (dict, optional): Corps JSON envoyé.
        user (str, optional): Identifiant utilisateur pour enrichir les logs.
    """
    
    url = f"{SERVER_URL}{endpoint}"

    logger = log.get_logger(CTX.NETWORK, user)

    try:
        logger.debug(f"Sending POST {endpoint}")
        resp = requests.post(url, json=payload or {})
        logger.debug(f"Received {resp.status_code} from {endpoint}")
        #resp.raise_for_status()
        return resp

    except requests.exceptions.ConnectionError:
        logger.error(f"unable to connect to {url}")
        return None

    except requests.exceptions.Timeout:
        logger.error(f"request to {url} timed out")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"request error on {url}: {e}")
        return None


def handle_resp(resp, required_fields=None, context=CTX.NETWORK, user=None):
    """
    Analyse et logue la réponse serveur normalisée.

    Args:
        resp: La réponse HTTP du serveur.
        required_fields (list, optional): Liste des champs attendus dans la clé 'data' de la réponse.
        context (str, optional): Contexte pour le logging.
        user (str, optional): Identifiant utilisateur associé à la requête (pour les logs).

    Returns:
        dict or None: Les données extraites de la réponse si succès et champs requis présents, sinon None.
    """

    logger = log.get_logger(context, user)

    if resp is None:
        logger.error("No response received")
        return None

    # Décodage JSON
    try:
        payload = resp.json()
    except Exception as e:
        logger.error(f"Invalid JSON response: {e}")
        return None

    payload_context = payload.get("context", context)
    logger = log.get_logger(payload_context, user)

    status = payload.get("status")
    if status == "error":
        logger.error(payload.get("message", "unknown server error"))
        return None

    if status == "ok":
        logger.info(payload.get("message", "operation successful"))
        data = payload.get("data", {})

        # Vérifie les champs requis uniquement en cas de succès
        if required_fields:
            missing = [f for f in required_fields if f not in data]
            if missing:
                logger.error(f"Missing fields in response data: {missing}")
                return None

        return data

    logger.error("Invalid response status")
    return None
