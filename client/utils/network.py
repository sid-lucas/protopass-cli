import requests
from utils.logger import log_client

SERVER_URL = "http://127.0.0.1:5000"

# Format des réponses JSON attendues du serveur :
#{
#  "status": "ok" | "error",
#  "context": "Register" | "SRP start" | "SRP verify" | "Session" | "UserKey",
#  "message": "Texte détaillant une erreur ou un succès",
#  "data": { ... optionnel ... }
#}


def api_post(endpoint, payload=None):
    """
    Envoie une requête POST au serveur et gère les logs réseau.
    """
    
    url = f"{SERVER_URL}{endpoint}"

    try:
        log_client("info", "Network", f"sending POST {endpoint}")
        resp = requests.post(url, json=payload or {})
        log_client("info", "Network", f"received {resp.status_code} from {endpoint}")
        resp.raise_for_status()
        return resp

    except requests.exceptions.ConnectionError:
        log_client("error", "Network", f"unable to connect to {url}")
        return None

    except requests.exceptions.Timeout:
        log_client("error", "Network", f"request to {url} timed out")
        return None

    except requests.exceptions.RequestException as e:
        log_client("error", "Network", f"request error on {url}: {e}")
        return None


def handle_resp(resp, required_fields=None, context="Server"):
    """
    Analyse et logue la réponse serveur normalisée.

    Args:
        resp: La réponse HTTP du serveur.
        required_fields (list, optional): Liste des champs attendus dans la clé 'data' de la réponse.
        context (str, optional): Contexte pour le logging.

    Returns:
        dict or None: Les données extraites de la réponse si succès et champs requis présents, sinon None.
    """

    if not resp:
        log_client("error", context, "no response received")
        return None

    # Décodage JSON
    try:
        payload = resp.json()
    except Exception as e:
        log_client("error", context, f"invalid JSON response: {e}")
        return None

    status = payload.get("status")

    if status == "error":
        log_client("error", payload.get("context", context), payload.get("message", "unknown server error"))
        return None

    if status == "ok":
        log_client("info", payload.get("context", context), payload.get("message", "operation successful"))
        data = payload.get("data", {})

        # Vérifie les champs requis uniquement en cas de succès
        if required_fields:
            missing = [f for f in required_fields if f not in data]
            if missing:
                log_client("error", payload.get("context", context), f"missing fields in response data: {missing}")
                return None

        return data

    log_client("error", context, "invalid response status")
    return None
