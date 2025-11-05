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


def api_post(endpoint, payload=None, user=None):
    """
    Envoie une requête POST au serveur et gère les logs réseau.

    Args:
        endpoint (str): Route API cible.
        payload (dict, optional): Corps JSON envoyé.
        user (str, optional): Identifiant utilisateur pour enrichir les logs.
    """
    
    url = f"{SERVER_URL}{endpoint}"

    try:
        log_client("info", "Network", f"sending POST {endpoint}", user=user)
        resp = requests.post(url, json=payload or {})
        log_client("info", "Network", f"received {resp.status_code} from {endpoint}", user=user)
        resp.raise_for_status()
        return resp

    except requests.exceptions.ConnectionError:
        log_client("error", "Network", f"unable to connect to {url}", user=user)
        return None

    except requests.exceptions.Timeout:
        log_client("error", "Network", f"request to {url} timed out", user=user)
        return None

    except requests.exceptions.RequestException as e:
        log_client("error", "Network", f"request error on {url}: {e}", user=user)
        return None


def handle_resp(resp, required_fields=None, context="Server", user=None):
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

    if not resp:
        log_client("error", context, "no response received", user=user)
        return None

    # Décodage JSON
    try:
        payload = resp.json()
    except Exception as e:
        log_client("error", context, f"invalid JSON response: {e}", user=user)
        return None

    status = payload.get("status")

    if status == "error":
        log_client("error", payload.get("context", context), payload.get("message", "unknown server error"), user=user)
        return None

    if status == "ok":
        log_client("info", payload.get("context", context), payload.get("message", "operation successful"), user=user)
        data = payload.get("data", {})

        # Vérifie les champs requis uniquement en cas de succès
        if required_fields:
            missing = [f for f in required_fields if f not in data]
            if missing:
                log_client("error", payload.get("context", context), f"missing fields in response data: {missing}", user=user)
                return None

        return data

    log_client("error", context, "invalid response status", user=user)
    return None
