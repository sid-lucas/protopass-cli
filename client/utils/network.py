import requests
from client.utils.logger import log_client

SERVER_URL = "http://127.0.0.1:5000"

# Format des réponses JSON attendues du serveur :
#{
#  "status": "ok" | "error",
#  "context": "Register" | "SRP start" | "SRP verify" | "Session" | "UserKey",
#  "message": "Texte détaillant une erreur ou un succès",
#  "data": { ... optionnel ... }
#}


def api_post(endpoint, payload={}):
    """Envoie une requête POST au serveur."""
    try:
        resp = requests.post(f"{SERVER_URL}{endpoint}", json=payload)
        resp.raise_for_status()
        return resp
    except requests.exceptions.ConnectionError:
        log_client("error", f"API POST {endpoint}", "unable to connect to server")
        return None
    except requests.exceptions.RequestException as e:
        log_client("error", f"API POST {endpoint}", str(e))
        return None

def check_resp(resp, required_fields=None, context="Server"):
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
    server_context = payload.get("context", context)
    message = payload.get("message", "")
    data = payload.get("data", {})

    # Statut d'erreur
    if status == "error":
        log_client("error", server_context, message or "unknown server error")
        return None

    # Statut succès
    if status == "ok":
        log_client("info", server_context, message or "operation successful")

    # Vérifie la présence des champs requis dans data
    if required_fields:
        missing = [f for f in required_fields if f not in data]
        if missing:
            log_client("error", server_context, f"missing fields in response data: {missing}")
            return None

    return data

