import requests
from .logger import log

SERVER_URL = "http://127.0.0.1:5000"

# Format des réponses JSON serveur :
#{
#  "status": "ok" | "error",
#  "context": "Register" | "SRP start" | "SRP verify" | "Session" | "UserKey",
#  "message": "Texte humain lisible (succès ou erreur)",
#  "data": { ... optionnel ... }
#}


def api_post(endpoint, payload=None):
    """Envoie une requête POST au serveur."""
    try:
        resp = requests.post(f"{SERVER_URL}{endpoint}", json=payload or {})
        resp.raise_for_status()
        return resp
    except requests.exceptions.ConnectionError:
        log("error", f"API POST {endpoint}", "unable to connect to server")
        return None
    except requests.exceptions.RequestException as e:
        log("error", f"API POST {endpoint}", str(e))
        return None

def check_resp(resp, required_fields=None, context="Server response"):
    """Vérifie la cohérence logique d'une réponse JSON serveur."""
    if not resp:
        log("error", context, "no response received")
        return None
    try:
        data = resp.json()
    except Exception as e:
        log("error", context, f"invalid JSON response: {e}")
        return None
    if data.get("status") == "error":
        log("error", data.get("context", context), data.get("message", "unknown error"))
        return None
    if required_fields:
        missing = [f for f in required_fields if f not in data]
        if missing:
            log("error", context, f"missing fields in response: {missing}")
            return None
    return data
