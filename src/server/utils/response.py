from flask import jsonify
from server.utils.logger import log_server

def make_resp(status, context, message="", http_code=200, data=None):
    """
    Crée une réponse JSON normalisée.
    """

    # Log the response status
    if status == "ok":
        log_server("info", context, message)
    elif status == "error":
        log_server("error", context, message)
    else:
        log_server("warning", context, message)

    payload = {
        "status": status,
        "context": context,
        "message": message,
    }
    if data is not None:
        payload["data"] = data

    return jsonify(payload), http_code
