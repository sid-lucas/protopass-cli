from flask import Flask, request, jsonify
from server.user_store import add_user, get_user
import base64, srp
import os, time
import json
from pathlib import Path

SESSIONS_PATH = Path(__file__).resolve().parent / "server_data" / "sessions.json"

def _load_sessions():
    SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SESSIONS_PATH.exists():
        SESSIONS_PATH.write_text("{}")
    try:
        return json.loads(SESSIONS_PATH.read_text())
    except Exception:
        return {}

def _save_sessions(sessions):
    SESSIONS_PATH.write_text(json.dumps(sessions, indent=2))


app = Flask(__name__)
# Rechargement des sessions en mémoire après reboot
app.config["SESSIONS"] = _load_sessions()


@app.post("/register")
def register():
    data = request.get_json(force=True)
    try:
        add_user(
            data["username"], data["salt"], data["vkey"],
            data["public_key"], data["private_key_enc"], data["nonce"], data["tag"]
        )
    except ValueError as e:
        return jsonify({"Error": str(e)}), 400

    print(f"[SERVER] Registered new user '{data['username']}'.")
    return jsonify({"status": "ok", "username": data['username']}), 201




@app.post("/srp/start")
def srp_start():
    # serveur recoit username et clé publique du client (A)
    data = request.get_json(force=True)
    username = data.get("username")
    A_b64 = data.get("A")

    if not username or not A_b64:
        return jsonify({"Error": "missing username or A"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"Error": "unknown user"}), 404

    # Decode valeurs depuis base64
    A = base64.b64decode(A_b64)
    salt = base64.b64decode(user["salt"])
    vkey = base64.b64decode(user["vkey"])

    # Création de l’objet SRP côté serveur
    v = srp.Verifier(
        username.encode(),
        salt,
        vkey,
        A,
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )

    # serveur calcul sa clé publique (B)
    s_B, B = v.get_challenge()
    if s_B is None or B is None:
        return jsonify({"Error": "invalid SRP A value"}), 400

    # Stocke l’objet Verifier pour la suite, et username pour la gestion de session
    app.config["SRP_SESSION"] = v
    app.config["CURRENT_USER"] = username


    # envoie au client le sel et la clé publique server (B)
    return jsonify({
        "salt": user["salt"],
        "B": base64.b64encode(B).decode()
    }), 200

@app.post("/srp/verify")
def srp_verify():
    # serveur recoit le challenge complété par le client
    data = request.get_json(force=True)
    M_b64 = data.get("M")

    v = app.config.get("SRP_SESSION")
    if not v:
        return jsonify({"Error": "no active SRP session"}), 400

    if not M_b64:
        return jsonify({"Error": "missing M"}), 400

    M = base64.b64decode(M_b64)

    HAMK = v.verify_session(M)
    if HAMK is None:
        return jsonify({"Error": "bad proof"}), 403

    # sinon : authentification réussie
    print("[SERVER] SRP authentification successfull")
    
    
    # Génère un identifiant de session sécurisé
    session_id = base64.urlsafe_b64encode(os.urandom(32)).decode()
    username = app.config.get("CURRENT_USER", "unknown")


    # Initialise le stockage des sessions si nécessaire
    if "SESSIONS" not in app.config:
        app.config["SESSIONS"] = {}

    # Stocke la session en mémoire avec expiration (1 heure ici)
    app.config["SESSIONS"][session_id] = {
        "username": username,
        "created": time.time(),
        "expires": time.time() + 3600
    }
    # Stocke la session dans sa database
    _save_sessions(app.config["SESSIONS"])

    print(f"[SERVER] New session for '{username}' ({session_id[:10]}...)")

    #donne au client HAMK et session_id
    return jsonify({
        "HAMK": base64.b64encode(HAMK).decode(),
        "session_id": session_id
    }), 200


# avant d'exec une commande, le cli contacte le serveur pour vérifier que le session_id est ok
# vérifie la présence et la validité temporelle du session_id
@app.post("/session/verify")
def verify_session():
    data = request.get_json(force=True)
    token = data.get("session_id")

    # vérifie la validité de la session que le client a fourni
    sessions = app.config.get("SESSIONS", {})
    session_data = sessions.get(token)

    # invalide si token absent ou expiré
    if not session_data or time.time() > session_data["expires"]:
        return jsonify({"valid": False}), 401

    # Nettoyage automatique de toutes les session expirées
    expired_tokens = [sid for sid, s in sessions.items() if time.time() > s["expires"]]
    for sid in expired_tokens:
        del sessions[sid]
    if expired_tokens:
        _save_sessions(sessions)


    return jsonify({
        "valid": True,
        "username": session_data["username"]
    }), 200


@app.post("/session/logout")
def logout_session():
    data = request.get_json(force=True)
    token = data.get("session_id")

    sessions = app.config.get("SESSIONS", {})
    if token in sessions:
        del sessions[token]
        print(f"[SERVER] Session {token[:10]}... deleted")
        return jsonify({"status": "logged_out"}), 200

    return jsonify({"Error": "invalid session"}), 400










if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)




