from flask import Flask, request, jsonify
from server.user_store import add_user, get_user
from server.session_store import create_session, revoke_session, is_valid, get_session
import base64, srp
import os, time


app = Flask(__name__)


@app.post("/register")
def register():
    data = request.get_json(force=True)
    try:
        add_user(
            data["username"], data["salt"], data["vkey"],
            data["public_key"], data["private_key_enc"], data["nonce"], data["tag"]
        )
    except KeyError as e:
        return jsonify({"Error": str(e)}), 400 #données manquantes -> Bad Request
    except ValueError as e:
        return jsonify({"Error": str(e)}), 409 #utilisateur existe déjà -> Conflit

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
    
    # Authentification SRP réussie -> création d'une session côté serveur
    username = app.config.get("CURRENT_USER", "unknown")
    session_id = create_session(username, ttl_seconds=3600)

    print(f"[SERVER] New session for '{username}' ({session_id[:10]}...)")

    # donne au client la preuve et token de session
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

    if not token:
        return jsonify({"valid": False}), 401

    # vérifie via le store central
    if not is_valid(token):
        return jsonify({"valid": False}), 401

    s = get_session(token)
    return jsonify({
        "valid": True,
        "username": s["username"]
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




