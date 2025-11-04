from flask import Flask, request
from server.user_store import add_user, get_user
from server.vault_store import add_vault, get_vault
from server.session_store import create_session, revoke_session, is_valid, get_session
import base64, srp
from functools import wraps
from server.utils.response import make_resp

app = Flask(__name__)


# ============================================================
#  Helpers internes et Décorateurs
# ============================================================

def require_session(func):
    """Décorateur Flask, empêche qu'une route soit appelée sans session valide."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        data = request.get_json(force=True) or {}
        token = data.get("session_id")

        if not token:
            return make_resp("error", "Session", "missing session_id", 400)

        if not is_valid(token):
            return make_resp("error", "Session", "invalid or expired session", 401)

        s = get_session(token)
        if not s:
            return make_resp("error", "Session", "session not found", 401)

        # injecte le username validé dans les arguments de la route
        return func(*args, username=s["username"], **kwargs)
    return wrapper


# ============================================================
#  Routes publiques (pas de session requise)
# ============================================================

@app.post("/register")
def register():
    """Enregistre un nouvel utilisateur avec ses données SRP et sa user_key."""
    data = request.get_json(force=True)

    try:
        username = data["username"]
        add_user(
            username, data["salt"], data["vkey"],
            data["public_key"], data["private_key_enc"], data["nonce"], data["tag"]
        )
    # Erreur données manquantes
    except KeyError as e:
        return make_resp("error", "Register", f"missing required fields: {e}", 400)
    # Erreur utilisateur déjà existant
    except ValueError as e:
        return make_resp("error", "Register", "user already exists", 409)

    # Succès, création de l'utilisateur
    return make_resp(
        "ok", "Register", "user created successfully", 201,
        data={"username": username}
    )

@app.post("/srp/start")
def srp_start():
    """Démarre le protocole SRP côté serveur."""
    # serveur recoit username et clé publique du client (A)
    data = request.get_json(force=True)
    username = data.get("username")
    A_b64 = data.get("A")

    if not username or not A_b64:
        return make_resp("error", "SRP start", "missing username or A", 400)

    user = get_user(username)
    if not user:
        return make_resp("error", "SRP start", f"unknown user '{username}'", 404)

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
        return make_resp("error", "SRP start", "invalid SRP A value", 400)

    # Stocke l’objet Verifier pour la suite, et username pour la gestion de session
    app.config["SRP_SESSION"] = v
    app.config["CURRENT_USER"] = username


    # envoie au client le sel et la clé publique server (B)
    return make_resp("ok", "SRP start", "challenge generated", 200,
        data={
            "salt": user["salt"],
            "B": base64.b64encode(B).decode()
        }
    )

@app.post("/srp/verify")
def srp_verify():
    """Vérifie le challenge SRP complété par le client."""
    # serveur recoit le challenge complété par le client
    data = request.get_json(force=True)
    M_b64 = data.get("M")

    v = app.config.get("SRP_SESSION")
    if not v:
        return make_resp("error", "SRP verify", "no active SRP session", 400)

    if not M_b64:
        return make_resp("error", "SRP verify", "missing M", 400)

    M = base64.b64decode(M_b64)

    HAMK = v.verify_session(M)
    if HAMK is None:
        return make_resp("error", "SRP verify", "bad proof", 403)
 
    # Authentification SRP réussie -> création d'une session côté serveur
    username = app.config.get("CURRENT_USER", "unknown")
    session_id = create_session(username)

    # donne au client la preuve et token de session
    # /!\ ATTENTION
    # /!\ le token de session est transféré en clair, implémenter TLS en production !
    return make_resp("ok", "SRP verify", "authentication successful", 200,
        data={
            "HAMK": base64.b64encode(HAMK).decode(),
            "session_id": session_id
        }
    )


# ============================================================
#  Routes protégées (requièrent une session valide)
# ============================================================

@app.post("/session/verify")
@require_session
def verify_session(username):
    """
    Permet au client de vérifier la validité de sa session avant d'exécuter une commande protégée.
    """

    return make_resp("ok", "Session verify", "session is valid", 200,
        data={"username": username}
    )

@app.post("/session/logout")
def logout_session():
    """
    Révoque une session côté serveur.
    """

    data = request.get_json(force=True)
    token = data.get("session_id")

    if not token:
        return make_resp("error", "Session logout", "missing session_id", 400)

    # Supprime la session côté serveur et informe le client
    revoke_session(token)
    return make_resp("ok", "Session logout", f"Session {token[:10]}... revoked", 200)

@app.post("/userkey")
@require_session
def get_userkey(username):
    """
    Retourne la user_key de l'utilisateur authentifié.
    """

    user = get_user(username)
    if not user:
        return make_resp("error", "User key", "user not found", 404)

    return make_resp("ok", "User key", "user key retrieved", 200,
        data={"user_key": user["user_key"]}
    )

@app.post("/vault/create")
@require_session
def create_vault(username):
    """
    Crée un nouveau vault pour l'utilisateur authentifié.
    """
    data = request.get_json(force=True)

    try:
        vault_id = data["vault_id"]
        add_vault(
            vault_id, data["key_enc"], data["signature"],
            data["name"], data["items"]
        )
    # Erreur données manquantes
    except KeyError as e:
        return make_resp("error", "Vault Create", f"missing required fields: {e}", 400)
    # Erreur utilisateur déjà existant
    except ValueError as e:
        return make_resp("error", "Vault Create", str(e), 409)

    # stocke simplement les données reçues concernant le nouveau vault
    return make_resp("ok", "Vault create", "vault created successfully", 201,
        data={"vault_id": vault_id}
    )


# ============================================================
#  Point d'entrée serveur
# ============================================================
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)