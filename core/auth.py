import getpass
import srp
import hashlib, base64
import requests
import json
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bcrypt

SERVER_URL = "http://127.0.0.1:5000"


# ============================================================
# Helpers Internes
# ============================================================

def api_post(endpoint, payload):
    """Wrapper commun pour les requêtes POST vers le serveur Flask."""
    try:
        resp = requests.post(f"{SERVER_URL}{endpoint}", json=payload)
    except requests.exceptions.ConnectionError:
        print("Error: server unreachable")
        return None

    if resp.status_code >= 400:
        # si JSON dispo, essaie de lire le message d'erreur propre
        try:
            err = resp.json().get("Error", "")
        except Exception:
            err = resp.text
        print(f"Error ({resp.status_code}): {err}")
        return None
    return resp


# ============================================================
# Classe Session (gestion locale de session)
# ============================================================

class Session:
    """Gère la session locale du client (sauvegarde, validation, suppression)."""
    PATH = Path(__file__).resolve().parents[1] / "client_data" / "session.json"

    @classmethod
    def save(cls, username, session_id):
        cls.PATH.parent.mkdir(parents=True, exist_ok=True)
        cls.PATH.write_text(json.dumps({
            "username": username,
            "session_id": session_id
        }, indent=2))

    @classmethod
    def load(cls):
        if not cls.PATH.exists():
            return None
        try:
            data = json.loads(cls.PATH.read_text())
            return data.get("session_id")
        except Exception:
            return None

    @classmethod
    def clear(cls):
        if cls.PATH.exists():
            cls.PATH.unlink()

    @classmethod
    def valid(cls):
        """Vérifie si la session locale existe et est encore valide côté serveur."""
        sid = cls.load()
        if not sid:
            return False

        resp = api_post("/session/verify", {"session_id": sid})
        if not resp:
            return False
        return resp.json().get("valid", False)


# ============================================================
# Commandes CLI
# ============================================================

def init_vault(_args):
    print("salut a tous")

def register_account(args):
    """Création d'un nouveau compte utilisateur."""
    # vérifie qu'on est pas déjà connecté
    if Session.valid():
        print("You are already logged in. Please logout before creating a new account.")
        return

    username = args.username
    print(f"Creation of a new account '{username}'")

    # Demande du mot de passe
    password = getpass.getpass("Enter your password: ")

    # Générer (salt + verifier) selon SRP
    salt, vkey = srp.create_salted_verification_key(
        username, password,
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )
    # Encode en b64
    salt_b64 = base64.b64encode(salt).decode()
    vkey_b64 = base64.b64encode(vkey).decode()

    # Dériver une clé symétrique via bcrypt en prenant le password et le sel du compte
    aes_key = bcrypt.kdf(
        password=password.encode(),
        salt=salt,
        desired_key_bytes=32,
        rounds=12  # facteur de coût
    )

    # Génération de la paire de clé RSA (2048 bits) appelée 'user key'
    # Ces clés seront stockée sur le serveur afin de permettre le multiplateforme
    key = RSA.generate(2048)
    private_user_key = key.export_key(format='DER')
    public_user_key = key.publickey().export_key(format='DER')
    
    # Chiffrement de la clé privée user key avec la clé dérivée bcrypt
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    private_user_key_enc, tag = cipher.encrypt_and_digest(private_user_key)

    # Préparation du JSON
    payload = {
        "username": username,
        "salt": salt_b64,
        "vkey": vkey_b64,
        "public_key": base64.b64encode(public_user_key).decode(),
        "private_key_enc": base64.b64encode(private_user_key_enc).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    # envoi au serveur sur la route /register
    resp = api_post("/register", payload)
    if not resp:
        return

    
    print(f"The account '{username}' has been succesfully created")

def login_account(args):
    """Authentification d'un utilisateur existant via SRP."""
    # Vérifie si une session locale est déjà active
    if Session.valid():
        print("You are already logged in. Please logout first.")
        return

    username = args.username
    password = getpass.getpass(f"Enter your password of '{username}': ")

    # Création de l'objet SRP côté clien
    usr = srp.User(
        username.encode(),
        password.encode(),
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )

    # client calcul sa clé publique (A)
    _, A = usr.start_authentication()

    payload = {
        "username": username,
        "A": base64.b64encode(A).decode()
    }

    # Envoi au serveur
    resp = api_post("/srp/start", payload)
    if not resp:
        return


    # Réception du set et clé publique (B) du serveur
    data = resp.json()
    salt = base64.b64decode(data["salt"])
    B = base64.b64decode(data["B"])

    # Validation du challenge
    M = usr.process_challenge(salt, B)

    # Envoi de la preuve au serveur pour vérification
    payload = {"M": base64.b64encode(M).decode()}
    resp = api_post("/srp/verify", payload)
    if not resp:
        return


    data = resp.json()
    HAMK = base64.b64decode(data["HAMK"])

    # Validation finale
    session_id = data.get("session_id")
    usr.verify_session(HAMK)
    if usr.authenticated() and session_id:
        Session.save(username, session_id)
        print(f"Login successful, welcome {username}.")
    else:
        print("Error: incorrect username or password")

def logout_account(_args):
    """Déconnexion de l'utilisateur (révocation de la session côté client et serveur)."""
    session_id = Session.load()
    if not session_id:
        print("No active session found.")
        return

    resp = api_post("/session/logout", {"session_id": session_id})
    if not resp:
        return

    Session.clear()
    print("Logout successful. Session terminated.")

