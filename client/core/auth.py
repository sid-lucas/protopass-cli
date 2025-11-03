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
from utils.network import api_post, handle_resp
from utils.logger import log_client

class Session:
    """
    Gère la session locale du client (sauvegarde, validation, suppression).
    Les sessions sont identifiées par un session_id fourni par le serveur.
    """

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

        data = handle_resp(
            api_post("/session/verify", {"session_id": sid}),
            required_fields=["username"],
            context="Session verify"
        )
        if data is None:
            cls.clear()

        return bool(data)


def register_account(args):
    """
    Création d'un nouveau compte utilisateur.
    """

    # vérifie qu'on est pas déjà connecté
    if Session.valid():
        log_client("info", "Register", "User is already logged in.")
        return

    username = args.username
    log_client("info", "Register", f"Starting registration for username '{username}'")

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
        rounds=200  # facteur de coût (à partir de 200 pour de la sécurité basique)
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

    # Envoie du nouvel utilisateur au serveur
    payload = {
        "username": username,
        "salt": salt_b64,
        "vkey": vkey_b64,
        "public_key": base64.b64encode(public_user_key).decode(),
        "private_key_enc": base64.b64encode(private_user_key_enc).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    data = handle_resp(
        api_post("/register", payload),
        required_fields=["username"],
        context="Register"
    )
    if data is None: return

    log_client("info", "Register", f"Account '{username}' created successfully")

def login_account(args):
    """
    Authentification d'un utilisateur existant via SRP.
    """

    # Vérifie si une session locale est déjà active
    if Session.valid():
        log_client("info", "Login", "User is already logged in.")
        return

    username = args.username
    password = getpass.getpass(f"Enter your password of '{username}': ")

    # Création de l'objet SRP côté client
    usr = srp.User(
        username.encode(),
        password.encode(),
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )

    # client calcul sa clé publique (A)
    # la première valeur de retour est inutilisée
    # '_' est utilisé par convention pour indiquer cela
    _, A = usr.start_authentication()


    # Envoi au serveur le username et la clé publique (A)
    payload = {
        "username": username,
        "A": base64.b64encode(A).decode()
    }
    data = handle_resp(
        api_post("/srp/start", payload),
        required_fields=["salt", "B"],
        context="SRP start"
    )
    if data is None: return

    # Réception du sel et clé publique (B) du serveur
    salt = base64.b64decode(data["salt"])
    B = base64.b64decode(data["B"])

    # Validation du challenge
    M = usr.process_challenge(salt, B)

    # Envoi au serveur du challenge complété (M)
    payload = {
        "username": username,
        "M": base64.b64encode(M).decode()
    }
    data = handle_resp(
        api_post("/srp/verify", payload),
        required_fields=["HAMK", "session_id"],
        context="SRP verify"
    )
    if data is None: return

    # Réception de la preuve d'authentification finale (HAMK)
    HAMK = base64.b64decode(data["HAMK"])

    # Validation finale de la session SRP
    session_id = data.get("session_id")
    usr.verify_session(HAMK)
    if not usr.authenticated() or not session_id:
        log_client("error", "Login", "incorrect username or password")
        return
    Session.save(username, session_id)

    # Demande au serveur la user key et réceptionne les données
    data = handle_resp(
        api_post("/userkey", {"session_id": session_id}),
        required_fields=["user_key"],
        context="Fetch user key"
    )
    if data is None: return

    # Réception des données de la clé privée chiffrée
    user_key = data.get("user_key", {})
    private_key_enc_b64 = user_key.get("private_key_enc")
    nonce_b64 = user_key.get("nonce")
    tag_b64 = user_key.get("tag")

    if not all([private_key_enc_b64, nonce_b64, tag_b64]):
        log_client("error", "Login", "incomplete user key data from server.")
        return

    private_key_enc = base64.b64decode(private_key_enc_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)


    # Déchiffrement de la clé privée user key avec la clé dérivée bcrypt
    try:
        # Dérivation de la clé AES via bcrypt
        aes_key = bcrypt.kdf(
            password=password.encode(),
            salt=salt,
            desired_key_bytes=32,
            rounds=200  # facteur de coût (à partir de 200 pour de la sécurité basique)
        )
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        private_user_key = cipher.decrypt_and_verify(private_key_enc, tag)
    except ValueError:
        log_client("error", "Login", "unable to decrypt user key (possible causes: invalid password, corrupted data, or mismatched salt).")
        return

    #TODO la clé privée déchiffrée doit rester en mémoire et déchiffrer chaque vault key 
    # qu'on recevra dans le futur

    log_client("info", "Login", f"Login successful, welcome {username}.")

def logout_account(args):
    """
    Déconnexion de l'utilisateur (révocation de la session côté client et serveur).
    """

    session_id = Session.load()
    if not session_id:
        log_client("info", "Logout", "No active session found.")
        return
        
    data = handle_resp(
        api_post("/session/logout", {"session_id": session_id}),
        context="Logout"
    )
    if data is None: 
        log_client("error", "Logout", "failed to revoke session on server.")
        return

    # Nettoyage de la session locale
    Session.clear()
    log_client("info", "Logout", "Logout successful. Session terminated.")