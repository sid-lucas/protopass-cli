import getpass
import base64
import bcrypt
import srp
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from .account_state import AccountState
from utils.network import api_post, handle_resp
from utils.logger import log_client, notify_user
import hashlib

def is_valid_username(username):
    return re.fullmatch(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{1,18}[a-zA-Z0-9])?$", username) is not None

def register_account(args):
    """
    Création d'un nouveau compte utilisateur.
    """

    # vérifie qu'on est pas déjà connecté
    if AccountState.valid():
        log_client("info", "Register", "User is already logged in.", user=AccountState.username())
        notify_user("You are already logged in.")
        return

    username = args.username
    username_hash = hashlib.sha256(username.encode()).hexdigest()

    if not is_valid_username(username):
        log_client("error", "Register", "Invalid username. Use 3-20 letters, digits, '-' or '_'.", user=username)
        notify_user("Invalid username. Use 3-20 letters, digits, '-' or '_'.")
        return
        
    log_client("info", "Register", f"Starting registration for username '{username}'", user=username)

    # Demande du mot de passe
    password = getpass.getpass("Enter your password: ")

    # Générer (salt + verifier) selon SRP
    salt, vkey = srp.create_salted_verification_key(
        username_hash, password,
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
        "username": username_hash,
        "salt": salt_b64,
        "vkey": vkey_b64,
        "public_key": base64.b64encode(public_user_key).decode(),
        "private_key_enc": base64.b64encode(private_user_key_enc).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    data = handle_resp(
        api_post("/register", payload, user=username),
        required_fields=["username"],
        context="Register",
        user=username
    )
    if data is None:
        notify_user("Registration failed. Please check logs for details.")
        return

    log_client("info", "Register", f"Account '{username}' created successfully", user=username)
    notify_user(f"Account '{username}' created successfully.")

def login_account(args):
    """
    Authentification d'un utilisateur existant via SRP.
    """

    # Vérifie si une session locale est déjà active
    if AccountState.valid():
        log_client("info", "Login", "User is already logged in.", user=AccountState.username())
        notify_user("You are already logged in.")
        return

    username = args.username
    username_hash = hashlib.sha256(username.encode()).hexdigest()
    password = getpass.getpass(f"Enter the password of '{username}': ")

    # Création de l'objet SRP côté client
    usr = srp.User(
        username_hash.encode(),
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
        "username": username_hash,
        "A": base64.b64encode(A).decode()
    }
    data = handle_resp(
        api_post("/srp/start", payload, user=username),
        required_fields=["salt", "B"],
        context="SRP start",
        user=username
    )
    if data is None:
        notify_user("Login failed during SRP start.")
        return

    # Réception du sel et clé publique (B) du serveur
    salt_b64 = data["salt"]
    salt = base64.b64decode(salt_b64)
    B = base64.b64decode(data["B"])

    # Validation du challenge
    M = usr.process_challenge(salt, B)

    # Envoi au serveur du challenge complété (M)
    payload = {
        "username": username_hash,
        "M": base64.b64encode(M).decode()
    }
    data = handle_resp(
        api_post("/srp/verify", payload, user=username),
        required_fields=["HAMK", "session_id"],
        context="SRP verify",
        user=username
    )
    if data is None:
        notify_user("Login failed during SRP verification.")
        return

    # Réception de la preuve d'authentification finale (HAMK)
    HAMK = base64.b64decode(data["HAMK"])

    # Validation finale de la session SRP
    session_id = data.get("session_id")
    usr.verify_session(HAMK)
    if not usr.authenticated() or not session_id:
        log_client("error", "Login", "incorrect username or password", user=username)
        notify_user("Incorrect username or password.")
        return
    # Demande au serveur la user key et réceptionne les données
    data = handle_resp(
        api_post("/userkey", {"session_id": session_id}, user=username),
        required_fields=["user_key"],
        context="Fetch user key",
        user=username
    )
    if data is None:
        notify_user("Failed to retrieve user key from server.")
        return

    # Réception des données de la clé privée chiffrée
    user_key = data.get("user_key", {})
    public_key_b64 = user_key.get("public_key")
    private_key_enc_b64 = user_key.get("private_key_enc")
    nonce_b64 = user_key.get("nonce")
    tag_b64 = user_key.get("tag")

    if not all([public_key_b64, private_key_enc_b64, nonce_b64, tag_b64]):
        log_client("error", "Login", "incomplete user key data from server.", user=username)
        notify_user("Incomplete user key data received from server.")
        return

    private_key_enc = base64.b64decode(private_key_enc_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    private_user_key = AccountState._decrypt_private_key(password, private_key_enc, nonce, tag, salt)
    if private_user_key is None:
        return

    # Stockage de l'état du compte pour les prochaines commandes
    AccountState.set_private_key(private_user_key) # clé privée en mémoire volatile
    if AccountState.save(username, session_id, public_key_b64, private_key_enc_b64, nonce_b64, tag_b64, salt_b64) is False:
        log_client("error", "Login", "failed to save account state locally.", user=username)
        notify_user("Failed to save account state locally.")
        return

    log_client("info", "Login", f"Login successful, welcome {username}.", user=username)
    notify_user(f"Login successful. Welcome {username}!")

def logout_account(args):
    """
    Déconnexion de l'utilisateur (révocation de la session côté client et serveur).
    """

    session_id = AccountState.session_id()
    username = AccountState.username()
    if not session_id:
        log_client("info", "Logout", "No active session found.", user=username)
        notify_user("No active session found.")
        return
        
    data = handle_resp(
        api_post("/session/logout", {"session_id": session_id}, user=username),
        context="Logout",
        user=username
    )
    if data is None: 
        log_client("error", "Logout", "failed to revoke session on server.", user=username)
        notify_user("Failed to revoke session on server.")
        return

    # Nettoyage de la session locale
    AccountState.clear()
    log_client("info", "Logout", "Logout successful. Session terminated.", user=username)
    notify_user("Logout successful. Session terminated.")
