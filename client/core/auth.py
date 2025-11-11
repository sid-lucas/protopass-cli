import getpass
import base64
import srp
import re
from Crypto.Hash import SHA256
from .account_state import AccountState
from ..utils import logger as log
from client.utils.network import api_post, handle_resp
from client.utils.logger import notify_user
from client.utils.logger import CTX
from client.utils.crypto import (
    derive_aes_key,
    encrypt_gcm,
    b64_block_from_bytes,
    generate_userkey_pair,
)

def is_valid_username(username):
    return re.fullmatch(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{1,18}[a-zA-Z0-9])?$", username) is not None

def register_account(args):
    """
    Création d'un nouveau compte utilisateur.
    """
    
    logger = log.get_logger(CTX.REGISTER)

    # vérifie qu'on est pas déjà connecté
    if AccountState.valid():
        logger.warning("User is already logged in.")
        notify_user("You are already logged in.")
        return

    username = args.username
    username_hash = SHA256.new(username.encode()).hexdigest()

    if not is_valid_username(username):
        logger.error("Entered an invalid username")
        notify_user("Invalid username. Use 3-20 letters, digits, '-' or '_'.")
        return

    logger.info(f"Starting registration for username '{username}'")

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
    aes_key = derive_aes_key(
        password=password,
        salt=salt
    )

    # Génération de la paire de clé RSA (2048 bits) appelée 'userkey"
    public_user_key, private_user_key = generate_userkey_pair()
    
    # Chiffrement de la clé privée user key avec la clé dérivée bcrypt
    ciphertext, nonce, tag = encrypt_gcm(aes_key, private_user_key)
    private_key_block = b64_block_from_bytes(ciphertext, nonce, tag)

    # Envoie du nouvel utilisateur au serveur
    payload = {
        "username": username_hash,
        "salt": salt_b64,
        "vkey": vkey_b64,
        "public_key": base64.b64encode(public_user_key).decode(),
        "private_key_enc": private_key_block["enc"],
        "nonce": private_key_block["nonce"],
        "tag": private_key_block["tag"]
    }
    data = handle_resp(
        api_post("/register", payload),
        required_fields=["username"],
        context=CTX.REGISTER
    )
    if data is None:
        notify_user("Registration failed. Please check logs for details.")
        return

    logger.info(f"Account '{username}' has been created")
    notify_user(f"Account '{username}' created successfully.")

def login_account(args):
    """
    Authentification d'un utilisateur existant via SRP.
    """

    logger = log.get_logger(CTX.LOGIN)

    # Vérifie si une session locale est déjà active
    if AccountState.valid():
        logger.warning("User is already logged in.")
        notify_user("You are already logged in.")
        return

    username = args.username
    logger = log.get_logger(CTX.LOGIN, username)
    logger.info(f"Tried to login as '{username}'")

    username_hash = SHA256.new(username.encode()).hexdigest()
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
        context=CTX.SRP_START,
        user=username
    )
    if data is None:
        notify_user("Incorrect username or password. Try again.")
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
        context=CTX.SRP_VERIFY,
        user=username
    )
    if data is None:
        notify_user("Incorrect username or password. Try again.")
        return

    # Réception de la preuve d'authentification finale (HAMK)
    HAMK = base64.b64decode(data["HAMK"])

    # Validation finale de la session SRP
    session_id = data.get("session_id")
    usr.verify_session(HAMK)
    if not usr.authenticated() or not session_id:
        logger.error("Incorrect username or password (SRP verification failed).")
        notify_user("Incorrect username or password.")
        return
    # Demande au serveur la user key et réceptionne les données
    data = handle_resp(
        api_post(
            "/userkey",
            {"session_id": session_id, "username_hash": username_hash},
            user=username
        ),
        required_fields=["user_key"],
        context=CTX.FETCH_USER_KEY,
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
        logger.error("Incomplete user key data from server.")
        notify_user("Incomplete user key data received from server.")
        return

    private_block = {
        "enc": private_key_enc_b64,
        "nonce": nonce_b64,
        "tag": tag_b64,
    }
    try:
        private_user_key = AccountState._decrypt_secret(password, private_block, salt_b64)
    except Exception:
        private_user_key = None
    if private_user_key is None:
        return

    # Stockage de l'état du compte pour les prochaines commandes
    AccountState.set_private_key(private_user_key) # clé privée en mémoire volatile
    AccountState.set_session_id(session_id) # idem

    try:
        session_block = AccountState._encrypt_secret(password, session_id.encode(), salt_b64)
    except Exception:
        logger.error("Failed to encrypt session for local storage.")
        notify_user("Unable to protect local session data.")
        return

    if AccountState.save(username, salt_b64, public_key_b64, private_block, session_block) is False:
        logger.error("Failed to save account state locally.")
        notify_user("Failed to save account state locally.")
        return

    logger.info(f"User '{username}' successfully logged")
    notify_user(f"Login successful. Welcome {username}!")

def logout_account(args):
    """
    Déconnexion de l'utilisateur (révocation de la session côté client et serveur).
    """

    session_payload = AccountState.session_payload()
    username = AccountState.username()
    logger = log.get_logger(CTX.LOGOUT, username)

    if not session_payload:
        logger.info("No active session found")
        notify_user("Already logged out.")
        return

    data = handle_resp(
        api_post("/session/logout", session_payload, user=username),
        context=CTX.LOGOUT,
        user=username
    )
    if data is None: 
        logger.error("Failed to revoke session on server.")
        return

    # Nettoyage de la session locale
    AccountState.clear()
    logger.info(f"User '{username}' logged out")
    notify_user("Logout successful. Session terminated.")
