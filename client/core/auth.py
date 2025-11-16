import getpass, base64, srp, re
from Crypto.Hash import SHA256
from .account_state import AccountState
from ..utils import logger as log
from ..utils.agent_client import AgentClient
from ..utils.logger import CTX
from ..utils.logger import notify_user
from ..utils.network import api_post, handle_resp
from ..utils.crypto import (
    generate_userkey_pair,
)

MAX_PASSWORD_ATTEMPTS = 3

def is_valid_username(username):
    return re.fullmatch(r"^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{1,18}[a-zA-Z0-9])?$", username) is not None

def register_account(args):
    """
    Création d'un nouveau compte utilisateur.
    """
    agent = AgentClient()
    logger = log.get_logger(CTX.REGISTER)

    # vérifie qu'on est pas déjà connecté
    if AccountState.valid():
        logger.warning("User is already logged in")
        notify_user("You are already logged in.")
        return

    username = args.username
    username_hash = SHA256.new(username.encode()).hexdigest()

    if not is_valid_username(username):
        logger.error("Entered an invalid username")
        notify_user("Invalid username. Use 3-20 letters, digits, '-' or '_'.")
        return

    logger.info(f"Starting registration for username '{username}'")

    # Demande et confirmation du mot de passe (3 essais max)
    password = None
    for attempt in range(MAX_PASSWORD_ATTEMPTS):
        password = getpass.getpass("Enter desired password: ")
        password_confirm = getpass.getpass("Confirm your password: ")
        if password == password_confirm:
            break

        logger.error("Password confirmation mismatch during registration")
        if attempt < MAX_PASSWORD_ATTEMPTS - 1:
            notify_user("Passwords do not match. Try again.\n")
    else:
        notify_user("Passwords do not match. Registration cancelled.")
        return

    # Générer (salt + verifier) selon SRP
    salt, vkey = srp.create_salted_verification_key(
        username_hash, password,
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )
    salt_b64 = base64.b64encode(salt).decode()
    vkey_b64 = base64.b64encode(vkey).decode()

    try:
        # Démarre l'agent, il dérive la master_key
        if not agent.start(username, password, salt_b64, logger):
            logger.error("Failed to initialize secure agent during registration")
            notify_user("Unable to start the secure agent. Please try again.")
            return

        # Génération de la paire de clé RSA (2048 bits) appelée 'userkey"
        public_user_key, private_user_key = generate_userkey_pair()
        
        # Chiffrement de la clé privée user key avec l'agent (qui contient la master_key)    
        private_key_b64 = base64.b64encode(private_user_key).decode()
        enc_data = agent.encrypt(private_key_b64, logger)
        if not enc_data:
            logger.error("Agent failed to encrypt private key during registration")
            notify_user("Secure agent unavailable. Please try again.")
            return

        private_key_block = {
            "enc": enc_data["ciphertext"],
            "nonce": enc_data["nonce"],
            "tag": enc_data["tag"],
        }
    finally:
        agent.shutdown(logger)

    # Envoie données du nouvel utilisateur au serveur
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
    
    notify_user(f"Account '{username}' created successfully.")

def login_account(args):
    """
    Authentification d'un utilisateur existant via SRP.
    """
    agent = AgentClient()
    username = args.username
    logger = log.get_logger(CTX.LOGIN, username)

    # Vérifie si une session locale est déjà active
    if AccountState.valid():
        logger.warning("User is already logged in")
        notify_user("You are already logged in.")
        return

    logger.info(f"Tried to login as '{username}'")

    username_hash = SHA256.new(username.encode()).hexdigest()
    
    keep_agent_alive = False
    login_success = False
    
    password = None
    session_id = None
    salt_b64 = None
    public_key_b64 = None
    private_block = None
    private_user_key = None

    try:
        # Autorise plusieurs tentatives de saisie avant d'abandonner
        for attempt in range(MAX_PASSWORD_ATTEMPTS):
            password = getpass.getpass(f"Enter the password of '{username}': ")

            # Création de l'objet SRP côté client
            usr = srp.User(
                username_hash.encode(),
                password.encode(),
                hash_alg=srp.SHA256,
                ng_type=srp.NG_2048
            )

            _, A = usr.start_authentication()

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
                if attempt < MAX_PASSWORD_ATTEMPTS - 1:
                    notify_user("Incorrect username or password. Try again.")
                continue

            salt_b64 = data["salt"]
            salt = base64.b64decode(salt_b64)
            B = base64.b64decode(data["B"])

            M = usr.process_challenge(salt, B)

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
                if attempt < MAX_PASSWORD_ATTEMPTS - 1:
                    notify_user("Incorrect username or password. Try again.")
                continue

            HAMK = base64.b64decode(data["HAMK"])

            session_id = data.get("session_id")
            usr.verify_session(HAMK)
            if not usr.authenticated() or not session_id:
                logger.error("Incorrect username or password (SRP verification failed)")
                if attempt < MAX_PASSWORD_ATTEMPTS - 1:
                    notify_user("Incorrect username or password. Try again.")
                continue

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

            user_key = data.get("user_key", {})
            public_key_b64 = user_key.get("public_key")
            private_block = {
                "enc": user_key.get("private_key_enc"),
                "nonce": user_key.get("nonce"),
                "tag": user_key.get("tag"),
            }

            if not agent.start(username, password, salt_b64, logger):
                if attempt < MAX_PASSWORD_ATTEMPTS - 1:
                    notify_user("Incorrect username or password. Try again.")
                continue

            data = agent.decrypt(
                private_block["enc"],
                private_block["nonce"],
                private_block["tag"],
                logger
            )
            if not data:
                if attempt < MAX_PASSWORD_ATTEMPTS - 1:
                    notify_user("Incorrect username or password. Try again.")
                continue
            
            private_user_key = base64.b64decode(data.get("plaintext"))

            login_success = True
            break

        if not login_success:
            notify_user("Too many incorrect password attempts.")
            return

        AccountState.set_private_key(private_user_key)
        AccountState.set_session_id(session_id)

        session_id_b64 = base64.b64encode(session_id.encode()).decode()
        enc_data = agent.encrypt(session_id_b64, logger)
        if not enc_data:
            logger.error("Agent failed to encrypt session block during login")
            notify_user("Secure agent unavailable. Please try again.")
            return

        session_block = {
            "enc": enc_data["ciphertext"],
            "nonce": enc_data["nonce"],
            "tag": enc_data["tag"],
        }

        if AccountState.save(username, salt_b64, public_key_b64, private_block, session_block, password) is False:
            logger.error("Failed to save account state locally")
            notify_user("An error occured. Please try again.")
            return

        logger.info(f"User '{username}' successfully logged")
        notify_user(f"Login successful. Welcome {username}!")
        keep_agent_alive = True

    finally:
        if not keep_agent_alive:
            agent.shutdown(logger)

def logout_account(args):
    """
    Déconnexion de l'utilisateur (révocation de la session côté client et serveur).
    """
    agent = AgentClient()
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
        logger.error("Failed to revoke session on server")
        return

    # Nettoyage de la session locale et shutdown de l'agent
    AccountState.clear()
    agent.shutdown(logger)

    logger.info(f"User '{username}' logged out")
    notify_user("Logout successful. Session terminated.")
