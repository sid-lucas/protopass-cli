import getpass
import srp
import hashlib, base64
import requests
import json
from pathlib import Path

SESSION_FILE = Path(__file__).resolve().parents[1] / "client_data" / "session.json"


def init_vault(_args):
    print("salut a tous")

def register_account(args):
    username = args.username
    print(f"Creation of a new account '{username}'")

    # 1. Demande du mot de passe
    password = getpass.getpass("Enter your password: ")

    # 2. Générer (salt + verifier) selon SRP
    salt, vkey = srp.create_salted_verification_key(
        username, password,
        hash_alg=srp.SHA256,
        ng_type=srp.NG_2048
    )

    # 3. Encode en b64
    salt_b64 = base64.b64encode(salt).decode()
    vkey_b64 = base64.b64encode(vkey).decode()

    # 4. Préparation du JSON
    payload = {
        "username": username,
        "salt": salt_b64,
        "vkey": vkey_b64,
    }

    # 5. envoi au serveur sur la route /register
    url = "http://127.0.0.1:5000/register"
    try:
        resp = requests.post(url, json=payload)
    except requests.exceptions.ConnectionError:
        print("Error: server unreachable")
        return

    # 6. réception du code retour
    if resp.status_code != 201:
        print(f"Error: servor responded ({resp.status_code}) : {resp.text}")
    
    print(f"The account '{username}' has been succesfully created")


def login_account(args):
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
    url = "http://127.0.0.1:5000/srp/start"
    try:
        resp = requests.post(url, json=payload)
    except requests.exceptions.ConnectionError:
        print("Error: server unreachable")
        return

    if resp.status_code != 200:
        print(f"Error: servor responded ({resp.status_code}) : {resp.text}")
        return

    # Réception du set et clé publique (B) du serveur
    data = resp.json()
    salt = base64.b64decode(data["salt"])
    B = base64.b64decode(data["B"])

    # Validation du challenge
    M = usr.process_challenge(salt, B)

    # Envoi de la preuve au serveur pour vérification
    url = "http://127.0.0.1:5000/srp/verify"
    payload = {"M": base64.b64encode(M).decode()}
    resp = requests.post(url, json=payload)

    if resp.status_code != 200:
        print(f"Error: servor responded ({resp.status_code}) : {resp.text}")
        return

    data = resp.json()
    HAMK = base64.b64decode(data["HAMK"])

    # Validation finale
    session_id = data.get("session_id")
    usr.verify_session(HAMK)
    if usr.authenticated() and session_id:
        save_session(username, session_id)
        print(f"Login successful, welcome {username}.")
    else:
        print("Error: incorrect username or password")


def logout_account(_args):
    session_id = load_session()
    if not session_id:
        print("No active session found.")
        return

    url = "http://127.0.0.1:5000/session/logout"
    try:
        resp = requests.post(url, json={"session_id": session_id})
    except requests.exceptions.ConnectionError:
        print("Error: server unreachable")
        return

    if resp.status_code == 200:
        # Supprime le fichier local de session
        if SESSION_FILE.exists():
            SESSION_FILE.unlink()
        print("Logout successful. Session terminated.")
    else:
        print(f"Error: {resp.text}")





def save_session(username, session_id):
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps({
        "username": username,
        "session_id": session_id
    }, indent=2))

def load_session():
    if not SESSION_FILE.exists():
        return None
    try:
        data = json.loads(SESSION_FILE.read_text())
        return data.get("session_id")
    except Exception:
        return None

def is_session_valid():
    session_id = load_session()
    if not session_id:
        return False

    try:
        resp = requests.post("http://127.0.0.1:5000/session/verify", json={"session_id": session_id})
        if resp.status_code != 200:
            return False
        return resp.json().get("valid", False)
    except requests.exceptions.ConnectionError:
        return False
