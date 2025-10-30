import getpass
import srp
import hashlib, base64
import requests


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
        print("Error: cannot connect to the server")
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
        print("Error: cannot connect to the server")
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
    usr.verify_session(HAMK)
    if usr.authenticated():
        print(f"Login successful, welcome {username}.")
    else:
        print("Error: incorrect username or password")

