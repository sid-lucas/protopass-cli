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
    if resp.status_code == 201:
        print(f"The account '{username}' has been succesfully created")
    else:
        print(f"Error: servor responded ({resp.status_code}) : {resp.text}")

def login_account(args):
    """
    ok
    """
    # Récupère le username en argument
    username = args.username

    # Message d'information pour indiquer à quel compte on se connecte
    print(f"Connecting as '{username}'...")
    master_password = getpass.getpass("Enter your password: ")

    # Pour l’instant, on ne vérifie pas encore le mot de passe, on teste juste le flux
    print(f"Login successful for {username}.")
