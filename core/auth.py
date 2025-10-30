import getpass

def init_vault(_args):
    print("salut a tous")

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
