import argparse
from core import auth


def main():
    # Création parseur de commandes
    parser = argparse.ArgumentParser(
        prog="protonpass-cli",
        description="Prototype password manager CLI"
    )

    # Espace pour des sous-commandes (init, login, etc.)
    subparsers = parser.add_subparsers(dest="command", help="commands")

    # déclaration sous-commande 'init' et association a une fonction
    p_init = subparsers.add_parser("init", help="test init")
    p_init.set_defaults(func=auth.init_vault)

    p_register = subparsers.add_parser("register", help="Register a new account")
    p_register.add_argument("--username", required=True, help="Username of the account")
    p_register.set_defaults(func=auth.register_account)

    p_login = subparsers.add_parser("login", help="Log to account")
    p_login.add_argument("--username", required=True, help="Username of the account")
    p_login.set_defaults(func=auth.login_account)

    p_logout = subparsers.add_parser("logout", help="Logout from current session")
    p_logout.set_defaults(func=auth.logout_account)



    # Lit ce que l'user passe comme arguments (après 'python cli.py')
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Vérifie la session avant d'exécuter une commande
    restricted = ["login", "register"]
    if args.command not in restricted and not auth.Session.valid():
        print("You must be logged in to use this command.")
        print("Please run: python cli.py login --username <your_name>") #TODO CHANGE TEXT?
        return

    # Exécution de la commande demandée
    args.func(args)


if __name__ == "__main__":
    main()
