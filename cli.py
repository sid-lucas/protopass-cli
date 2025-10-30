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

    p_login = subparsers.add_parser("login", help="Log to account")
    p_login.add_argument("--username", required=True, help="Username of the account")
    p_login.set_defaults(func=auth.login_account)

    # Lit ce que l'user passe comme arguments (après 'python cli.py')
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # appelle la fonction associée à la sous-commande
    args.func(args)


if __name__ == "__main__":
    main()
