import argparse

def main():
    # Création parseur de commandes
    parser = argparse.ArgumentParser(
        prog="protonpass-cli",
        description="Prototype password manager CLI"
    )

    # Espace pour des sous-commandes (init, login, etc.)
    subparsers = parser.add_subparsers(dest="command", help="Sous-commandes")

    # déclaration sous-commande 'init'
    p_init = subparsers.add_parser("init", help="Initialiser le coffre")

    # association fonction à 'init'
    p_init.set_defaults(func=lambda _args: print("Commande 'init' appelée."))


    # Lit ce que l'user passe comme arguments (après 'python cli.py')
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # appelle la fonction associée à la sous-commande
    args.func(args)


if __name__ == "__main__":
    main()
