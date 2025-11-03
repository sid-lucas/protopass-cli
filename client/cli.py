import argparse
from core import auth
from core import vault

class ShellArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)

# Création parseur de commandes
parser = ShellArgumentParser(
    prog="protopass",
    description="Prototype password manager CLI"
)

restricted = ["login", "register", "shell"]


def main():

    # Espace pour des sous-commandes (register, login, etc.)
    subparsers = parser.add_subparsers(dest="command", help="commands")

    p_shell = subparsers.add_parser("shell", help="Start interactive protopass shell")
    p_shell.set_defaults(func=start_shell)

    # ============================================================
    # Commandes d'authentification
    # ============================================================
    p_register = subparsers.add_parser("register", help="Register a new account")
    p_register.add_argument("--username", required=True, help="Username of the account")
    p_register.set_defaults(func=auth.register_account)

    p_login = subparsers.add_parser("login", help="Log to account")
    p_login.add_argument("--username", required=True, help="Username of the account")
    p_login.set_defaults(func=auth.login_account)

    p_logout = subparsers.add_parser("logout", help="Logout from current session")
    p_logout.set_defaults(func=auth.logout_account)

    # ============================================================
    # Commandes gestion vault
    # ============================================================
    p_vault = subparsers.add_parser("vault", help="Manage vaults")
    vault_sub = p_vault.add_subparsers(dest="vault_command")
    p_vault.set_defaults(func=lambda args: p_vault.print_help())

    p_vault_create = vault_sub.add_parser("create", help="Create a new vault")
    p_vault_create.add_argument("--name", required=True, help="Name of the vault")
    p_vault_create.set_defaults(func=vault.create_vault)

    p_vault_delete = vault_sub.add_parser("delete", help="Delete a vault")
    p_vault_delete.add_argument("--name", required=True, help="Name of the vault to delete")
    p_vault_delete.set_defaults(func=vault.delete_vault)

    p_vault_select = vault_sub.add_parser("select", help="Select a vault to use")
    p_vault_select.add_argument("--name", required=True, help="Name of the vault to select")
    p_vault_select.set_defaults(func=vault.select_vault)

    p_vault_list = vault_sub.add_parser("list", help="List all vaults")
    p_vault_list.set_defaults(func=vault.list_vaults)

    

    


    # Lit ce que l'user passe comme arguments (après 'python cli.py')
    args = parser.parse_args()

    if not args.command:
        #parser.print_help()
        return

    # Vérifie la session avant d'exécuter une commande
    if args.command not in restricted and not auth.AccountState.valid():
        print("You must be logged in to use this command.")
        print("Please run: python cli.py login --username <your_name>") #TODO change TEXT?
        return

    # Exécution de la commande demandée
    args.func(args)

def start_shell(_args=None):
    import shlex

    print("ProtoPass CLI Shell. Type 'exit', 'quit' or 'q' to quit.")
    print("Type 'help' to list available commands.")

    while True:
        try:
            raw_input = input("\nprotopass> ").strip()
            if raw_input in ["exit", "quit", "q"]:
                break
            if raw_input in ["help", "?"]:
                parser.print_help()
                continue
            if not raw_input:
                continue

            args_list = shlex.split(raw_input)

            try:
                args = parser.parse_args(args_list)
            except Exception as e:
                print(e)
                continue
            except SystemExit:
                continue

            if not hasattr(args, "func"):
                print("Invalid command. Type 'help' for a list of commands.")
                continue

            # Check session
            if args.command not in restricted and not auth.AccountState.valid():
                print("You must be logged in to use this command.")
                continue

            args.func(args)

        except KeyboardInterrupt:
            print("\nUse 'q' to quit.")
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
