import argparse, os, readline, atexit
from .core import auth
from .core import vault
from .utils.agent_client import AgentClient
from .utils.logger import notify_user

class ShellArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


SESSION_OPTIONAL_COMMANDS = {"login", "logout", "register", "shell"}

def dispatch_command(args):
    """
    Point d'entrée commun pour exécuter une commande en tenant compte des règles de session.
    """
    if not hasattr(args, "func"):
        print("Invalid command. Type 'help' for a list of commands.")
        return

    if args.command not in SESSION_OPTIONAL_COMMANDS and not auth.AccountState.valid():
        print("You must be logged in to use this command.")
        return

    try:
        args.func(args)
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user.")

def build_parser():
    """
    Construit l'arborescence complète des commandes (réutilisée en mode shell).
    """
    parser = ShellArgumentParser(
        prog="protopass",
        description="Prototype password manager CLI"
    )

    # Sous-parseur principal qui accueille toutes les commandes de premier niveau
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
    # Crée un sous-sous-parseur pour les actions vault (create/delete/...)
    vault_sub = p_vault.add_subparsers(dest="vault_command")
    p_vault.set_defaults(func=lambda args: p_vault.print_help())

    p_vault_create = vault_sub.add_parser("create", help="Create a new vault")
    p_vault_create.set_defaults(func=vault.create_vault)

    p_vault_delete = vault_sub.add_parser("delete", help="Delete a vault")
    p_vault_delete.add_argument("index", type=int, help="Index as shown in vault list")
    p_vault_delete.set_defaults(func=vault.delete_vault)

    p_vault_select = vault_sub.add_parser("select", help="Select a vault to use")
    p_vault_select.add_argument("index", type=int, help="Index as shown in vault list")
    p_vault_select.set_defaults(func=vault.select_vault)

    p_vault_list = vault_sub.add_parser("list", help="List all vaults")
    p_vault_list.set_defaults(func=vault.list_vaults)

    return parser


def main():
    parser = build_parser()

    # Lit ce que l'user passe comme arguments (après 'python cli.py')
    try:
        args = parser.parse_args()
    except ValueError as err:
        print(err)
        return

    if not args.command:
        return

    dispatch_command(args)

def start_shell(_args=None):
    import shlex

    parser = build_parser()
    exit_keywords = {"exit", "quit", "q"}
    help_keywords = {"help", "?"}

    # Active l'historique et flèches
    history_path = os.path.expanduser("~/.protopass_history")
    try:
        readline.read_history_file(history_path)
    except FileNotFoundError:
        pass
    atexit.register(readline.write_history_file, history_path)

    print("ProtoPass CLI Shell. Type 'exit', 'quit' or 'q' to quit.")

    session_verified = None  # Evite de revalider la session à chaque appui sur Entrée
    prompt_user = None  # Username affiché seulement si la session a été confirmée
    agent_missing_notified = False

    def ensure_agent_presence():
        nonlocal agent_missing_notified
        if not auth.AccountState.PATH.exists():
            return False

        agent = AgentClient(autostart=False)
        if agent.sock_path.exists():
            agent_missing_notified = False
            return True

        if not agent_missing_notified:
            auth.AccountState.clear()
            notify_user("You got logged out due to inactivity.")
            agent_missing_notified = True
        return False

    def refresh_prompt_user(force=False):
        nonlocal session_verified, prompt_user

        if not ensure_agent_presence():
            session_verified = False
            prompt_user = None
            return

        if not force and session_verified is not None:
            return

        session_verified = auth.AccountState.valid()
        prompt_user = auth.AccountState.username() if session_verified else None

    while True:
        try:
            refresh_prompt_user()
            prompt = f"{prompt_user}@protopass> " if prompt_user else "protopass> "
            raw_line = input(f"\n{prompt}").strip()
            
            if not raw_line:
                continue

            if raw_line in exit_keywords:
                break

            if raw_line in help_keywords:
                parser.print_help()
                continue

            # Si l'agent a expiré pendant que l'utilisateur saisissait sa commande,
            # force une vérification avant d'analyser la commande.
            refresh_prompt_user(force=True)

            args_list = shlex.split(raw_line)

            try:
                args = parser.parse_args(args_list)
            except ValueError as err:
                print(err)
                continue
            except SystemExit:
                continue

            dispatch_command(args)
            session_verified = None  # force refreshing prompt next iteration

        except KeyboardInterrupt:
            print("\nUse 'q' to quit.")
        except EOFError:
            print()
            break
        except Exception as err:
            print(f"[ERROR] {err}")


if __name__ == "__main__":
    main()
