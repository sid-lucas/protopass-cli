import argparse, os, readline, atexit
from .core import auth
from .core import vault
from .core import item
from .core.item_schema import Field
from .utils.agent_client import AgentClient
from .utils.logger import notify_user

HELP_FORMATTER = lambda prog: argparse.HelpFormatter(prog, max_help_position=45, width=120)

class ShellArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", HELP_FORMATTER)
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise ValueError(message)

SESSION_OPTIONAL_COMMANDS = {"login", "logout", "register", "shell"}

def dispatch_command(args, session_valid=None):
    """
    Point d'entrée commun pour exécuter une commande en tenant compte des règles de session.
    """
    if not hasattr(args, "func"):
        print("Invalid command. Type 'help' for a list of commands.")
        return

    if args.command not in SESSION_OPTIONAL_COMMANDS:
        is_valid = session_valid
        if is_valid is None:
            is_valid = auth.AccountState.valid()
        if not is_valid:
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
    subparsers = parser.add_subparsers(dest="command", help="commands", parser_class=ShellArgumentParser)

    p_shell = subparsers.add_parser("shell", help="Start interactive protopass shell")
    p_shell.set_defaults(func=start_shell)

    # ============================================================
    # Commandes d'authentification
    # ============================================================

    # ====== register -u <username> ======
    p_register = subparsers.add_parser("register", help="Register a new account")
    p_register.add_argument("-u", "--username", required=True, help="Username of the account")
    p_register.set_defaults(func=auth.register_account)

    # ====== login -u <username> ======
    p_login = subparsers.add_parser("login", help="Log to account")
    p_login.add_argument("-u", "--username", required=True, help="Username of the account")
    p_login.add_argument("--password-stdin", action="store_true", help="Read the account password from standard input",)
    p_login.set_defaults(func=auth.login_account)

    # ====== logout ======
    p_logout = subparsers.add_parser("logout", help="Logout from current session")
    p_logout.set_defaults(func=auth.logout_account)

    # ============================================================
    # Commandes gestion vault
    # ============================================================
    p_vault = subparsers.add_parser("vault", help="Manage vaults")
    # Crée un sous-sous-parseur pour les actions vault (create/delete/...)
    vault_sub = p_vault.add_subparsers(dest="vault_command", parser_class=ShellArgumentParser)
    p_vault.set_defaults(func=lambda args: p_vault.print_help())

    # ====== vault create ======
    p_vault_create = vault_sub.add_parser("create", help="Create a new vault")
    p_vault_create.add_argument("-n", "--name", help="Vault name")
    p_vault_create.add_argument("-d", "--description", help="Vault description")
    p_vault_create.set_defaults(func=vault.create_vault)

    # ====== vault delete <idx> ======
    p_vault_delete = vault_sub.add_parser("delete", help="Delete a vault")
    p_vault_delete.add_argument("index", type=int, help="Index as shown in vault list")
    p_vault_delete.set_defaults(func=vault.delete_vault)

    # ====== vault select <idx> ======
    p_vault_select = vault_sub.add_parser("select", help="Select a vault to use")
    p_vault_select.add_argument("index", type=int, help="Index as shown in vault list")
    p_vault_select.set_defaults(func=vault.select_vault)

    # ====== vault list ======
    p_vault_list = vault_sub.add_parser("list", help="List all vaults")
    p_vault_list.set_defaults(func=vault.list_vaults)

    # ============================================================
    # Commandes gestion item
    # ============================================================
    p_item = subparsers.add_parser("item", help="Manage items")
    # Crée un sous-sous-parseur pour les actions item (create/delete/...)
    item_sub = p_item.add_subparsers(dest="item_command", parser_class=ShellArgumentParser)
    p_item.set_defaults(func=lambda args: p_item.print_help())

    # ====== item create ======
    p_item_create = item_sub.add_parser("create", help="Create a new item in the selected vault")
    # Required group
    req = p_item_create.add_argument_group("Required")
    req.add_argument("-t", "--type", required=True, help="Type of item to create (login, card, ...)")

    # Common fields group
    common = p_item_create.add_argument_group("Common fields")
    common.add_argument("-n", "--name", help="Title of the item")
    common.add_argument("-e", "--email", "--username", dest="email", help="Account email or username")
    common.add_argument("-p", "--password", help="Account password")
    common.add_argument("-pA", "--password-auto", action="store_true", help="Generate strong password automatically")
    common.add_argument("-U", "--url", help="Associated website URL")

    # Extra fields group
    extra = p_item_create.add_argument_group("Extra fields")
    extra.add_argument("--firstname", help="First name")
    extra.add_argument("--lastname", help="Last name")
    extra.add_argument("--phone", help="Phone number")
    extra.add_argument("--notes", help="Additional notes")

    # Card-specific group
    card = p_item_create.add_argument_group("Card fields")
    card.add_argument("--card-number", help="Card number")
    card.add_argument("--expiry", help="Expiration date")
    card.add_argument("--holder", help="Card holder name")
    card.add_argument("--cvv", help="Security code")
    p_item_create.set_defaults(func=item.create_item)

    # ====== item list ======
    p_item_list = item_sub.add_parser("list", help="List all items in the selected vault")
    p_item_list.set_defaults(func=item.list_items)

    # ====== item show <idx> ======
    p_item_show = item_sub.add_parser("show", help="Show item details")
    p_item_show.add_argument("index", type=int, help="Index as shown in item list")
    p_item_show.set_defaults(func=item.show_item)

    # ====== item edit ======
    p_item_edit = item_sub.add_parser("edit", help="Edit a specific field of an item")
    p_item_edit.add_argument("index", type=int, help="Index as shown in item list")
    p_item_edit.add_argument("field", help="Field name to edit (e.g. name, email, password, url)")
    p_item_edit.add_argument("value", help="New value for the field")
    p_item_edit.set_defaults(func=item.edit_item)

    # ====== item delete ======
    p_item_delete = item_sub.add_parser("delete", help="Delete a field from an item")
    p_item_delete.add_argument("index", type=int, help="Index of the item")
    p_item_delete.add_argument("field", help="Field to delete")
    p_item_delete.set_defaults(func=item.delete_item_field)

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
    prefix = ""  # Username affiché seulement si la session a été confirmée
    suffix = "" # Nom du vault sélectionné (si disponible)
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
        nonlocal session_verified, prefix, suffix

        if not ensure_agent_presence():
            session_verified = False
            prefix = ""
            suffix = ""
            return

        if not force and session_verified is not None:
            return

        session_verified = auth.AccountState.valid()
        if session_verified:
            username = auth.AccountState.username() or ""
            prefix = f"{username}@" if username else ""
            vault_name = auth.AccountState.current_vault_name() or ""
            suffix = f"[{vault_name}]" if vault_name else ""
        else:
            prefix = ""
            suffix = ""

    while True:
        try:
            refresh_prompt_user()

            raw_line = input(f"\n{prefix}protopass{suffix}> ").strip()
            
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

            dispatch_command(args, session_verified)
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
