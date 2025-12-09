import argparse, os, readline, atexit
from .core import auth
from .core import vault
from .core import item
from .core.integration import simplelogin as sl
from .core.item_schema import Field, Type, SCHEMAS
from .utils.agent_client import AgentClient
from .utils.logger import notify_user

class WideHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=60, width=160)

class WideRawHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=60, width=160)

HELP_FORMATTER = WideHelpFormatter
RAW_HELP_FORMATTER = WideRawHelpFormatter
SHELL_RUNNING = False

def _add_item_field_flags(parser, include_auto=False, action="store"):
    is_toggle = action == "store_true"
    common_kwargs = {"action": action} if is_toggle else {}

    # Common fields group
    parser.add_argument("-n", "--name", help="Title of the item", **common_kwargs)
    parser.add_argument("-e", "--email", "--username", dest="email", help="Account email or username", **common_kwargs)
    parser.add_argument("-p", "--password", help="Account password", **common_kwargs)
    if include_auto and not is_toggle:
        parser.add_argument("-pA", "--password-auto", action="store_true", help="Generate strong password automatically")
    parser.add_argument("--totp", help="TOTP secret (base32)", **common_kwargs)
    if include_auto and not is_toggle:
        parser.add_argument("--totp-auto", action="store_true", help="Generate TOTP secret automatically")
    parser.add_argument("-U", "--url", help="Associated website URL", **common_kwargs)

    # Extra fields
    parser.add_argument("--firstname", help="First name", **common_kwargs)
    parser.add_argument("--lastname", help="Last name", **common_kwargs)
    parser.add_argument("--phone", help="Phone number", **common_kwargs)
    parser.add_argument("--notes", help="Additional notes", **common_kwargs)

    # Card-specific
    parser.add_argument("--cardnumber", help="Card number", **common_kwargs)
    parser.add_argument("--expiry", help="Expiration date", **common_kwargs)
    parser.add_argument("--holder", help="Card holder name", **common_kwargs)
    parser.add_argument("--cvv", help="Security code", **common_kwargs)

def _item_create_epilog():
    lines = ["Item types and their associated fields:"]
    pad_type = max(len(t.value) for t in Type) + 1
    req_strings = {t: ", ".join(f.value for f in SCHEMAS[t]["required"]) or "-" for t in Type}
    pad_req = max(len(req) for req in req_strings.values())
    for t in Type:
        req = req_strings[t]
        rec = ", ".join(f.value for f in SCHEMAS[t]["recommended"]) or "-"
        left = f"- {t.value.ljust(pad_type)}required: [{req}]"
        left = left.ljust(len("- ") + pad_type + len("required: []") + pad_req)
        lines.append(f"{left} recommended: [{rec}]")
    return "\n".join(lines)

def _refresh_agent_ttl_if_running():
    """Ping the agent to refresh its TTL without auto-starting it."""
    try:
        agent = AgentClient(autostart=False)
        if agent.sock_path.exists():
            agent.status()
    except Exception:
        pass

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
    _refresh_agent_ttl_if_running() # action user -> refresh le TTL de l'agent

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
    p_item_create = item_sub.add_parser(
        "create",
        help="Create a new item in the selected vault",
        formatter_class=RAW_HELP_FORMATTER,
        epilog=_item_create_epilog(),
    )
    # Required group
    req = p_item_create.add_argument_group("Required")
    req.add_argument("-t", "--type", required=True, help="Type of item to create (login, alias, card, note, identity, other)")

    # Champs optionnels (mêmes flags que field-add)
    _add_item_field_flags(p_item_create, include_auto=True, action="store")
    p_item_create.set_defaults(func=item.create_item)

    # ====== item list ======
    p_item_list = item_sub.add_parser("list", help="List all items in the selected vault")
    p_item_list.set_defaults(func=item.list_items)

    # ====== item totp <idx> ======
    p_item_totp = item_sub.add_parser("totp", help="Show current TOTP code for an item")
    p_item_totp.add_argument("index", type=int, help="Index as shown in item list")
    p_item_totp.set_defaults(func=item.show_item_totp)

    # ====== item show <idx> ======
    p_item_show = item_sub.add_parser("show", help="Show item details")
    p_item_show.add_argument("index", type=int, help="Index as shown in item list")
    p_item_show.set_defaults(func=item.show_item)

    # ====== item delete ======
    p_item_delete = item_sub.add_parser("delete", help="Delete an entire item")
    p_item_delete.add_argument("index", type=int, help="Index of the item to delete")
    p_item_delete.set_defaults(func=item.delete_item)

    # ====== item field management ======
    # field add
    p_item_field_add = item_sub.add_parser(
        "field-add",
        help="Add one or more fields to an item using flags (same as create)",
        formatter_class=RAW_HELP_FORMATTER,
        epilog="Example:\nitem field-add 1 --firstname bob -e user@mail.com -pA -U https://example.com --notes \"hello world\""
    )
    p_item_field_add.add_argument("index", type=int, help="Index as shown in item list")
    _add_item_field_flags(p_item_field_add, include_auto=True, action="store")
    p_item_field_add.set_defaults(func=item.add_item_field)

    # field edit
    p_item_field_edit = item_sub.add_parser("field-edit", help="Edit a specific field of an item")
    p_item_field_edit.add_argument("index", type=int, help="Index as shown in item list")
    p_item_field_edit.add_argument("field", help="Field name to edit (e.g. name, email, password, url)")
    p_item_field_edit.add_argument("value", help="New value for the field")
    p_item_field_edit.set_defaults(func=item.edit_item_field)

    # field delete
    p_item_field_delete = item_sub.add_parser("field-delete", help="Delete one or more fields from an item (via flags)")
    p_item_field_delete.add_argument("index", type=int, help="Index of the item")
    _add_item_field_flags(p_item_field_delete, include_auto=False, action="store_true")
    p_item_field_delete.set_defaults(func=item.delete_item_field)

    # ============================================================
    # Commandes integrations
    # ============================================================
    p_integration = subparsers.add_parser("integration", help="Manage integrations")
    integration_sub = p_integration.add_subparsers(dest="integration_command", parser_class=ShellArgumentParser)
    p_integration.set_defaults(func=lambda args: p_integration.print_help())

    # ------- SimpleLogin -------
    p_sl = integration_sub.add_parser("simplelogin", help="SimpleLogin integration")
    sl_sub = p_sl.add_subparsers(dest="simplelogin_command", parser_class=ShellArgumentParser)
    p_sl.set_defaults(func=lambda args: p_sl.print_help())
    # simplelogin set-key
    p_sl_setkey = sl_sub.add_parser("set-key", help="Set the SimpleLogin API key")
    p_sl_setkey.set_defaults(func=sl.prompt_set_api_key)

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
    global SHELL_RUNNING
    if SHELL_RUNNING:
        notify_user("Interactive shell already running.")
        return
    SHELL_RUNNING = True

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

    try:
        while True:
            try:
                refresh_prompt_user()

                raw_line = input(f"\n{prefix}protopass{suffix}> ").strip()
                _refresh_agent_ttl_if_running()
                
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
    finally:
        SHELL_RUNNING = False


if __name__ == "__main__":
    main()
