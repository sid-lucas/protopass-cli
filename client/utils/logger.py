import logging
from enum import Enum
from pathlib import Path


class LogContext(str, Enum):
    NETWORK = "Network"
    REGISTER = "Register"
    LOGIN = "Login"
    LOGOUT = "Logout"
    SRP_START = "SRP Start"
    SRP_VERIFY = "SRP Verify"
    FETCH_USER_KEY = "Fetch User Key"
    ACCOUNT_STATE = "Account State"
    SESSION = "Session"
    SESSION_VERIFY = "Session Verify"
    DECRYPT = "Decrypt"
    VAULT_LIST = "Vault List"
    VAULT_CREATE = "Vault Create"
    VAULT_DELETE = "Vault Delete"
    VAULT_SELECT = "Vault Select"
    ITEM_LIST = "Item List"
    ITEM_CREATE = "Item Create"
    ITEM_DELETE = "Item Delete"
    ITEM_SELECT = "Item Select"


CTX = LogContext


# ============================================================
# Paths & filenames
# ============================================================
LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "protopass.log"


# ============================================================
# Logging configuration
# ============================================================
class _UserAwareFormatter(logging.Formatter):
    def format(self, record):
        user = getattr(record, "user", None)
        if user and user != "-":
            record.user_display = f" | user={user}"
        else:
            record.user_display = ""
        return super().format(record)


_formatter = _UserAwareFormatter(
    "%(asctime)s | %(levelname)s | %(context)s%(user_display)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_logger = logging.getLogger("protopass.client")
if not _logger.handlers:
    _logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(_formatter)
    _logger.addHandler(file_handler)
    _logger.propagate = False


# ============================================================
# Helpers
# ============================================================
def _resolve_username(explicit_user: str | None) -> str | None:
    if explicit_user:
        return explicit_user
    try:
        from core.account_state import AccountState  # type: ignore
        return AccountState.username()
    except Exception:
        return None


# ============================================================
# Logger adapter
# ============================================================
class _ContextLoggerAdapter(logging.LoggerAdapter):
    """
    Enrichit systématiquement les logs avec un contexte et un utilisateur.
    """

    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})

        # Contexte : priorité au kwargs, sinon à la valeur fournie lors de l'init.
        if "context" not in extra and "context" in self.extra:
            extra["context"] = self.extra["context"]

        # Utilisateur : kwargs > adapter > résolution automatique.
        user = extra.get("user", self.extra.get("user"))
        if user is None or user == "-":
            user = _resolve_username(None)
        extra["user"] = user or "-"

        return msg, kwargs


# ============================================================
# API utilitaire
# ============================================================
def get_logger(context: str, user: str | None = None) -> logging.LoggerAdapter:
    """Retourne un logger prêt à l'emploi pour un contexte donné."""
    context_value = context.value if isinstance(context, LogContext) else str(context)
    return _ContextLoggerAdapter(_logger, {"context": context_value, "user": user})


# ============================================================
# Public API
# ============================================================
def _log(level: int, context: str, message: str, user: str | None = None, **kwargs) -> None:
    get_logger(context, user).log(level, message, **kwargs)

def log_client(level: str, context: str, message: str, user: str | None = None, **kwargs) -> None:
    """Compat helper (utilisé durant la migration)."""
    level_value = getattr(logging, level.upper(), logging.INFO)
    _log(level_value, context, message, user=user, **kwargs)

def debug(context: str, message: str, user: str | None = None, **kwargs) -> None:
    _log(logging.DEBUG, context, message, user=user, **kwargs)


def info(context: str, message: str, user: str | None = None, **kwargs) -> None:
    _log(logging.INFO, context, message, user=user, **kwargs)


def warning(context: str, message: str, user: str | None = None, **kwargs) -> None:
    _log(logging.WARNING, context, message, user=user, **kwargs)


def error(context: str, message: str, user: str | None = None, **kwargs) -> None:
    _log(logging.ERROR, context, message, user=user, **kwargs)


def critical(context: str, message: str, user: str | None = None, **kwargs) -> None:
    _log(logging.CRITICAL, context, message, user=user, **kwargs)


def notify_user(message: str) -> None:
    """
    Affiche un message dans la console, destiné à l'utilisateur.
    """
    print(message)
