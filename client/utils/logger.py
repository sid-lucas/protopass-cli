import logging
from pathlib import Path



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
    _logger.setLevel(logging.INFO)
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
# Public API
# ============================================================
def log_client(level: str, context: str, message: str, user: str | None = None) -> None:
    """
    Écrit un message dans le journal client (fichier).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    resolved_user = _resolve_username(user) or "-"
    extra = {"context": context, "user": resolved_user}
    _logger.log(log_level, message, extra=extra)


def notify_user(message: str) -> None:
    """
    Affiche un message dans la console, destiné à l'utilisateur.
    """
    print(message)
