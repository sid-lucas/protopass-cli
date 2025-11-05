import logging
from pathlib import Path


LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "protopass.log"

_logger = logging.getLogger("protopass.client")
if not _logger.handlers:
    _logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(context)s | user=%(user)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    _logger.addHandler(file_handler)
    _logger.propagate = False


def _resolve_username(explicit_user: str | None) -> str | None:
    if explicit_user:
        return explicit_user
    try:
        from core.account_state import AccountState  # type: ignore
        return AccountState.username()
    except Exception:
        return None


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
