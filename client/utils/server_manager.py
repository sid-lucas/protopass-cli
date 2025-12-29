import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
PID_FILE = ROOT_DIR / "server" / "protopass_server.pid"
LOG_FILE = ROOT_DIR / "server" / "server.log"


def _read_pid() -> int | None:
    try:
        pid = int(PID_FILE.read_text().strip())
        return pid if pid > 0 else None
    except Exception:
        return None


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_server() -> tuple[bool, str]:
    """Launch the Flask server in background."""
    existing_pid = _read_pid()
    if existing_pid and _is_running(existing_pid):
        return False, f"Server already running (pid {existing_pid})."

    PID_FILE.unlink(missing_ok=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            proc = subprocess.Popen(
                [sys.executable, "-m", "server.app"],
                cwd=ROOT_DIR,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
            )
    except Exception as exc:
        return False, f"Failed to start server: {exc}"

    PID_FILE.write_text(str(proc.pid))

    # Petite pause pour vérifier que le process reste vivant.
    time.sleep(0.2)
    if not _is_running(proc.pid):
        PID_FILE.unlink(missing_ok=True)
        return False, "Server process exited immediately (see server.log)."

    return True, f"Server started (pid {proc.pid}). Logs: {LOG_FILE}"


def stop_server(timeout: float = 5.0) -> tuple[bool, str]:
    """Terminate the background Flask server if running."""
    pid = _read_pid()
    if not pid:
        return False, "No server PID file found."

    if not _is_running(pid):
        PID_FILE.unlink(missing_ok=True)
        return False, "Server is not running (stale PID removed)."

    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as exc:
        return False, f"Failed to terminate server (pid {pid}): {exc}"

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _is_running(pid):
            PID_FILE.unlink(missing_ok=True)
            return True, f"Server stopped (pid {pid})."
        time.sleep(0.1)

    # Tentative cleanup même si le process persiste
    PID_FILE.unlink(missing_ok=True)
    return False, f"Server may still be running (pid {pid}) after SIGTERM."
