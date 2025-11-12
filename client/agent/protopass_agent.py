import os, json, socket, signal, sys, time, errno
from pathlib import Path

"""
Protopass Agent — Processus local sécurisé
Garde en mémoire la master_key et exécute les opérations sensibles pour le client CLI.
"""

# Constantes globales
APP_DIR = Path.home() / ".protopass"
SOCK_PATH = APP_DIR / "agent.sock"

# État interne de l'agent
_running = True
_state = {"locked": True, "username": None, "ttl": None, "since": int(time.time())}

# ============================================================
#  Gestion de l'agent
# ============================================================

def _cleanup():
    """Supprime le socket existant s'il reste un fichier précédent."""
    try:
        if SOCK_PATH.exists(): SOCK_PATH.unlink()
    except Exception:
        pass

def _prepare_socket():
    """
    Crée le répertoire ~/.protopass avec les bonnes permissions (restrictives),
    puis ouvre et sécurise le socket UNIX (owner-only).
    """
    APP_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(APP_DIR, 0o700)
    _cleanup()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(SOCK_PATH))
    os.chmod(SOCK_PATH, 0o600)

    # Vérifie que le fichier socket appartient bien à l'utilisateur courant
    st = os.stat(SOCK_PATH)
    if (st.st_mode & 0o777) != 0o600 or st.st_uid != os.getuid():
        raise PermissionError("agent.sock must be 0600 and owned by current user")
    s.listen(5)
    return s

def _handle(line: str):
    """
    Analyse la requête JSON reçue et renvoie une réponse JSON conforme.
    """
    try:
        req = json.loads(line) if line else {}
        op = req.get("op")
        mid = req.get("id")

        # Dictionnaire de dispatch : plus clair, extensible
        ops = {
            "status": _op_status,
            "unlock": _op_unlock,
            "lock": _op_lock,
            "shutdown": _op_shutdown,
        }
        
        if op not in ops:
            resp = {"status": "error", "data": {"code": "ERR_UNKNOWN_OP"}}
        else:
            resp = ops[op](req)

        resp["id"] = mid
        return resp

    except Exception as e:
        return {"status": "error",
                "data": {"code": "ERR_BAD_JSON", "message": str(e)}}

def _serve(sock):
    """
    Boucle principale de l'agent :
    - Attend une connexion sur le socket
    - Reçoit une ligne JSON
    - Traite la requête et renvoie la réponse
    """
    while _running:
        try:
            conn, _ = sock.accept()
        except OSError as e:
            if e.errno in (errno.EINTR, errno.EAGAIN): continue
            break

        with conn:
            data = conn.recv(1 << 20) # lecture jusqu'à 1 Mo MAX
            line = data.strip().decode("utf-8", "replace")
            resp = _handle(line) # Traite la requête
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

def _sig(_s,_f):
    """Gestion du signal SIGINT/SIGTERM -> arrêt propre."""
    global _running; _running = False

# ============================================================
#  Opérations
# ============================================================

def _op_status(req):
    """Retourne l'état actuel de l'agent."""
    return {"status": "ok", "data": _state}

def _op_unlock(req):
    """Simule un déverrouillage"""
    user = req.get("data", {}).get("username")
    if not user:
        return {"status": "error", "data": {"code": "ERR_MISSING_USER"}}

    _state.update({
        "locked": False,
        "username": user,
        "since": int(time.time())
    })
    return {"status": "ok", "data": {"message": f"unlocked (stub) for {user}"}}

def _op_lock(req):
    """Verrouille l'agent"""
    _state.update({
        "locked": True,
        "username": None,
        "since": int(time.time())
    })
    return {"status": "ok", "data": {"message": "locked"}}

def _op_shutdown(req):
    """Ferme proprement l'agent."""
    global _running
    _running = False
    return {"status": "ok", "data": {"message": "bye"}}

# ============================================================
#  main
# ============================================================

def main():
    """
    Point d'entrée principal de l'agent.
    Initialise le socket et lance la boucle de service.
    """
    # crée uniquement des fichiers accessibles au user
    os.umask(0o177) 

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"[agent] en écoute sur {SOCK_PATH}")
    sock = _prepare_socket()

    try:
        _serve(sock)
    finally:
        print("[agent] arrêt en cours...")
        sock.close()
        _cleanup()
        


if __name__ == "__main__":
    sys.exit(main() or 0)