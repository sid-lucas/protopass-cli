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

    # Vérifie que le fichier socket appartient bien à l’utilisateur courant
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

        # -- Listes des commandes (op) --

        if op == "status":
            # Retourne l’état actuel de l’agent
            return {"id": mid, "status": "ok", "data": _state}
        
        if op == "shutdown":
            # Demande d’arrêt propre
            global _running; _running = False
            return {"id": mid, "status": "ok", "data": {"message":"bye"}}
        
        
        # Commande inconnue
        return {"id": mid, "status": "error", "data": {"code":"ERR_UNKNOWN_OP"}}
    

    except Exception as e:
        # JSON invalide ou autre erreur
        return {"status":"error","data":{"code":"ERR_BAD_JSON","message":str(e)}}

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
            data = conn.recv(1 << 20) # lecture jusqu’à 1 Mo MAX
            line = data.strip().decode("utf-8", "replace")
            resp = _handle(line) # Traite la requête
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

def _sig(_s,_f):
    """Gestion du signal SIGINT/SIGTERM -> arrêt propre."""
    global _running; _running = False

def main():
    """
    Point d’entrée principal de l’agent.
    Initialise le socket et lance la boucle de service.
    """
    # crée uniquement des fichiers accessibles au user
    os.umask(0o177) 

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    sock = _prepare_socket()
    try:
        _serve(sock)
    finally:
        sock.close()
        _cleanup()

if __name__ == "__main__":
    sys.exit(main() or 0)