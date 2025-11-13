import os, json, socket, signal, sys, time, errno, threading, base64, hmac, hashlib
from pathlib import Path
from client.utils.crypto import (
    derive_master_key,
    encrypt_gcm, decrypt_gcm,
)

"""
Protopass Agent — Processus local sécurisé
Garde en mémoire la master_key et exécute les opérations sensibles pour le client CLI.
"""

# Globales
APP_DIR = Path.home() / ".protopass"
SOCK_PATH = APP_DIR / "agent.sock"
TTL = 300 # 5 minutes d'inactivité = auto-destruction

_master_key = None
_ttl_timer = None

# État interne de l'agent
_running = True
_state = {"username": None, "ttl": TTL, "since": int(time.time())}

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
            "start": _op_start,
            "shutdown": _op_shutdown,
            "encrypt": _op_encrypt,
            "decrypt": _op_decrypt,
            "hmac": _op_hmac,   
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

def _wipe_sensitive_data():
    """Efface toute donnée sensible avant arrêt."""
    if _state.get("username"):
        _state["username"] = None

    # Effacement propre de la master_key en mémoire
    global _master_key
    if isinstance(_master_key, bytearray):
        for i in range(len(_master_key)):
            _master_key[i] = 0
    _master_key = None

    _state["locked"] = True
    print("[agent] données sensibles effacées.")

def _schedule_auto_shutdown(ttl):
    """Planifie un arrêt automatique après TTL secondes."""
    global _ttl_timer
    if _ttl_timer:
        _ttl_timer.cancel() # annule l’ancien timer
        _ttl_timer = None

    def _expire():
        print(f"[agent] inactif depuis {ttl}s - arrêt automatique.")
        _op_shutdown()

    _ttl_timer = threading.Timer(ttl, _expire)
    _ttl_timer.daemon = True
    _ttl_timer.start()

def _sig(_s,_f):
    """Gestion du signal SIGINT/SIGTERM -> arrêt propre."""
    global _running; _running = False

# ============================================================
#  Opérations
# ============================================================

def _op_status(req):
    """Retourne l'état actuel de l'agent."""
    return {"status": "ok", "data": _state}

def _op_start(req):
    """
    Démarre la session sécurisée de l'agent.
    - Reçoit les infos utilisateur et le mot de passe
    - Dérive la master_key en fonction du mot de passe
    - Démarre le TTL d'auto-clean
    """
    # Récupération des paramètres envoyés par le client
    user = req["data"]["username"]
    password = req["data"]["password"]
    salt_b64 = req["data"]["salt"]

    # Validation des entrées
    if not user or not password or not salt_b64:
        return {"status": "error", "data": {"code": "ERR_MISSING_CREDENTIALS"}}

    # dérivation clé AES
    salt = base64.b64decode(salt_b64)
    global _master_key
    _master_key = bytearray(derive_master_key(password, salt))

    # Mise à jour de l'état global
    _state.update({
        "username": user,
        "since": int(time.time()),
        "ttl": TTL, # TTL 5 min par défaut
    })

    print(f"[agent] session active pour {user}")

    # Planifie un auto-shutdown quand le TTL expire
    _schedule_auto_shutdown(_state["ttl"])

    return {"status": "ok", "data": {"message": f"session started for {user}"}}

def _op_shutdown(req=None):
    """
    Termine proprement l'agent :
    - Efface les données sensibles
    - Ferme le socket et quitte le process
    """
    global _running
    _running = False
    _wipe_sensitive_data()

    print("[agent] shutdown demandé.")
    return {"status": "ok", "data": {"message": "agent shutting down"}}

def _op_encrypt(req):
    """
    Chiffre un texte clair à l'aide de la master_key en mémoire.
    Renvoie ciphertext, nonce et tag en base64.
    """
    global _master_key
    if not _master_key:
        return {"status": "error", "data": {"code": "ERR_LOCKED"}}

    plaintext = req.get("data", {}).get("plaintext")
    if not plaintext:
        return {"status": "error", "data": {"code": "ERR_MISSING_DATA"}}

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    # Chiffre
    nonce, ciphertext, tag = encrypt_gcm(_master_key, plaintext)

    # Reset le TTL
    _schedule_auto_shutdown(_state["ttl"])

    # Réponse au CLI
    return {
        "status": "ok",
        "data": {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
        },
    }

def _op_decrypt(req):
    """
    Déchiffre un text à l'aide de la master_key en mémoire.
    Attend ciphertext, nonce et tag en base64.
    """
    global _master_key
    if not _master_key:
        return {"status": "error", "data": {"code": "ERR_LOCKED"}}

    data = req.get("data", {})
    ciphertext_b64 = data.get("ciphertext")
    nonce_b64 = data.get("nonce")
    tag_b64 = data.get("tag")

    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        return {"status": "error", "data": {"code": "ERR_MISSING_DATA"}}

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    # Déchiffre
    plaintext = decrypt_gcm(_master_key, nonce, ciphertext, tag)

    # Reset le TTL
    _schedule_auto_shutdown(_state["ttl"])

    # Réponse au CLI
    return {
        "status": "ok",
        "data": {"plaintext": plaintext.decode("utf-8")},
    }

def _op_hmac(req):
    """
    Calcule un HMAC-SHA256(payload) avec la master_key en mémoire.
    Entrée: data.payload_b64 (bytes encodés en base64)
    Sortie: data.hmac (base64 du digest)
    """
    # Vérifie qu'on a une clé en mémoire
    global _master_key
    if not _master_key:
        return {"status": "error", "data": {"code": "ERR_LOCKED"}}

    data = req.get("data", {})
    payload_b64 = data.get("payload_b64")
    if not payload_b64:
        return {"status": "error", "data": {"code": "ERR_MISSING_DATA"}}

    # Décodage du payload
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as e:
        return {"status": "error", "data": {"code": "ERR_BAD_BASE64", "message": str(e)}}

    # Calcule HMAC-SHA256
    mac = hmac.new(bytes(_master_key), payload, digestmod=hashlib.sha256).digest()
    mac_b64 = base64.b64encode(mac).decode()

    # Reset le TTL
    _schedule_auto_shutdown(_state["ttl"])

    return {"status": "ok", "data": {"hmac": mac_b64, "algo": "HMAC-SHA256"}}
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
