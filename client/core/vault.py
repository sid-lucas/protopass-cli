import base64, uuid, os, json
from datetime import datetime, timezone
from .account_state import AccountState
from ..utils import logger as log
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.display import render_table, format_timestamp, prompt_field
from ..utils.crypto import (
    encrypt_gcm,
    decrypt_gcm,
    sign_vault_key,
    wrap_vault_key,
    unwrap_vault_key,
    b64_block_from_bytes,
    bytes_from_b64_block,
)

def _fetch_vault_rows():
    """
    Récupère tous les vaults depuis le serveur, déchiffre leurs métadonnées
    et retourne une liste de lignes prêtes pour l'affichage dans vault list
    """
    # récupération du contexte utilisateur actuel
    current_user = AccountState.username()
    logger = log.get_logger(CTX.VAULT_LIST, current_user)
    session_payload = AccountState.session_payload()
    if session_payload is None:
        logger.error("No active session found in account state.")
        notify_user("No active session. Please log in.")
        return None
    # requête API pour récupérer les vaults distants
    resp = api_post("/vault/list", session_payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vaults"],
        context=CTX.VAULT_LIST,
        user=current_user
    )
    if data is None:
        notify_user("Unable to retrieve vault list. See logs for details.")
        return None
    vaults = data["vaults"]
    if len(vaults) == 0:
        notify_user("No vaults found.")
        return None
    
    # récupération de la clé privée locale pour déchiffrer les données
    private_key = AccountState.private_key()
    if private_key is None:
        logger.error("No valid private key in account state (memory).")
        notify_user("Unable to decrypt vaults with current keys.")
        return None
    
    # boucle sur chaque coffre pour construire les lignes d'affichage
    rows = []
    for vault in vaults:
        vault_id = vault.get("vault_id", "unknown")
        try:
            # Déchiffrement des métadonnées
            vault_key_enc = base64.b64decode(vault["key_enc"])
            vault_key = unwrap_vault_key(private_key, vault_key_enc)

            # met la clé de ce vault en cache RAM
            AccountState.set_vault_key(vault_id, vault_key)

            metadata_blob = vault.get("metadata")
            if not metadata_blob:
                raise ValueError("missing metadata blob")
            enc, nonce, tag = bytes_from_b64_block(metadata_blob)
            plaintext = decrypt_gcm(vault_key, enc, nonce, tag).decode()
            metadata = json.loads(plaintext)
            vault_name = metadata.get("name")
            description = metadata.get("description")
            created_at = metadata.get("created_at")
            created_display = format_timestamp(created_at) if created_at else "-"

        except Exception as e:
            logger.warning(f"Failed to decrypt vault '{vault_id[:8]}' ({e})")
            continue

        # ajoute le nouveau vault lu dans une ligne
        rows.append({
            "idx": str(len(rows) + 1),
            "name": vault_name or "-",
            "desc": description or "-",
            "created": created_display,
            "uuid": vault["vault_id"]
        })

    return rows

def _get_vault_uuid_by_index(index: int, rows=None, logger=None):
    """
    Retourne l'UUID du vault correspondant à l'index affiché dans vault list,
    ou None si introuvable ou si aucune ligne.

    rows: liste pré-calculée issue de _fetch_vault_rows pour éviter les requêtes doublons.
    """
    if rows is None:
        rows = _fetch_vault_rows()
    failed = False

    if not rows:
        failed = True

    if not failed :
        for row in rows:
            if row.get("idx") == str(index):
                return row.get("uuid")


    notify_user(f"No vault found for index {index}.")
    if logger:
        logger.error(f"No vault associated with index '{index}'")
    return None



def delete_vault(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.VAULT_DELETE, AccountState.username())

    rows = _fetch_vault_rows()
    if not rows:
        return
    
    # Trouver le vault via l'index
    vault_id_to_del = _get_vault_uuid_by_index(args.index, rows, logger)
    if vault_id_to_del is None:
        return

    notify_user(f"found vault id to del : {vault_id_to_del}")

    session_payload = AccountState.session_payload()
    if session_payload is None:
        logger.error("No valid session found in account state.")
        return
    # Envoie les informations du nouveau vault au serveur
    payload = {
        **session_payload,
        "vault_id": vault_id_to_del,
    }
    resp = api_post("/vault/delete", payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vault_id"],
        context=CTX.VAULT_DELETE,
        user=current_user
    )
    if data is None:
        notify_user("Vault deletion failed. See logs for details.")
        return
    
    # Nettoie l'état local si on supprime le vault actuellement sélectionné
    current_selected = AccountState.current_vault()
    if current_selected == vault_id_to_del:
        AccountState.clear_current_vault()
    AccountState.remove_vault_key(vault_id_to_del)

    notify_user(f"Vault deleted successfully.")

def select_vault(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.VAULT_SELECT, current_user)

    # On récupère les lignes (et, par effet de bord, on remplit _vault_keys)
    rows = _fetch_vault_rows()
    if not rows:
        return

    # Retrouve l'UUID à partir de l'index
    vault_id = _get_vault_uuid_by_index(args.index, rows, logger)
    if vault_id is None:
        return

    # Essaie de récupérer la clé en RAM (si elle y est déjà)
    vault_key = AccountState.vault_key(vault_id)
    if vault_key is None:
        # Si pas en RAM, on déclenche un fetch complet (equivalent de vault list)
        rows = _fetch_vault_rows()
        if not rows:
            return

        # Maintenant la clé DOIT être en RAM si tout s’est bien passé
        vault_key = AccountState.vault_key(vault_id)
        if vault_key is None:
            logger.error(f"Failed to load vault_key for vault {vault_id}")
            notify_user("Unable to decrypt selected vault key.")
            return

    # Maj du vault courant
    AccountState.set_current_vault(vault_id)

    notify_user(f"Vault {args.index} is now selected.")

    
def list_vaults(_args):
    if not AccountState.valid():
        print("Please login to list vaults.")
        return

    rows = _fetch_vault_rows()
    if not rows:
        return
    
    # Ajout du marqueur "*" sur le vault sélectionné
    current = AccountState.current_vault()
    if current:
        for row in rows:
            if row["uuid"] == current:
                row["idx"] = "*" + row["idx"]
                break

    columns = [
        ("idx", "#", 3),
        ("name", "Name", 15),
        ("desc", "Description", 40),
        ("created", "Created", 17),
    ]
    print(render_table(rows, columns))

def create_vault(_args):
    current_user = AccountState.username()
    public_key = AccountState.public_key()
    private_key = AccountState.private_key()
    if current_user is None or public_key is None or private_key is None:
        notify_user(
            "Vault creation aborted: local account state is invalid.\n"
            "Run 'logout' then 'login' to regenerate your keys."
        )
        return
    
    logger = log.get_logger(CTX.VAULT_CREATE, current_user)

    vault_name = prompt_field("Vault name", 15, False, logger)
    description = prompt_field("Description", 40, True, logger)

    # Création du JSON
    now = datetime.now(timezone.utc).isoformat()
    metadata_plain = {
        "name": vault_name,
        "description": description,
        "created_at": now,
    }
    metadata_plaintext = json.dumps(metadata_plain)

    # Génère un UUID pour le vault
    vault_id = str(uuid.uuid4())
    # Génère une clé symétrique de 256bits pour le vault
    vault_key = os.urandom(32)

    # signature de la clé du vault avec la clé privée de l'utilisateur
    vault_signature = sign_vault_key(private_key, vault_key)

    # chiffre la clé du vault avec la clé publique de l'utilisateur
    vault_key_enc = wrap_vault_key(public_key, vault_key)

    # chiffrement des métadonnées du vault avec la vault_key
    ciphertext, nonce, tag = encrypt_gcm(vault_key, metadata_plaintext.encode())
    metadata_blob = b64_block_from_bytes(ciphertext, nonce, tag)

    # Pas d'items créés pour l'instant

    session_payload = AccountState.session_payload()
    if session_payload is None:
        logger.error("No valid session found in account state.")
        return
    # Envoie les informations du nouveau vault au serveur
    payload = {
        **session_payload,
        "vault_id": vault_id,
        "key_enc": base64.b64encode(vault_key_enc).decode(),
        "signature": base64.b64encode(vault_signature).decode(),
        "metadata": metadata_blob,
        "items": []
    }
    resp = api_post("/vault/create", payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vault_id"],
        context=CTX.VAULT_CREATE,
        user=current_user
    )
    if data is None:
        notify_user("Vault creation failed. See logs for details.")
        return

    notify_user(f"Vault '{vault_name}' created successfully.")
