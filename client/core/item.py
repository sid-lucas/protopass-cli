import uuid, json, os, base64
from datetime import datetime, timezone
from .items.schemas import Type, Field, SCHEMAS, FIELD_MAXLEN
from .items.prompt import prompt_fields_for_type
from .account_state import AccountState
from ..utils import logger as log
from ..utils.common import get_id_by_index
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.display import render_table, format_timestamp
from ..utils.crypto import (
    encrypt_gcm,
    decrypt_gcm,
    b64_block_from_bytes,
    bytes_from_b64_block,
)

def _fetch_item_rows():
    """
    Récupère et déchiffre les items du vault courant.
    Retourne une liste de dicts prêts pour un rendu tabulaire.
    """
    # récupération du contexte utilisateur actuel
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_LIST, current_user)
    session_payload = AccountState.session_payload()
    if session_payload is None:
        logger.error("No valid session payload.")
        notify_user("No active session. Please log in.")
        return None

    # Vérifie le vault sélectionner et récupère la clé
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>.")
        return None
    vault_key = AccountState.vault_key(vault_id)
    if vault_key is None:
        logger.error("No vault key in memory for current vault.")
        notify_user("Selected vault not found. Try to select the vault again.")
        return None

    # Récupère tous les vaults et trouve celui qui nous intéresse
    # TODO Surement moyen de factoriser avec comment fonctionne 'fetch vault' dans vault.py
    resp = api_post("/vault/list", session_payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vaults"],
        context=CTX.ITEM_LIST,
        user=current_user
    )
    if data is None:
        notify_user("Unable to retrieve vaults for item listing.")
        return None
    target_vault = None
    for v in data["vaults"]:
        if v.get("vault_id") == vault_id:
            target_vault = v
            break
    if target_vault is None:
        logger.error(f"Current vault '{vault_id}' not found on server.")
        notify_user("Selected vault not found on server.")
        return None

    # Récupère les items du vault sélectionné
    items = target_vault.get("items", [])
    if not items:
        notify_user("No items in this vault.")
        return []
    
    rows = []
    for idx, item in enumerate(items, start=1):
        item_id = item.get("item_id", "unknown")
        try:
            # 1) déchiffre item_key avec vault_key
            key_enc, key_nonce, key_tag = bytes_from_b64_block(item["key"])
            item_key = decrypt_gcm(vault_key, key_enc, key_nonce, key_tag)

            # 2) déchiffre le contenu avec item_key
            enc, nonce, tag = bytes_from_b64_block(item["content"])
            plaintext = decrypt_gcm(item_key, enc, nonce, tag).decode()

            data = json.loads(plaintext)
            type = (data.get("type") or "-").upper()
            title = data.get("title") or "-"
            created_at = data.get("created_at")
            created_display = format_timestamp(created_at) if created_at else "-"
            updated_at = data.get("updated_at")
            updated_display = format_timestamp(updated_at) if updated_at else "-"

        except Exception as e:
            logger.warning(f"Failed to decrypt item '{item_id[:8]}': {e}")
            continue
    
        rows.append({
            "idx": str(idx),
            "type": type,
            "title": title,
            "created": created_display,
            "updated": updated_display,
            "uuid": item.get("item_id"),
        })

    return rows

def list_items(_args):
    if not AccountState.valid():
        print("Please login to list items.")
        return

    rows = _fetch_item_rows()
    if not rows:
        return

    columns = [
        ("idx", "#", 3),
        ("type", "Type", 8),
        ("title", "Name", FIELD_MAXLEN[Field.TITLE]),
        ("updated", "Last modified", 17),
        ("created", "Created", 17),
    ]
    print(render_table(rows, columns))

def show_item(args):
    return


def create_item(_args):
    logger = log.get_logger(CTX.ITEM_CREATE, AccountState.username())

    # Vérifier qu’un vault est sélectionné
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>")
        return

    # Récupérer la clé du vault
    vault_key = AccountState.vault_key(vault_id)
    if vault_key is None:
        notify_user("Vault key not found. Try to select a vault again.")
        return

    # POUR LINSTANT : TYPE "LOGIN" PAR DEFAUT
    # A CHANGER PLUS TARD
    item_type = Type.LOGIN

    # Création du JSON
    now = datetime.now(timezone.utc).isoformat()
    fields = prompt_fields_for_type(item_type)
    plaintext = {
        "type": item_type.value,
        **fields,
        "created_at": now,
        "updated_at": now,
    }
    plaintext_json = json.dumps(plaintext).encode()

    # Génère un UUID pour l'item
    item_id = str(uuid.uuid4())
    # Génère une clé symétrique de 256bits pour l'item
    item_key = os.urandom(32)

    # Chiffrement du contenu avec item_key
    enc, nonce, tag = encrypt_gcm(item_key, plaintext_json)
    # Chiffrement de item_key avec vault_key
    key_enc, key_nonce, key_tag = encrypt_gcm(vault_key, item_key)


    # Construction du payload pour envoi au serveur
    payload = {
        **AccountState.session_payload(),
        "vault_id": vault_id,
        "item": {
            "item_id": item_id,
            "key": {
                "enc": base64.b64encode(key_enc).decode(),
                "nonce": base64.b64encode(key_nonce).decode(),
                "tag": base64.b64encode(key_tag).decode()
            },
            "content": {
                "enc": base64.b64encode(enc).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(tag).decode()
            }
        }
    }
    resp = api_post("/item/create", payload)
    data = handle_resp(resp, required_fields=["item_id"], context=CTX.ITEM_CREATE)

    if data is None:
        notify_user("Item creation failed.")
        return

    notify_user(f"Item '{plaintext['title']}' created.")
