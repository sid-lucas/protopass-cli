import uuid, json, os, base64
from datetime import datetime, timezone
from .items.schemas import Type, Field, SCHEMAS, FIELD_MAXLEN
from .items.prompt import prompt_fields_for_type
from .account_state import AccountState
from ..utils import logger as log
from ..utils.common import get_id_by_index, fetch_vaults, find_vault_by_id
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.display import render_table, format_timestamp
from ..utils.crypto import (
    encrypt_b64_block,
    decrypt_b64_block,
    b64_block_from_bytes,
    bytes_from_b64_block,
)

def _fetch_item_rows():
    """
    Récupère et déchiffre les items du vault courant.
    Retourne une liste de dicts prêts pour un rendu tabulaire.
    """
    # récupération du contexte utilisateur actuel
    session_payload = AccountState.session_payload()
    if session_payload is None:
        return None
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_LIST, current_user)

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
    vaults = fetch_vaults(session_payload, current_user, CTX.ITEM_LIST)
    target_vault = find_vault_by_id(vaults, vault_id)
    if target_vault is None:
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
            item_key = decrypt_b64_block(vault_key, item["key"])
            # 2) déchiffre le contenu avec item_key
            plaintext = decrypt_b64_block(item_key, item["content"])

            data = json.loads(plaintext)
            type = (data.get("type") or "-").upper()
            title = data.get("title") or "-"
            created_at = data.get("created_at")
            created_display = format_timestamp(created_at) if created_at else "-"
            updated_at = data.get("updated_at")
            updated_display = format_timestamp(updated_at) if updated_at else "-"

        except Exception as e:
            logger.error(f"Failed to decrypt item '{item_id[:8]}': {e}")
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
    # récupération du contexte utilisateur actuel
    session_payload = AccountState.session_payload()
    if session_payload is None:
        return
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_SHOW, current_user)

    # Récupère les lignes (idx, title, type, uuid, ...)
    rows = _fetch_item_rows()
    if not rows:
        return

    # Retrouve l'id de l'item à partir de l'index
    item_id = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return

    # Récupère le vault courant
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>.")
        return

    vault_key = AccountState.vault_key(vault_id)
    if vault_key is None:
        logger.error("No vault key in memory for current vault.")
        notify_user("Vault key not found. Try to select the vault again.")
        return

    # Récupère tous les vaults puis celui qui nous intéresse
    vaults = fetch_vaults(session_payload, current_user, CTX.ITEM_SHOW)
    if vaults is None:
        notify_user("Unable to retrieve vaults for item show.")
        return

    target_vault = find_vault_by_id(vaults, vault_id)
    if target_vault is None:
        logger.error(f"Current vault '{vault_id}' not found on server.")
        notify_user("Selected vault not found on server.")
        return

    # Retrouve l'item brut dans ce vault
    raw_items = target_vault.get("items", [])
    raw_item = next((it for it in raw_items if it.get("item_id") == item_id), None)
    if raw_item is None:
        notify_user("Item not found on server.")
        return

    # 1) Déchiffre item_key via vault_key
    try:
        key_enc, key_nonce, key_tag = bytes_from_b64_block(raw_item["key"])
        item_key = decrypt_gcm(vault_key, key_enc, key_nonce, key_tag)
    except Exception as e:
        logger.error(f"Failed to decrypt item key: {e}")
        notify_user("Unable to decrypt item key.")
        return

    # 2) Déchiffre le contenu via item_key
    try:
        enc, nonce, tag = bytes_from_b64_block(raw_item["content"])
        plaintext = decrypt_gcm(item_key, enc, nonce, tag).decode()
        data = json.loads(plaintext)
    except Exception as e:
        logger.error(f"Failed to decrypt item content: {e}")
        notify_user("Unable to decrypt item content.")
        return

    # Affichage simple du JSON déchiffré
    print("\n=== Item details ===")
    for k, v in data.items():
        print(f"{k}: {v}")
    print("")



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
    key_block = encrypt_b64_block(vault_key, item_key)
    # Chiffrement de item_key avec vault_key
    content_block = encrypt_b64_block(item_key, plaintext_json)

    # Construction du payload pour envoi au serveur
    payload = {
        **AccountState.session_payload(),
        "vault_id": vault_id,
        "item": {
            "item_id": item_id,
            "key": key_block,
            "content": content_block
        }
    }
    resp = api_post("/item/create", payload)
    data = handle_resp(resp, required_fields=["item_id"], context=CTX.ITEM_CREATE)

    if data is None:
        notify_user("Item creation failed.")
        return

    notify_user(f"Item '{plaintext['title']}' created.")
