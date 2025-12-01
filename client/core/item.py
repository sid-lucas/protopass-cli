import uuid, json, os, base64
from datetime import datetime, timezone
from .item_schema import Type, Field, SCHEMAS, FIELD_MAXLEN
from .account_state import AccountState
from . import vault
from .generator import PasswordOptions, generate_password
from ..utils import logger as log
from ..utils.common import get_id_by_index, fetch_vaults, find_vault_by_id
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.display import (
    render_table,
    format_timestamp,
    prompt_field,
    verify_prompt,
    render_item_details,
)
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
    vault_key = vault.ensure_vault_key(vault_id, logger)
    if vault_key is None:
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
            name = data.get("name") or "-"
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
            "name": name,
            "created": created_display,
            "updated": updated_display,
            "uuid": item.get("item_id"),
        })

    return rows

def _load_item(item_id, logger):
    """
    Charge un item complet :
    - retrouve le vault courant
    - retrouve l'item brut
    - déchiffre item_key
    - déchiffre data JSON
    Retourne (raw_item, item_key, data, target_vault)
    """
    session_payload = AccountState.session_payload()
    if session_payload is None:
        return None

    current_user = AccountState.username()

    # Récupere le vault courant
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected.")
        return None

    vault_key = vault.ensure_vault_key(vault_id, logger)
    if vault_key is None:
        return None

    # Récupère les vaults et trouver le bon
    vaults = fetch_vaults(session_payload, current_user, CTX.ITEM_SHOW)
    target_vault = find_vault_by_id(vaults, vault_id)
    if target_vault is None:
        notify_user("Vault not found on server.")
        return None

    # Trouver l'item brut
    raw_items = target_vault.get("items", [])
    raw_item = next((it for it in raw_items if it.get("item_id") == item_id), None)
    if raw_item is None:
        notify_user("Item not found.")
        return None

    # Déchiffrer clés + contenu
    try:
        item_key = decrypt_b64_block(vault_key, raw_item["key"])
        plaintext = decrypt_b64_block(item_key, raw_item["content"])
        data = json.loads(plaintext)
    except Exception as e:
        logger.error(f"Failed to decrypt item: {e}")
        return None

    return raw_item, item_key, data, target_vault

def _save_item(item_id, item_key, data, target_vault, raw_item, logger):
    """
    Rechiffre l'item modifié et le renvoie au serveur.
    """
    # Mise à jour du timestamp
    now = datetime.now(timezone.utc).isoformat()
    data["updated_at"] = now

    # Rechiffrement du JSON
    plaintext = json.dumps(data).encode()
    new_content_block = encrypt_b64_block(item_key, plaintext)

    # Préparation du payload
    payload = {
        **AccountState.session_payload(),
        "vault_id": target_vault["vault_id"],
        "item": {
            "item_id": item_id,
            "key": raw_item["key"], # même item = même clé
            "content": new_content_block # maj du contenu seulement
        }
    }

    resp = api_post("/item/update", payload)
    result = handle_resp(resp, context=CTX.ITEM_UPDATE)

    if result is None:
        notify_user("Failed to update item.")
        return False

    return True







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
        ("name", "Name", FIELD_MAXLEN[Field.NAME]),
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

    # Récupère les lignes (idx, name, type, uuid, ...)
    rows = _fetch_item_rows()
    if not rows:
        return

    # Retrouve l'id de l'item à partir de l'index
    item_id, _ = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return

    # Récupère le vault courant
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>.")
        return

    vault_key = vault.ensure_vault_key(vault_id, logger)
    if vault_key is None:
        notify_user("Unable to load the selected vault key. Try to select the vault again.")
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

    # Déchiffre item_key et le contenu
    try:
        item_key = decrypt_b64_block(vault_key, raw_item["key"])
        plaintext = decrypt_b64_block(item_key, raw_item["content"])
    except Exception as e:
        logger.error(f"Failed to decrypt: {e}")
        notify_user("An error occured. Check the logs for more details.")
        return
    
    data = json.loads(plaintext)

    # Affichage plus lisible (table Field/Value)
    print("\n=== Item details ===")
    print(render_item_details(data))



def create_item(args):
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

    # Reçoit le type et doit être présent dans l'enum
    if not args.type:
        notify_user("You must specify --type <type>.")
        return
    try:
        item_type = Type(args.type)
    except ValueError:
        notify_user(f"Invalid type '{args.type}'.\nValid types: {[t.value for t in Type]}")
        return

    schema = SCHEMAS[item_type]

    if getattr(args, "password_auto", False):
        args.password = generate_password(options=PasswordOptions())
    fields = {}

    def _label_for(field: Field) -> str:
        if field.value == "name":
            return "Item name"
        if field.value == "email":
            return "Account email or username"
        return field.value.replace("_", " ")

    def _collect(field: Field, allow_empty: bool) -> bool:
        attr = field.value
        cli_value = getattr(args, attr, None)
        label = _label_for(field)
        max_len = FIELD_MAXLEN[field]

        if cli_value is not None:
            valid = verify_prompt(cli_value, label, max_len, allow_empty, logger)
            if valid is False:
                return False
            if valid is None:
                fields[attr] = None
            else:
                fields[attr] = cli_value.strip()
            return True

        fields[attr] = prompt_field(label, max_len, allow_empty, logger)
        return True

    for field in schema["required"]:
        if _collect(field, allow_empty=False) is False:
            return

    for field in schema["recommended"]:
        if _collect(field, allow_empty=True) is False:
            return

    # Création du JSON
    now = datetime.now(timezone.utc).isoformat()
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

    notify_user(f"Item '{plaintext['name']}' created.")
