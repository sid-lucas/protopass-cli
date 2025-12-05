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

# ============================================================
#  Internal helpers
# ============================================================

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

# ============================================================
#  Gestion des items
# ============================================================

def list_items(_args):
    if not AccountState.valid():
        print("Please login to list items.")
        return

    logger = log.get_logger(CTX.ITEM_LIST, AccountState.username())
    rows = _fetch_item_rows()
    if not rows:
        return
    logger.info(f"{len(rows)} item(s) retrieved")

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
    logger.info(f"Item '{item_id[:8]}...' displayed")

def create_item(args):
    logger = log.get_logger(CTX.ITEM_CREATE, AccountState.username())

    # Vérifier qu’un vault est sélectionné
    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>")
        return

    # Récupérer la clé du vault
    vault_key = vault.ensure_vault_key(vault_id, logger)
    if vault_key is None:
        notify_user("Vault key not available. Try selecting the vault again.")
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
        if field == Field.CARDNUMBER:
            return "Card number"
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

    # Collecte des champs supplémentaires fournis en CLI (hors required/recommended)
    extra_fields = [f for f in Field if f not in schema["required"] and f not in schema["recommended"]]
    for field in extra_fields:
        attr = field.value
        cli_value = getattr(args, attr, None)
        if cli_value is None:
            continue
        label = _label_for(field)
        max_len = FIELD_MAXLEN.get(field)
        valid = verify_prompt(cli_value, label, max_len or len(cli_value), True, logger)
        if valid is False:
            return
        if valid is None:
            fields[attr] = None
        else:
            fields[attr] = cli_value.strip()

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

def delete_item(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_DELETE, current_user)

    if not AccountState.valid():
        print("Please login to delete an item.")
        return

    rows = _fetch_item_rows()
    if not rows:
        return

    item_id, _ = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return

    vault_id = AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected.")
        return

    payload = {
        **AccountState.session_payload(),
        "vault_id": vault_id,
        "item_id": item_id
    }

    resp = api_post("/item/delete", payload)
    data = handle_resp(resp, context=CTX.ITEM_DELETE)

    if data is None:
        notify_user("Item deletion failed.")
        return

    notify_user(f"Item #{args.index} deleted.")

# ============================================================
#  Gestion des champs d'un item
# ============================================================

def add_item_field(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_UPDATE, current_user)

    # Récupérer tous les items du vault courant
    rows = _fetch_item_rows()
    if not rows:
        return

    # Trouver item_id via index fourni
    item_id, _ = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return

    # Charger les infos de l'item
    loaded = _load_item(item_id, logger)
    if not loaded:
        return
    raw_item, item_key, data, target_vault = loaded

    # Collecte des champs fournis via flags (mêmes noms que item create)
    candidate_values = {
        Field.NAME: getattr(args, "name", None),
        Field.EMAIL: getattr(args, "email", None),
        Field.PASSWORD: getattr(args, "password", None),
        Field.URL: getattr(args, "url", None),
        Field.FIRSTNAME: getattr(args, "firstname", None),
        Field.LASTNAME: getattr(args, "lastname", None),
        Field.PHONE: getattr(args, "phone", None),
        Field.NOTES: getattr(args, "notes", None),
        Field.CARDNUMBER: getattr(args, "cardnumber", None),
        Field.EXPIRY: getattr(args, "expiry", None),
        Field.HOLDER: getattr(args, "holder", None),
        Field.CVV: getattr(args, "cvv", None),
    }

    if getattr(args, "password_auto", False):
        candidate_values[Field.PASSWORD] = generate_password(options=PasswordOptions())

    added = []
    skipped = []

    for field, val in candidate_values.items():
        if val is None:
            continue
        if field.value in data:
            skipped.append(field.value)
            continue
        max_len = FIELD_MAXLEN.get(field)
        if max_len and len(val) > max_len:
            notify_user(f"Value too long for '{field.value}' (max {max_len}).")
            return
        data[field.value] = val
        added.append(field.value)

    ok = _save_item(item_id, item_key, data, target_vault, raw_item, logger)
    if not ok:
        return

    if added:
        added_msg = ", ".join(added)
        notify_user(f"Field(s) added: {added_msg}.")
    if skipped and not added:
        skipped_msg = ", ".join(skipped)
        notify_user(f"No new fields added. Already present: {skipped_msg}.")
    elif skipped:
        skipped_msg = ", ".join(skipped)
        notify_user(f"Skipped existing fields: {skipped_msg}.")

def edit_item_field(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_UPDATE, current_user)

    # Récupérer tous les items du vault courant
    rows = _fetch_item_rows()
    if not rows:
        return

    # Trouver item_id via index fourni
    item_id, _ = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return

    # Charger les infos de l'item
    loaded = _load_item(item_id, logger)
    if not loaded:
        return
    raw_item, item_key, data, target_vault = loaded

    # Vérifier le champ fourni
    try:
        field = Field(args.field)
    except ValueError:
        notify_user(f"Invalid field '{args.field}'.")
        return
    if field.value not in data:
        notify_user(f"Field '{field.value}' does not exist in this item.")
        return

    # Vérifier longueur max
    max_len = FIELD_MAXLEN.get(field)
    if max_len and len(args.value) > max_len:
        notify_user(f"Value too long for '{field.value}' (max {max_len}).")
        return

    # Mise à jour du champ
    data[field.value] = args.value
    ok = _save_item(item_id, item_key, data, target_vault, raw_item, logger)
    if not ok:
        return

    notify_user(f"Field '{field.value}' updated.")

def delete_item_field(args):
    current_user = AccountState.username()
    logger = log.get_logger(CTX.ITEM_UPDATE, current_user)

    # Récupérer tous les items du vault courant
    rows = _fetch_item_rows()
    if not rows:
        return

    # Trouver item_id via index fourni
    item_id, _ = get_id_by_index(args.index, rows, logger=logger)
    if item_id is None:
        return
    
    # Charger les infos de l'item
    loaded = _load_item(item_id, logger)
    if not loaded:
        return
    raw_item, item_key, data, target_vault = loaded

    # Vérifier champ
    try:
        field = Field(args.field)
    except ValueError:
        notify_user(f"Invalid field '{args.field}'.")
        return
    if field.value not in data:
        notify_user(f"Field '{field.value}' does not exist in this item.")
        return

    # Vérifier required (interdit de supprimer)
    item_type = Type(data["type"])
    required_fields = [f.value for f in SCHEMAS[item_type]["required"]]

    if field.value in required_fields:
        notify_user(f"Field '{field.value}' is required and cannot be deleted.")
        return

    # Suppression
    del data[field.value]
    ok = _save_item(item_id, item_key, data, target_vault, raw_item, logger)
    if not ok:
        return

    notify_user(f"Field '{field.value}' deleted.")
