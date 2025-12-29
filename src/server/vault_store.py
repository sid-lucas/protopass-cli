import json
from pathlib import Path

APP_DIR = Path.home() / ".protopass" / "server_data"
DB_PATH = APP_DIR / "vaults"

def _vault_file_path(username_hash: str) -> Path:
    # retourne le chemin du fichier vaults/{username_hash}.json
    return DB_PATH / f"{username_hash}.json"

def _save_user_vaults(username_hash: str, vaults: list):
    # écrit la liste des vaults sur disque (joli format)
    DB_PATH.mkdir(parents=True, exist_ok=True)
    try:
        DB_PATH.chmod(0o700)
    except Exception:
        pass
    path = _vault_file_path(username_hash)
    path.write_text(json.dumps(vaults, indent=2))

def get_user_vaults(username_hash: str) -> list:
    path = _vault_file_path(username_hash)
    if not path.exists():
        return []
    return json.loads(path.read_text())

def add_vault(username_hash: str, vault_id: str, key_enc: str, signature: str, metadata: dict, items: list):
    vaults = get_user_vaults(username_hash)

    if any(vault["vault_id"] == vault_id for vault in vaults):
        raise ValueError("ID already exists, creation has been aborted.")

    new_vault = {
        "vault_id": vault_id,
        "key_enc": key_enc,
        "signature": signature,
        "metadata": metadata,
        "items": items,
    }

    vaults.append(new_vault)
    _save_user_vaults(username_hash, vaults)
    return True

def remove_vault(username_hash: str, vault_id: str) -> bool:
    vaults = get_user_vaults(username_hash)

    # filtre tous les vaults sauf celui ciblé
    filtered = [v for v in vaults if v["vault_id"] != vault_id]

    if len(filtered) == len(vaults):
        # aucun vault supprimé, id inconnu
        return False

    _save_user_vaults(username_hash, filtered)
    return True

def add_item(username_hash: str, vault_id: str, item: dict) -> bool:
    """
    Ajoute un item chiffré dans le vault donné de l'utilisateur.
    """
    vaults = get_user_vaults(username_hash)

    # Récupère le vault cible dans lequel add l'item
    target = None
    for v in vaults:
        if v.get("vault_id") == vault_id:
            target = v
            break
    if target is None:
        raise ValueError("vault not found")

    # Prend les items déjà présent
    items = target.get("items")
    if items is None:
        items = []
        target["items"] = items

    item_id = item.get("item_id")
    if not item_id:
        raise ValueError("missing item_id")

    if any(i.get("item_id") == item_id for i in items):
        raise ValueError("item_id already exists")

    # Ajoute le nouvel item aux items présent et save le vault
    items.append(item)
    _save_user_vaults(username_hash, vaults)
    return True

def modify_item(username_hash: str, vault_id: str, item: dict) -> bool:
    """
    Met à jour un item existant dans un vault.
    """
    vaults = get_user_vaults(username_hash)

    target = None
    for v in vaults:
        if v.get("vault_id") == vault_id:
            target = v
            break
    if target is None:
        raise ValueError("vault not found")

    items = target.get("items")
    if items is None:
        raise ValueError("item_id not found")

    item_id = item.get("item_id")
    if not item_id:
        raise ValueError("missing item_id")

    for idx, existing in enumerate(items):
        if existing.get("item_id") == item_id:
            items[idx] = item
            _save_user_vaults(username_hash, vaults)
            return True

    raise ValueError("item_id not found")

def remove_item(username_hash: str, vault_id: str, item_id: str) -> bool:
    """
    Supprime un item complet dans un vault.
    """
    vaults = get_user_vaults(username_hash)

    # Trouver le vault
    target = None
    for v in vaults:
        if v.get("vault_id") == vault_id:
            target = v
            break
    if target is None:
        raise ValueError("vault not found")

    items = target.get("items")
    if items is None:
        raise ValueError("no items in vault")

    # Trouver item_id
    for idx, existing in enumerate(items):
        if existing.get("item_id") == item_id:
            del items[idx]
            _save_user_vaults(username_hash, vaults)
            return True

    raise ValueError("item_id not found")
