import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "server_data" / "vaults"

def _vault_file_path(username_hash: str) -> Path:
    # retourne le chemin du fichier vaults/{username_hash}.json
    return DB_PATH / f"{username_hash}.json"

def _save_user_vaults(username_hash: str, vaults: list):
    # écrit la liste des vaults sur disque (joli format)
    DB_PATH.mkdir(parents=True, exist_ok=True)
    path = _vault_file_path(username_hash)
    path.write_text(json.dumps(vaults, indent=2))

def get_user_vaults(username_hash: str) -> list:
    path = _vault_file_path(username_hash)
    if not path.exists():
        return []
    return json.loads(path.read_text())


def add_vault(username_hash: str, vault_id: str, key_enc: str, signature: str, name: dict, description: dict | None, created_at: dict | None, items: list):
    vaults = get_user_vaults(username_hash)

    if any(vault["vault_id"] == vault_id for vault in vaults):
        raise ValueError("ID already exists, creation has been aborted.")

    new_vault = {
        "vault_id": vault_id,
        "key_enc": key_enc,
        "signature": signature,
        "name": name,
        "description": description,
        "created_at": created_at,
        "items": items,
    }

    vaults.append(new_vault)
    _save_user_vaults(username_hash, vaults)
    return True

def delete_vault(username_hash: str, vault_id: str) -> bool:
    vaults = get_user_vaults(username_hash)

    # filtre tous les vaults sauf celui ciblé
    filtered = [v for v in vaults if v["vault_id"] != vault_id]

    if len(filtered) == len(vaults):
        # aucun vault supprimé, id inconnu
        return False

    _save_user_vaults(username_hash, filtered)
    return True