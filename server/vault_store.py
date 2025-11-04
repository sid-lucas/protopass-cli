import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "server_data" / "vaults"

def _vault_file_path(username_hash: str) -> Path:
    # retourne le chemin du fichier vaults/{username_hash}.json
    return DB_PATH / f"{username_hash}.json"

def _load_user_vaults(username_hash: str) -> list:
    path = _vault_file_path(username_hash)
    if not path.exists():
        return []
    return json.loads(path.read_text())

def _save_user_vaults(username_hash: str, vaults: list):
    # écrit la liste des vaults sur disque (joli format)
    DB_PATH.mkdir(parents=True, exist_ok=True)
    path = _vault_file_path(username_hash)
    path.write_text(json.dumps(vaults, indent=2))

def add_vault(username_hash: str, vault_id: str, key_enc: str, signature: str, name: dict, items: list):
    vaults = _load_user_vaults(username_hash)

    if any(vault["vault_id"] == vault_id for vault in vaults):
        raise ValueError("ID already exists, creation has been aborted.")

    new_vault = {
        "vault_id": vault_id,
        "key_enc": key_enc,
        "signature": signature,
        "name": name,
        "items": items
    }

    vaults.append(new_vault)
    _save_user_vaults(username_hash, vaults)
    return True