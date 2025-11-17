from .network import api_post, handle_resp
from .logger import notify_user

def get_id_by_index(index: int, rows: list, logger=None):
    """
    rows : liste de dicts contenant au minimum {"idx": "...", id_key: "..."}
    id_key : nom de la clé à retourner (ex: 'uuid' ou 'id')
    """
    if not rows:
        return None

    for row in rows:
        if row.get("idx") == str(index):
            return row.get("uuid")

    notify_user(f"No entry found for index {index}.")
    if logger:
        logger.error(f"No entry associated with index {index}")
    return None

def fetch_vaults(session_payload, user, context):
    resp = api_post("/vault/list", session_payload, user=user)
    data = handle_resp(resp, required_fields=["vaults"], context=context, user=user)

    if data is None:
        return None

    vaults = data.get("vaults", [])
    if not vaults:
        return []

    return vaults

def find_vault_by_id(vaults, vault_id):
    for v in vaults:
        if v.get("vault_id") == vault_id:
            return v
    return None
