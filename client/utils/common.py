from client.utils.logger import notify_user

def get_id_by_index(index: int, rows: list, id_key: str, logger=None):
    """
    rows : liste de dicts contenant au minimum {"idx": "...", id_key: "..."}
    id_key : nom de la clé à retourner (ex: 'uuid' ou 'id')
    """
    if not rows:
        return None

    for row in rows:
        if row.get("idx") == str(index):
            return row.get(id_key)

    notify_user(f"No entry found for index {index}.")
    if logger:
        logger.error(f"No entry associated with index {index}")
    return None