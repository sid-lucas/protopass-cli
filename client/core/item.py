import uuid, json, os, base64
from ..core import auth
from ..utils import logger as log
from datetime import datetime, timezone
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.crypto import encrypt_gcm
from ..utils.display import prompt_field

def create_item(_args):
    logger = log.get_logger(CTX.ITEM_CREATE, auth.AccountState.username())

    # Vérifier qu’un vault est sélectionné
    vault_id = auth.AccountState.current_vault()
    if not vault_id:
        notify_user("No vault selected. Use: vault select <index>")
        return

    # Récupérer la clé du vault
    vault_key = auth.AccountState.vault_key(vault_id)
    if vault_key is None:
        notify_user("Vault key not found. Try to select a vault again.")
        return

    item_title = prompt_field("Item name", 15)

    # Construction de l'item (temporaire, modif plus tard)
    plaintext = {
        "type": "login",
        "title": item_title,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    plaintext_json = json.dumps(plaintext).encode()

    # Construire item_id + item_key random
    item_id = str(uuid.uuid4())
    item_key = os.urandom(32)

    # Chiffrement du contenu avec item_key
    enc, nonce, tag = encrypt_gcm(item_key, plaintext_json)
    # Chiffrement de item_key avec vault_key
    key_enc, key_nonce, key_tag = encrypt_gcm(vault_key, item_key)


    # Construction du payload pour envoi au serveur
    payload = {
        **auth.AccountState.session_payload(),
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
