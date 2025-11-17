import uuid, json, os, base64
from datetime import datetime, timezone
from .items.schemas import Type
from .items.prompt import prompt_fields_for_type
from .account_state import AccountState
from ..utils import logger as log
from ..utils.logger import CTX, notify_user
from ..utils.network import api_post, handle_resp
from ..utils.crypto import encrypt_gcm

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
