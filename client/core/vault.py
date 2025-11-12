import base64
import uuid
import os
from client.core import auth
from client.utils.display import render_table, format_timestamp
from client.utils.network import api_post, handle_resp
from client.utils import logger as log
from client.utils.logger import CTX, notify_user
from datetime import datetime, timezone
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

def _prompt_field(label, max_len, allow_empty=False):
    logger = log.get_logger(CTX.VAULT_CREATE, auth.AccountState.username())
    while True:
        value = input(f"{label} (max {max_len} chars): ").strip()
        if not value and allow_empty:
            return None
        if not value:
            logger.warning(f"Empty value provided for '{label}'")
            notify_user("This field cannot be empty.")
            continue
        if len(value) > max_len:
            logger.warning(f"Value for '{label}' exceeds {max_len} characters")
            notify_user(f"Value must be ≤ {max_len} characters.")
            continue
        return value

def _fetch_vault_rows():
    current_user = auth.AccountState.username()
    logger = log.get_logger(CTX.VAULT_LIST, current_user)
    session_payload = auth.AccountState.session_payload()
    if session_payload is None:
        logger.error("No active session found in account state.")
        notify_user("No active session. Please log in.")
        return None
    resp = api_post("/vault/list", session_payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vaults"],
        context=CTX.VAULT_LIST,
        user=current_user
    )
    if data is None:
        notify_user("Unable to retrieve vault list. See logs for details.")
        return None
    vaults = data["vaults"]
    if len(vaults) == 0:
        notify_user("No vaults found.")
        return None
    
    private_key = auth.AccountState.private_key()
    if private_key is None:
        logger.error("No valid private key in account state (memory).")
        notify_user("Unable to decrypt vaults with current keys.")
        return None
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    
    rows = []
    for vault in vaults:
        vault_id = vault.get("vault_id", "unknown")
        try:
            # Déchiffrement de la vault_key
            vault_key_enc = base64.b64decode(vault["key_enc"])
            vault_key = rsa_cipher.decrypt(vault_key_enc)

            # Déchiffrement du nom du vault
            vault_name = decrypt_metadata(vault["name"], vault_key)
            description = decrypt_metadata(vault.get("description"), vault_key)
            created_at = decrypt_metadata(vault.get("created_at"), vault_key)

        except Exception as e:
            logger.warning(f"Failed to decrypt vault '{vault_id[:8]}' ({e})")
            continue

        rows.append({
            "idx": str(len(rows) + 1),
            "name": vault_name or "-",
            "desc": description or "-",
            "created": format_timestamp(created_at),
            "uuid": vault["vault_id"]
        })

    return rows


    
def encrypt_metadata(key: bytes, value: str | None) -> dict | None:
    if not value:
        return None
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc, tag = cipher.encrypt_and_digest(value.encode())
    return {
        f"enc": base64.b64encode(enc).decode(),
        f"nonce": base64.b64encode(nonce).decode(),
        f"tag": base64.b64encode(tag).decode(),
    }

def decrypt_metadata(blob: dict | None, key: bytes) -> str | None:
    if not blob:
        return None
    try:
        enc = base64.b64decode(blob["enc"])
        nonce = base64.b64decode(blob["nonce"])
        tag = base64.b64decode(blob["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(enc, tag).decode()
    except Exception as err:
        log.error(CTX.VAULT_LIST, f"Failed to decrypt metadata: {err}", auth.AccountState.username())
        return None



def delete_vault(args):
    rows = _fetch_vault_rows()
    if not rows:
        return
    
    vault_id_to_del = None
    logger = log.get_logger(CTX.VAULT_DELETE, auth.AccountState.username())
    
    for row in rows:
        if row.get("idx") == str(args.index):
            vault_id_to_del = row.get("uuid")
            break

    if vault_id_to_del is None:
        notify_user(f"No vault found for index '{args.index}'")
        logger.error(f"No vault associated with index '{args.index}', deletion aborted")
        return

    notify_user(f"found vault id to del : {vault_id_to_del}")

    notify_user(f"Vault deleted successfully.")

def select_vault(args):
    print("select")
    
def list_vaults(_args):
    if not auth.AccountState.valid():
        print("Please login to list vaults.")
        return

    rows = _fetch_vault_rows()
    if not rows:
        return

    #log_client("info", "Vault List", f"Name: '{vault_name}', Vault ID: {vault_id[:8]}...")

    columns = [
        ("idx", "#", 3),
        ("name", "Name", 15),
        ("desc", "Description", 40),
        ("created", "Created", 17),
    ]
    print(render_table(rows, columns))

def create_vault(_args):
    current_user = auth.AccountState.username()
    public_key = auth.AccountState.public_key()
    private_key = auth.AccountState.private_key()
    if current_user is None or public_key is None or private_key is None:
        notify_user(
            "Vault creation aborted: local account state is invalid.\n"
            "Run 'logout' then 'login' to regenerate your keys."
        )
        return
    
    logger = log.get_logger(CTX.VAULT_CREATE, current_user)

    vault_name = _prompt_field("Vault name", 15)
    description = _prompt_field("Description", 40, allow_empty=True)
    created_at = datetime.now(timezone.utc).isoformat()

    # Génère un UUID unique pour le vault
    vault_id = str(uuid.uuid4())
    # Génère une clé symétrique de 256bits pour le vault
    vault_key = os.urandom(32)

    # signature de la clé du vault avec la clé privée de l'utilisateur
    vault_key_hash = SHA256.new(vault_key).digest()
    vault_signature = pkcs1_15.new(RSA.import_key(private_key)).sign(SHA256.new(vault_key_hash))

    # chiffre la clé du vault avec la clé publique de l'utilisateur
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    vault_key_enc = cipher.encrypt(vault_key)

    # chiffrement des metadonnées du vault avec la vault_key
    name_blob = encrypt_metadata(vault_key, vault_name)
    desc_blob = encrypt_metadata(vault_key, description)
    time_blob = encrypt_metadata(vault_key, created_at)

    # Pas d'items créés pour l'instant

    session_payload = auth.AccountState.session_payload()
    if session_payload is None:
        logger.error("No valid session found in account state.")
        notify_user("No active session. Please log in.")
        return
    # Envoie les informations du nouveau vault au serveur
    payload = {
        **session_payload,
        "vault_id": vault_id,
        "key_enc": base64.b64encode(vault_key_enc).decode(),
        "signature": base64.b64encode(vault_signature).decode(),
        "name": name_blob,
        "description": desc_blob,
        "created_at": time_blob,
        "items": []
    }
    resp = api_post("/vault/create", payload, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vault_id"],
        context=CTX.VAULT_CREATE,
        user=current_user
    )
    if data is None:
        notify_user("Vault creation failed. See logs for details.")
        return

    logger.info("Vault '%s' created (id=%s)", vault_name, vault_id[:8])
    notify_user(f"Vault '{vault_name}' created successfully.")
