import base64
import uuid
import os
from core import auth
from datetime import datetime, timezone
from utils.display import render_table, format_timestamp
from utils.network import api_post, handle_resp
from utils.logger import log_client, notify_user
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

def _prompt_field(label, max_len, allow_empty=False):
    while True:
        value = input(f"{label} (max {max_len} chars): ").strip()
        if not value and allow_empty:
            return None
        if not value:
            log_client("error", "Vault Create", "Tried an empty field.", user=auth.AccountState.username())
            notify_user("This field cannot be empty.")
            continue
        if len(value) > max_len:
            log_client("error", "Vault Create", f"Field must be ≤ {max_len} characters.", user=auth.AccountState.username())
            notify_user(f"Value must be ≤ {max_len} characters.")
            continue
        return value


    
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
        log_client("error", "Vault List", f"Failed to decrypt metadata: {err}", user=auth.AccountState.username())
        return None

def delete_vault(args):
    print("delete")

def select_vault(args):
    print("select")
    
def list_vaults(_args):
    current_user = auth.AccountState.username()
    resp = api_post("/vault/list", {"session_id": auth.AccountState.session_id()}, user=current_user)
    data = handle_resp(
        resp,
        required_fields=["vaults"],
        context="Vault List",
        user=current_user
    )
    if data is None:
        notify_user("Unable to retrieve vault list. See logs for details.")
        return
    vaults = data["vaults"]
    if len(vaults) == 0:
        log_client("info", "Vault List", "No vaults found.", user=current_user)
        notify_user("No vaults found.")
        return 
    
    private_key = auth.AccountState.private_key()
    if private_key is None:
        log_client("error", "Vault List", "No valid private key found in account state (memory).", user=current_user)
        notify_user("Unable to decrypt vaults with current keys.")
        return
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
            log_client("error", "Vault List", f"Failed to decrypt vault '{vault_id[:8]}...': {e}", user=current_user)
            continue

        rows.append({
            "idx": str(len(rows) + 1),
            "name": vault_name or "-",
            "desc": description or "(no description)",
            "created": format_timestamp(created_at),
        })

        #log_client("info", "Vault List", f"Name: '{vault_name}', Vault ID: {vault_id[:8]}...")

    columns = [
        ("idx", "#", 2),
        ("name", "Name", 15),
        ("desc", "Description", 40),
        ("created", "Created", 17),
    ]
    print(render_table(rows, columns))

def create_vault(_args):
    current_user = auth.AccountState.username()

    vault_name = _prompt_field("Vault name", 15)
    description = _prompt_field("Description", 40, allow_empty=True)
    created_at = datetime.now(timezone.utc).isoformat()

    # Génère un UUID unique pour le vault
    vault_id = str(uuid.uuid4())
    # Génère une clé symétrique de 256bits pour le vault
    vault_key = os.urandom(32)

    public_key = auth.AccountState.public_key()
    if public_key is None:
        log_client("error", "Vault Create", "No valid public key found in account state.", user=current_user)
        notify_user("No valid public key found. Please log in again.")
        return
    private_key = auth.AccountState.private_key()
    if private_key is None:
        log_client("error", "Vault Create", "No valid private key found in account state (memory).", user=current_user)
        notify_user("No valid private key in memory. Please unlock your account.")
        return

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

    session_id = auth.AccountState.session_id()
    if session_id is None:
        log_client("error", "Vault Create", "No valid session ID found in account state.", user=current_user)
        notify_user("No active session. Please log in.")
        return
    # Envoie les informations du nouveau vault au serveur
    payload = {
        "session_id": session_id,
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
        context="Vault Create",
        user=current_user
    )
    if data is None:
        notify_user("Vault creation failed. See logs for details.")
        return

    notify_user(f"Vault '{vault_name}' created successfully.")
