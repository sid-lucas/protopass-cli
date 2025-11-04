import uuid
import os
import base64
from core import auth
from datetime import datetime, timezone
from utils.network import api_post, handle_resp
from utils.logger import log_client
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
            log_client("error", "Vault Create", "This field cannot be empty.")
            continue
        if len(value) > max_len:
            log_client("error", "Vault Create", f"Must be ≤ {max_len} characters.")
            continue
        return value

def _format_timestamp(value: str | None) -> str:
    if not value:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value  # laisse tel quel si parsing impossible
    return dt.strftime("%d %b %Y %H:%M")
    
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
        log_client("error", "Vault List", f"Failed to decrypt metadata: {err}")
        return None

def delete_vault(args):
    print("delete")

def select_vault(args):
    print("select")
    
def list_vaults(_args):
    resp = api_post("/vault/list", {"session_id": auth.AccountState.session_id()})
    data = handle_resp(
        resp,
        required_fields=["vaults"],
        context="Vault List"
    )
    if data is None: return
    vaults = data["vaults"]
    if len(vaults) == 0:
        log_client("info", "Vault List", "No vaults found.")
        return 
    
    private_key = auth.AccountState.private_key()
    if private_key is None:
        log_client("error", "Vault List", "No valid private key found in account state (memory).")
        return
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    
    print("--- Vaults:")
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
            log_client("error", "Vault List", f"Failed to decrypt vault '{vault_id[:8]}...': {e}")
            continue
        
        created_at_str = _format_timestamp(created_at)
        print(f"{vault_name} - {description or '(no description)'} (Created: {created_at_str})")
        #log_client("info", "Vault List", f"Name: '{vault_name}', Vault ID: {vault_id[:8]}...")

    print("END OF LIST")

def create_vault(_args):

    vault_name = _prompt_field("Vault name", 15)
    description = _prompt_field("Description", 40, allow_empty=True)
    created_at = datetime.now(timezone.utc).isoformat()

    # Génère un UUID unique pour le vault
    vault_id = str(uuid.uuid4())
    # Génère une clé symétrique de 256bits pour le vault
    vault_key = os.urandom(32)

    public_key = auth.AccountState.public_key()
    if public_key is None:
        log_client("error", "Vault Create", "No valid public key found in account state.")
        return
    private_key = auth.AccountState.private_key()
    if private_key is None:
        log_client("error", "Vault Create", "No valid private key found in account state (memory).")
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
        log_client("error", "Vault Create", "No valid session ID found in account state.")
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
    resp = api_post("/vault/create", payload)
    data = handle_resp(
        resp,
        required_fields=["vault_id"],
        context="Vault Create"
    )
    if data is None: return