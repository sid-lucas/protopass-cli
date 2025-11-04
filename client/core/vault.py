import uuid
import os
import base64
from core import auth
from utils.network import api_post, handle_resp
from utils.logger import log_client
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes


def delete_vault(args):
    print("delete")

def select_vault(args):
    print("select")
    
def list_vaults(args):
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
    
    for vault in vaults:
        vault_id = vault.get("vault_id", "unknown")
        try:
            # Déchiffrement de la vault_key
            vault_key_enc = base64.b64decode(vault["key_enc"])
            private_key = auth.AccountState.private_key()
            if private_key is None:
                log_client("error", "Vault List", "No valid private key found in account state (memory).")
                return
            vault_key = PKCS1_OAEP.new(RSA.import_key(private_key)).decrypt(vault_key_enc)

            # Déchiffrement du nom du vault
            name_enc = base64.b64decode(vault["name"]["name_enc"])
            name_nonce = base64.b64decode(vault["name"]["name_nonce"])
            name_tag = base64.b64decode(vault["name"]["name_tag"])
            cipher_aes = AES.new(vault_key, AES.MODE_GCM, nonce=name_nonce)
            vault_name = cipher_aes.decrypt_and_verify(name_enc, name_tag).decode()
        except Exception as e:
            log_client("error", "Vault List", f"Failed to decrypt vault '{vault_id[:8]}...': {e}")
            continue

        log_client("info", "Vault List", f"Name: '{vault_name}', Vault ID: {vault_id[:8]}...")

    print("END OF LIST")

def create_vault(args):

    # Génère un UUID unique pour le vault
    vault_id = str(uuid.uuid4())
    vault_name = args.name

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

    # chiffrement du nom du vault avec la vault_key
    name_nonce = get_random_bytes(12)
    cipher_aes = AES.new(vault_key, AES.MODE_GCM, nonce=name_nonce)
    name_enc, name_tag = cipher_aes.encrypt_and_digest(vault_name.encode())

    # Pas d'items créés pour l'instant

    # Envoie les informations du nouveau vault au serveur
    payload = {
        "session_id": auth.AccountState.session_id(),
        "vault_id": vault_id,
        "key_enc": base64.b64encode(vault_key_enc).decode(),
        "signature": base64.b64encode(vault_signature).decode(),
        "name": {
            "name_enc": base64.b64encode(name_enc).decode(),
            "name_nonce": base64.b64encode(name_nonce).decode(),
            "name_tag": base64.b64encode(name_tag).decode()
        },
        "items": []
    }
    resp = api_post("/vault/create", payload)
    data = handle_resp(
        resp,
        required_fields=["vault_id"],
        context="Vault Create"
    )
    if data is None: return

    log_client("info", "Vault Create", f"Vault '{vault_id[:8]}' created successfully.")