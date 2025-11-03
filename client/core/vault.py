import uuid
import os
import base64
from client.core import auth
from utils.network import api_post, handle_resp
from utils.logger import log_client
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def delete_vault(args):
    print("delete")

def select_vault(args):
    print("select")
    
def list_vaults(args):
    print("list")

def create_vault(args):

    # Génère un UUID unique pour le vault
    id = str(uuid.uuid4())
    name = args.name

    # Génère une clé symétrique de 256bits pour le vault
    key = os.urandom(32)

    public_key = AccountState.public_key()
    if public_key is None:
        log_client("error", "Vault Create", "No valid public key found in account state.")
        return
    

    # chiffre la clé du vault avec la clé publique de l'utilisateur
    rsa_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(rsa_key)
    key_enc = cipher.encrypt(key)
    key_enc_b64 = base64.b64encode(key_enc).decode()

    payload = {
        "vault_id": id,
        "name": name,
        "key_enc": key_enc_b64
    }


    

    print("create")