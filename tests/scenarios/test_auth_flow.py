import pytest
import json
import importlib

from pathlib import Path
from client.core import auth
from client.core.account_state import AccountState
import server.session_store as session_store
import server.user_store as user_store
from server import app as flask_app
from tests.helpers import build_fake_api_post

"""
SCÉNARIOS : Authentification complète (Register → Login → Logout)

Ces tests valident :
- la création d'un utilisateur sur le serveur,
- la connexion SRP complète via le client,
- la persistance locale correcte (account_state.json),
- la révocation propre de la session.

Ils utilisent Flask en mode test et redirigent les fichiers client/serveur
vers des répertoires temporaires pour éviter les effets de bord.
"""

# ============================================================
#  Fixtures : environnement isolé
# ============================================================

@pytest.fixture()
def server_app(tmp_path, monkeypatch):
    """
    Lance le serveur Flask en mode test avec stockage isolé.
    """
    server_data = tmp_path / "server_data"
    server_data.mkdir()

    sessions_file = server_data / "sessions.json"
    users_file = server_data / "users.json"

    # Redirige les fichiers serveur sur un mock
    monkeypatch.setattr(session_store, "SESSIONS_PATH", str(sessions_file))
    monkeypatch.setattr(user_store, "USERS_PATH", users_file)


    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def client_state(tmp_path, monkeypatch):
    """
    Redirige les fichiers du client vers un dossier temporaire.
    """
    # idem : mock pour le stockage client
    fake_path = tmp_path / "account_state.json"
    monkeypatch.setattr(AccountState, "PATH", fake_path)
    yield
    if fake_path.exists():
        fake_path.unlink()


# ============================================================
#  Test principal : Register → Login → Logout
# ============================================================

def test_register_login_logout_cycle(monkeypatch, tmp_path, server_app):
    """
    Vérifie le cycle complet d'authentification : register → login → logout.
    """

    # ----------------------------------------
    # Étape 1 : Register
    # ----------------------------------------
    username = "alice"

    # Mock du mot de passe pour ne pas avoir à le taper
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "p@ssword123")

    # mock api_post pour rediriger les requêtes vers notre client Flask local
    fake_api_post = build_fake_api_post(server_app)

    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # Exécute la création de compte
    auth.register_account(type("Args", (), {"username": username})())

    users_file = tmp_path / "server_data" / "users.json"
    assert users_file.exists(), "users.json doit exister après register"
    data = json.loads(users_file.read_text())
    assert len(data) == 1, "Un utilisateur doit être enregistré"
    stored_user = next(iter(data.values()))
    assert "public_key" in stored_user["user_key"], "Les clés doivent être présentes"

    # ----------------------------------------
    # Étape 2 : Login
    # ----------------------------------------
    auth.login_account(type("Args", (), {"username": username})())

    # Vérifie que le fichier local a été créé
    assert AccountState.PATH.exists(), "account_state.json doit exister après login"
    acc_data = json.loads(AccountState.PATH.read_text())
    assert "session_id" in acc_data, "Le fichier local doit contenir la session"

    # Vérifie que la session est bien créée côté serveur
    sessions_file = tmp_path / "server_data" / "sessions.json"
    sessions = json.loads(sessions_file.read_text())
    assert len(sessions) == 1, "Une session doit exister côté serveur"

    # ----------------------------------------
    # Étape 3 : Logout
    # ----------------------------------------
    auth.logout_account(None)

    # Après logout : le fichier local doit être supprimé
    assert not AccountState.PATH.exists(), "Le fichier account_state.json doit être supprimé"

    # Et la session doit avoir disparu côté serveur
    sessions = json.loads(sessions_file.read_text())
    assert len(sessions) == 0, "Aucune session active ne doit rester sur le serveur"



def test_login_wrong_password(monkeypatch, tmp_path, server_app):
    """
    Vérifie qu'une tentative de login échoue si le mot de passe est incorrect.
    """

    username = "bob"

    # Mock pour éviter l'input manuel
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "goodpass")

    # Redirige api_post via le client Flask de test
    fake_api_post = build_fake_api_post(server_app)
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # --------------------------------------------
    # Étape 1 : Register avec le bon mot de passe
    # --------------------------------------------
    auth.register_account(type("Args", (), {"username": username})())

    users_file = tmp_path / "server_data" / "users.json"
    assert users_file.exists(), "users.json doit exister après register"

    # --------------------------------------------
    # Étape 2 : Login avec un mot de passe FAUX
    # --------------------------------------------
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "wrongpass")

    result = auth.login_account(type("Args", (), {"username": username})())

    # Vérifie que le client n’a rien écrit localement
    assert not AccountState.PATH.exists(), "Le fichier local ne doit pas être créé après un login raté"

    # Vérifie qu’aucune session n’a été créée sur le serveur
    sessions_file = tmp_path / "server_data" / "sessions.json"
    if sessions_file.exists():
        sessions = json.loads(sessions_file.read_text())
        assert len(sessions) == 0, "Aucune session ne doit être créée sur le serveur"



def test_protected_command_without_session(monkeypatch, tmp_path, server_app):
    """
    Vérifie qu'une commande protégée (vault.list_vaults) échoue sans session active.
    """

    # Import du module client "vault" sans session
    from client.core import vault

    # On prépare le fake api_post, mais on veut vérifier qu'il N'EST PAS appelé
    called = {"value": False}

    def fake_api_post(endpoint, payload=None, user=None):
        called["value"] = True
        pytest.fail("api_post ne devrait pas être appelé sans session")

    # Patch du fake pour intercepter d’éventuels appels réseau
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.vault.api_post", fake_api_post)

    # Patch print pour capturer la sortie utilisateur
    printed = []

    def fake_print(*args, **kwargs):
        printed.append(" ".join(map(str, args)))

    monkeypatch.setattr("builtins.print", fake_print)

    # ----------------------------------------
    # Étape : Appel de la commande sans session
    # ----------------------------------------
    vault.list_vaults(type("Args", (), {})())

    # Vérifications
    assert not called["value"], "Aucun appel réseau ne doit être effectué"
    assert any("login" in msg.lower() for msg in printed), (
        "Un message d'erreur indiquant que l'utilisateur doit être connecté doit apparaître"
    )
