import pytest, json, time
from client.core import auth
from client.core.account_state import AccountState
import server.session_store as session_store
import server.user_store as user_store
from server import app as flask_app
from tests.helpers import build_fake_api_post
from client.utils.crypto import canonical_json
from client.utils.agent_client import AgentClient

"""
SCENARIOS : Authentification côté client/serveur

Ce fichier couvre :
- le cycle utilisateur nominal (register → login → logout)
- les échecs d'authentification (mot de passe incorrect)
- l'accès refusé aux commandes protégees sans session
- la détection et le nettoyage d'une session expirée
- l'idempotence d'un logout répété
- le nettoyage automatique d'un account_state.json corrompu
- l'invalidation d'un session_id local falsifié

Chaque test utilise Flask en mode test et redirige les fichiers client/serveur vers des
répertoires temporaires afin d'éviter les effets de bord sur les données réelles.
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
#  Tests principaux
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
    assert "session" in acc_data, "Le fichier local doit contenir la session chiffrée"
    assert all(key in acc_data["session"] for key in ("enc", "nonce", "tag")), "La session doit être stockée sous forme chiffrée"

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


def test_session_expiration_auto_clear(monkeypatch, tmp_path, server_app):
    """
    Vérifie qu'une session expirée est détectée et nettoyée automatiquement côté client.
    """
    username = "carol"

    # Mock password input
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "strongpass")

    # Redirige api_post via le client Flask test client
    fake_api_post = build_fake_api_post(server_app)
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # Fige le temps au moment de la création de session
    base_time = 10_000.0
    monkeypatch.setattr(time, "time", lambda: base_time)

    # ---------------------------------------------------
    # Etape 1 : Register + Login
    # ---------------------------------------------------
    auth.register_account(type("Args", (), {"username": username})())
    auth.login_account(type("Args", (), {"username": username})())

    # Vérifie que la session est bien créée
    sessions_file = tmp_path / "server_data" / "sessions.json"
    data = json.loads(sessions_file.read_text())
    assert len(data) == 1, "Une session doit être active juste après login"

    # ---------------------------------------------------
    # Etape 2 : Simule le passage du temps (TTL dépassé)
    # ---------------------------------------------------
    monkeypatch.setattr(time, "time", lambda: base_time + 99999)

    # Capture les messages utilisateur
    printed = []

    def fake_print(*args, **kwargs):
        printed.append(" ".join(map(str, args)))

    monkeypatch.setattr("builtins.print", fake_print)

    # Vérifie la validité côté client
    from client.core.account_state import AccountState
    result = AccountState.valid()

    # Après expiration → doit être False et session nettoyée
    assert result is False, "AccountState.valid() doit renvoyer False après expiration"
    assert not AccountState.PATH.exists(), "Le fichier local doit être supprimé après expiration"
    assert any("log in" in msg.lower() or "expired" in msg.lower() for msg in printed), (
        "Un message d'expiration doit être affiché à l'utilisateur"
    )

    # Le serveur doit avoir supprimé la session (lazy cleanup)
    data = json.loads(sessions_file.read_text())
    assert len(data) == 0, "La session expirée doit être supprimée côté serveur"


def test_double_logout_idempotent(monkeypatch, tmp_path, server_app):
    """
    Vérifie que deux appels successifs à logout ne provoquent pas d'erreur et que le second est ignoré proprement.
    """
    username = "dave"

    # Mock du mot de passe
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "okpass")

    # Redirige api_post vers le client Flask de test
    fake_api_post = build_fake_api_post(server_app)
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # ----------------------------------------
    # Étape 1 : Register + Login
    # ----------------------------------------
    auth.register_account(type("Args", (), {"username": username})())
    auth.login_account(type("Args", (), {"username": username})())

    # Vérifie qu'une session est bien active
    sessions_file = tmp_path / "server_data" / "sessions.json"
    data = json.loads(sessions_file.read_text())
    assert len(data) == 1, "Une session doit exister après login"

    # ----------------------------------------
    # Étape 2 : Premier logout
    # ----------------------------------------
    printed = []

    def fake_print(*args, **kwargs):
        printed.append(" ".join(map(str, args)))

    monkeypatch.setattr("builtins.print", fake_print)
    auth.logout_account(None)

    # Fichier local supprimé et session serveur effacée
    assert not AccountState.PATH.exists(), "Le fichier account_state.json doit être supprimé après logout"
    data = json.loads(sessions_file.read_text())
    assert len(data) == 0, "La session doit avoir disparu côté serveur"

    # ----------------------------------------
    # Étape 3 : Second logout (idempotent)
    # ----------------------------------------
    auth.logout_account(None)

    # Aucun crash, message explicite que l'user est déjà déconnecté
    assert any("logged out" in msg.lower() for msg in printed), (
        "Le second logout doit simplement informer que l'utilisateur est déjà déconnecté"
    )


def test_session_corrupted_local_state(monkeypatch, tmp_path, server_app):
    """
    Vérifie que si account_state.json est corrompu ou incohérent, le client le supprime et affiche un message d'erreur propre.
    """
    username = "eve"

    # Patch des dépendances habituelles
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "goodpass")
    fake_api_post = build_fake_api_post(server_app)
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # ----------------------------------------
    # Étape 1 : Register + Login normal
    # ----------------------------------------
    auth.register_account(type("Args", (), {"username": username})())
    auth.login_account(type("Args", (), {"username": username})())

    # Vérifie que le fichier existe
    assert AccountState.PATH.exists(), "account_state.json doit exister après login"

    # ----------------------------------------
    # Étape 2 : Corrupt le fichier local
    # ----------------------------------------
    AccountState.PATH.write_text("{ invalid json")  # JSON cassé
    # Simule un redémarrage : on vide les caches en mémoire
    AccountState._cached_username = None
    AccountState._cached_session_id = None
    AccountState._cached_public_key = None

    # Capture les sorties console
    printed = []

    def fake_print(*args, **kwargs):
        printed.append(" ".join(map(str, args)))

    monkeypatch.setattr("builtins.print", fake_print)

    # ----------------------------------------
    # Étape 3 : Appel d’une fonction client qui lit l’état
    # ----------------------------------------
    result = AccountState.username()

    # Vérifications
    assert result is None, "La lecture du username doit renvoyer None en cas de JSON corrompu"
    assert not AccountState.PATH.exists(), "Le fichier corrompu doit être supprimé automatiquement"
    assert any("invalid" in msg.lower() or "corrupt" in msg.lower() or "login" in msg.lower() for msg in printed), (
        "Un message indiquant la corruption ou demandant une reconnexion doit être affiché"
    )


def test_session_invalid_local_id(monkeypatch, tmp_path, server_app):
    """
    Vérifie qu'un account_state.json avec un session_id invalide est détecté et nettoyé proprement sans crash.
    """
    username = "frank"

    # Mock mot de passe
    monkeypatch.setattr("getpass.getpass", lambda prompt=None: "strongpass")

    # Redirige toutes les requêtes via le client Flask de test
    fake_api_post = build_fake_api_post(server_app)
    monkeypatch.setattr("client.utils.network.api_post", fake_api_post)
    monkeypatch.setattr("client.core.auth.api_post", fake_api_post)
    monkeypatch.setattr("client.core.account_state.api_post", fake_api_post)

    # ----------------------------------------
    # Étape 1 : Register + Login
    # ----------------------------------------
    auth.register_account(type("Args", (), {"username": username})())
    auth.login_account(type("Args", (), {"username": username})())

    # Vérifie que le fichier local existe
    assert AccountState.PATH.exists(), "account_state.json doit exister après login"

    # ----------------------------------------
    # Étape 2 : Corrompt le session_id local
    # ----------------------------------------
    data = json.loads(AccountState.PATH.read_text())
    data["session"] = AccountState.encrypt_secret(b"FAKE_INVALID_SESSION")

    # Recalcule l'intégrité pour qu'elle reste cohérente avec les nouvelles données,
    # tout en conservant un session_id invalide côté serveur.

    mac_payload = {
        "username": data["username"],
        "public_key": data["public_key"],
        "salt": data["salt"],
        "private_key": data["private_key"],
        "session": data["session"],
    }
    agent = AgentClient()
    mac_resp = agent.hmac(canonical_json(mac_payload).encode())
    data["integrity"] = {"value": mac_resp["hmac"], "algo": "HMAC-SHA256"}

    AccountState.PATH.write_text(json.dumps(data))
    # Simule un redémarrage : on vide les caches en mémoire
    AccountState._cached_username = None
    AccountState._cached_session_id = None
    AccountState._cached_public_key = None

    # Capture les sorties utilisateur
    printed = []

    def fake_print(*args, **kwargs):
        printed.append(" ".join(map(str, args)))

    monkeypatch.setattr("builtins.print", fake_print)

    # ----------------------------------------
    # Étape 3 : Vérifie la validité
    # ----------------------------------------
    result = AccountState.valid()

    # Vérifications
    assert result is False, "La session invalide doit être considérée comme expirée"
    assert not AccountState.PATH.exists(), "Le fichier local doit être supprimé après détection d'invalidité"
    assert any("invalid" in msg.lower() or "expired" in msg.lower() for msg in printed), (
        "Un message d'expiration ou d'invalidité doit être affiché"
    )
