import json
from pathlib import Path
import pytest

from client.core.account_state import AccountState
from client.utils import logger as log


@pytest.fixture(autouse=True)
def isolate_account_state(tmp_path, monkeypatch):
    """
    Redirige le chemin de stockage vers un dossier temporaire.
    Cela empêche les tests de toucher au vrai account_state.json.
    """
    fake_path = tmp_path / "account_state.json"
    monkeypatch.setattr(AccountState, "PATH", fake_path)
    yield
    if fake_path.exists():
        fake_path.unlink()

"""
TEST : client/core/account_state.py

Ces tests vérifient la robustesse de la fonction AccountState._read().
On simule différents états du fichier local account_state.json :
- fichier absent
- fichier vide
- fichier JSON corrompu
- fichier valide
"""

def test_read_missing_file():
    """
    Si le fichier n'existe pas, _read() doit renvoyer None et ne pas planter.
    """
    result = AccountState._read()
    assert result is None


def test_read_empty_file():
    """
    Si le fichier existe mais est vide, _read() doit renvoyer None proprement.
    """
    AccountState.PATH.write_text("")
    result = AccountState._read()
    assert result is None


def test_read_corrupted_json():
    """
    Si le fichier contient un JSON invalide, _read() doit renvoyer None
    et ne pas lever d'exception.
    """
    AccountState.PATH.write_text("{ invalid json }")
    result = AccountState._read()
    assert result is None


def test_read_valid_json():
    """
    Si le fichier est valide, _read() doit renvoyer un dict avec les bonnes clés.
    """
    data = {
        "username": "alice",
        "session_id": "123",
        "public_key": "fakekey"
    }
    AccountState.PATH.write_text(json.dumps(data))
    result = AccountState._read()
    assert isinstance(result, dict)
    assert result["username"] == "alice"
    assert result["session_id"] == "123"
    assert result["public_key"] == "fakekey"
