import json
from pathlib import Path
import pytest

import server.session_store as session_store

"""
TEST: server/session_store.py

Ce fichier teste la logique interne du stockage de sessions côté serveur :
- création, validation, expiration et compatibilité sans hash.
Il ne démarre pas le serveur Flask.
Il ne fait aucun appel réseau.

Ces tests sont unitaires, mais suivent un scénario logique pour vérifier
que la persistance JSON et le nettoyage automatique fonctionnent comme prévu.
"""

@pytest.fixture()
def temp_sessions_file(tmp_path, monkeypatch):
    """
    Prépare un environnement isolé pour chaque test :
        - Crée un fichier temporaire "sessions.json"
        - Redirige le chemin utilisé par le module session_store (PATH)
        vers ce fichier temporaire
    """
    # Modifie la var globale du fichier de stockage en un fichier temporaire
    sessions_file = tmp_path / "sessions.json"
    monkeypatch.setattr(session_store, "PATH", str(sessions_file))
    return sessions_file


def test_create_and_validate_session_with_username_hash(temp_sessions_file, monkeypatch):
    """
    Vérifie la création et la validation d'une session avec username_hash.
    """
    base_time = 1_000.0

    # On fige le temps pour rendre le test prévisible
    monkeypatch.setattr(session_store.time, "time", lambda: base_time)

    # Création d'une session (valide pendant 30 secondes)
    sid = session_store.create_session("user_hash", ttl_seconds=30)

    # Le fichier doit avoir été créé
    assert temp_sessions_file.exists(), "Le fichier de sessions devrait être créé"

    # Lecture du contenu pour vérifier qu'il contient bien notre session
    stored = json.loads(temp_sessions_file.read_text())
    assert sid in stored
    assert stored[sid]["username"] == "user_hash"

    # Vérifie que la session est considérée comme valide avec le bon hash
    assert session_store.is_valid(sid, "user_hash") is True
    assert session_store.get_session(sid, "user_hash")["username"] == "user_hash"

    # Vérifie qu'une mauvaise valeur de hash rend la session invalide
    assert session_store.is_valid(sid, "autre_hash") is False
    assert session_store.get_session(sid, "autre_hash") is None


def test_legacy_validation_without_hash(temp_sessions_file, monkeypatch):
    """
    Vérifie que la validation d'une session fonctionne encore
    même si on ne fournit pas de username_hash (compatibilité).
    """
    base_time = 5_000.0
    monkeypatch.setattr(session_store.time, "time", lambda: base_time)

    # Création d'une session sans fournir de hash
    sid = session_store.create_session("legacy_hash", ttl_seconds=30)

    # Vérifie que la session est bien valide sans hash
    assert session_store.is_valid(sid) is True
    session = session_store.get_session(sid, None)
    assert session["username"] == "legacy_hash"


def test_session_expiration(temp_sessions_file, monkeypatch):
    """
    Vérifie que la session expire bien après le délai prévu (TTL).
    """
    base_time = 10_000.0
    monkeypatch.setattr(session_store.time, "time", lambda: base_time)

    # Création d'une session valable 10 secondes
    sid = session_store.create_session("expiring_hash", ttl_seconds=10)

    # Juste après la création → session valide
    assert session_store.is_valid(sid, "expiring_hash") is True

    # On avance artificiellement le temps de +11 secondes
    monkeypatch.setattr(session_store.time, "time", lambda: base_time + 11)

    # La session doit maintenant être considérée comme expirée
    assert session_store.is_valid(sid, "expiring_hash") is False

    # Et get_session() doit renvoyer None car la session a été supprimée (nettoyage lazy)
    assert session_store.get_session(sid, "expiring_hash") is None