import sys
from pathlib import Path

# Met la racine du projet dans sys.path pour que "import server.*" fonctionne en test.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from client.utils.agent_client import AgentClient


@pytest.fixture(autouse=True)
def ensure_agent_shutdown():
    """
    Make sure no agent process/socket persists between tests.
    """
    try:
        AgentClient(autostart=False).shutdown()
    except Exception:
        pass
    yield
    try:
        AgentClient(autostart=False).shutdown()
    except Exception:
        pass
