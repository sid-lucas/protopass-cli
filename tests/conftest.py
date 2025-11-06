import sys
from pathlib import Path

# Met la racine du projet dans sys.path pour que "import server.*" fonctionne en test.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
