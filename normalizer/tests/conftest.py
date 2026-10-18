import json
import sys
from pathlib import Path

import pytest

NORMALIZER_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(NORMALIZER_DIR))


@pytest.fixture
def load_fixture():
    def load(name):
        return json.loads((FIXTURES_DIR / name).read_text())
    return load
