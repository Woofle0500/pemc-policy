import json

import pytest

from conftest import FIXTURES_DIR
from normalize import normalize

STACK = "live/sandbox/ap-south-1/storage"


@pytest.mark.parametrize("name", ["existing_bucket", "new_bucket"])
def test_golden(name):
    plan = json.loads((FIXTURES_DIR / f"{name}.plan.json").read_text())
    expected = json.loads((FIXTURES_DIR / f"{name}.expected.json").read_text())
    assert normalize(plan, STACK) == expected
