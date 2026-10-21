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


def write_tables(directory, tagging_level="deny", exemptions=""):
    """Write a temporary enforcement table and exemptions file. Returns the evaluate.py options that point at them."""
    tables = Path(directory) / "tables"
    tables.mkdir(exist_ok=True)
    enforcement = tables / "enforcement.yaml"
    enforcement.write_text(
        "aws.ebs.encryption_required: {level: deny, exemptable: true, since: 2026-10-10}\n"
        f"common.tagging.required_labels: {{level: {tagging_level}, exemptable: true, since: 2026-10-10}}\n"
        "common.input.schema_valid: {level: deny, exemptable: false, since: 2026-10-18}\n")
    exemptions_file = tables / "exemptions.yaml"
    exemptions_file.write_text(exemptions)
    return ["--enforcement", str(enforcement), "--exemptions", str(exemptions_file)]
