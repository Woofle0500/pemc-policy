import copy
import json
import os
import shutil

import pytest

from conftest import FIXTURES_DIR, NORMALIZER_DIR
from evaluate import main as evaluate_main
from normalize import normalize

POLICIES_DIR = NORMALIZER_DIR.parent / "policies"
STACK = "live/sandbox/ap-south-1/storage"
BUCKET = "module.storage.aws_s3_bucket.this"

# Outside CI a missing conftest skips the tests. In CI it fails them.
pytestmark = pytest.mark.skipif(
    shutil.which("conftest") is None and "CI" not in os.environ,
    reason="conftest is not installed",
)


def evaluate(plan, tmp_path):
    """Normalise a plan and run it through every policy, the way the pipeline does."""
    input_path = tmp_path / "input.json"
    findings_path = tmp_path / "findings.json"
    input_path.write_text(json.dumps(normalize(plan, STACK)))
    code = evaluate_main([str(input_path), "--policies", str(POLICIES_DIR),
                          "--findings", str(findings_path)])
    findings = json.loads(findings_path.read_text())
    assert code == (1 if findings else 0)
    return findings


def load_plan(name):
    return json.loads((FIXTURES_DIR / f"{name}.plan.json").read_text())


@pytest.mark.parametrize("name", ["existing_bucket", "new_bucket"])
def test_fixture_has_no_findings(name, tmp_path):
    assert evaluate(load_plan(name), tmp_path) == []


def test_missing_required_label_is_reported(tmp_path):
    plan = load_plan("existing_bucket")
    assert plan["resource_changes"][0]["address"] == BUCKET
    plan = copy.deepcopy(plan)
    del plan["resource_changes"][0]["change"]["after"]["tags_all"]["pemc:owner"]

    findings = evaluate(plan, tmp_path)

    assert [(f["policy_id"], f["address"]) for f in findings] == [
        ("common.tagging.required_labels", BUCKET)]
    assert "pemc:owner" in findings[0]["msg"]
