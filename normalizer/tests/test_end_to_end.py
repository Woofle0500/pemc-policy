import copy
import json
import shutil
import subprocess

import pytest

from conftest import FIXTURES_DIR, NORMALIZER_DIR
from normalize import normalize

POLICIES_DIR = NORMALIZER_DIR.parent / "policies"
STACK = "live/sandbox/ap-south-1/storage"
BUCKET = "module.storage.aws_s3_bucket.this"

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not installed")


def collect_deny(node, findings=None):
    """Collect every finding under any key named deny, so no policy list is needed."""
    if findings is None:
        findings = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "deny":
                findings.extend(value)
            else:
                collect_deny(value, findings)
    elif isinstance(node, list):
        for item in node:
            collect_deny(item, findings)
    return findings


def evaluate(plan, tmp_path):
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(normalize(plan, STACK)))
    result = subprocess.run(
        ["opa", "eval", "-d", str(POLICIES_DIR), "--ignore", "*_test.rego",
         "-i", str(input_path), "--format", "json", "data"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return collect_deny(json.loads(result.stdout))


def load_plan(name):
    return json.loads((FIXTURES_DIR / f"{name}.plan.json").read_text())


@pytest.mark.parametrize("name", ["existing_bucket", "new_bucket"])
def test_fixture_has_no_findings(name, tmp_path):
    assert evaluate(load_plan(name), tmp_path) == []


def test_missing_required_label_is_reported(tmp_path):
    plan = load_plan("existing_bucket")
    bucket = plan["resource_changes"][0]
    assert bucket["address"] == BUCKET
    plan = copy.deepcopy(plan)
    del plan["resource_changes"][0]["change"]["after"]["tags_all"]["pemc:owner"]

    findings = evaluate(plan, tmp_path)

    assert [(f["policy_id"], f["address"]) for f in findings] == [
        ("common.tagging.required_labels", BUCKET)]
    assert "pemc:owner" in findings[0]["message"]
