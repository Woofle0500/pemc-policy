import json
import os
import shutil
import subprocess

import pytest

from conftest import FIXTURES_DIR, NORMALIZER_DIR, write_tables
from evaluate import EvaluateError, flatten, main, ran_packages, render_markdown, run_conftest
from normalize import normalize

POLICIES_DIR = NORMALIZER_DIR.parent / "policies"
BUCKET = "module.storage.aws_s3_bucket.this"

# Outside CI a missing conftest skips these tests. In CI it fails them.
needs_conftest = pytest.mark.skipif(
    shutil.which("conftest") is None and "CI" not in os.environ,
    reason="conftest is not installed",
)


def finding(policy_id="p.a", address="aws_x.a", msg="bad"):
    return {"msg": msg, "metadata": {"policy_id": policy_id, "address": address, "query": "q"}}


def result(namespace="p.a", successes=0, failures=()):
    return {"filename": "input.json", "namespace": namespace,
            "successes": successes, "failures": list(failures)}


# pure functions

def test_ran_packages_has_packages_with_a_pass_or_a_finding():
    results = [
        result("a", successes=2),
        result("b", failures=[finding()]),
        result("c"),
        result("d_test"),
        {"namespace": "e"},
    ]
    assert ran_packages(results) == {"a", "b"}


def test_flatten_sorts_by_policy_then_address():
    results = [
        result("b", failures=[finding("b", "z"), finding("b", "a")]),
        result("a", failures=[finding("a", "m")]),
    ]
    assert [(f["policy_id"], f["address"]) for f in flatten(results)] == [
        ("a", "m"), ("b", "a"), ("b", "z")]


def test_flatten_drops_conftest_query_field():
    assert flatten([result(failures=[finding()])]) == [
        {"policy_id": "p.a", "address": "aws_x.a", "msg": "bad"}]


@pytest.mark.parametrize("bad", [
    {"metadata": {"policy_id": "p", "address": "a"}},
    {"msg": "m", "metadata": {"address": "a"}},
    {"msg": "m", "metadata": {"policy_id": "p"}},
    {"msg": "m"},
    {"msg": "", "metadata": {"policy_id": "p", "address": "a"}},
    {"msg": "m", "metadata": {"policy_id": "p", "address": 3}},
])
def test_flatten_rejects_incomplete_finding(bad):
    with pytest.raises(EvaluateError, match="missing msg, address or policy_id"):
        flatten([result(failures=[bad])])


def test_render_markdown_clean():
    assert render_markdown([]) == "No policy findings.\n"


def test_render_markdown_table():
    findings = [{"policy_id": "p.a", "address": "aws_x.a", "msg": "bad", "status": "blocking"}]
    assert render_markdown(findings) == (
        "## Blocking\n\n"
        "| Policy | Address | Message |\n"
        "|---|---|---|\n"
        "| p.a | `aws_x.a` | bad |\n")


def test_render_markdown_escapes_pipes_and_newlines():
    findings = [{"policy_id": "p", "address": "a", "msg": "one | two\nthree", "status": "blocking"}]
    assert "| one \\| two three |" in render_markdown(findings)


def fake_conftest(monkeypatch, returncode, stdout="", stderr=""):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, returncode, stdout, stderr))


def test_run_conftest_parses_results(monkeypatch):
    fake_conftest(monkeypatch, 1, json.dumps([result(failures=[finding()])]))
    assert run_conftest("in.json", "policies")[0]["namespace"] == "p.a"


@pytest.mark.parametrize("returncode, stdout, stderr", [
    (1, "", "Error: running test: boom\nmore"),
    (0, "", ""),
    (2, "[]", ""),
    (1, "{}", ""),
    (0, "not json", ""),
])
def test_run_conftest_errors(monkeypatch, returncode, stdout, stderr):
    fake_conftest(monkeypatch, returncode, stdout, stderr)
    with pytest.raises(EvaluateError):
        run_conftest("in.json", "policies")


def test_run_conftest_error_names_first_line_of_stderr(monkeypatch):
    fake_conftest(monkeypatch, 1, "", "Error: running test: boom\nmore")
    with pytest.raises(EvaluateError, match="Error: running test: boom$"):
        run_conftest("in.json", "policies")


def test_main_without_conftest_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PATH", "")
    markdown = tmp_path / "findings.md"
    assert main(["in.json", "--policies", "policies", "--markdown", str(markdown), *write_tables(tmp_path)]) == 2
    assert "cannot run conftest" in capsys.readouterr().err
    assert markdown.read_text().startswith("Policy evaluation failed: cannot run conftest")


# with conftest

@pytest.fixture
def run(tmp_path):
    """Normalise a plan and run evaluate.py on it. Returns (exit code, findings, markdown)."""
    def go(plan=None, policies=POLICIES_DIR, input_text=None):
        input_path = tmp_path / "input.json"
        input_path.write_text(input_text if input_text is not None
                              else json.dumps(normalize(plan, "s")))
        findings, markdown = tmp_path / "findings.json", tmp_path / "findings.md"
        code = main([str(input_path), "--policies", str(policies),
                     "--findings", str(findings), "--markdown", str(markdown),
                     *write_tables(tmp_path)])
        return (code,
                json.loads(findings.read_text()) if findings.exists() else None,
                markdown.read_text())
    return go


def load_plan(name):
    return json.loads((FIXTURES_DIR / f"{name}.plan.json").read_text())


@needs_conftest
def test_clean_input_exits_0(run):
    code, findings, markdown = run(load_plan("existing_bucket"))
    assert (code, findings, markdown) == (0, [], "No policy findings.\n")


@needs_conftest
def test_violating_input_exits_1_with_the_row(run):
    plan = load_plan("existing_bucket")
    del plan["resource_changes"][0]["change"]["after"]["tags_all"]["pemc:owner"]

    code, findings, markdown = run(plan)

    assert code == 1
    assert [(f["policy_id"], f["address"]) for f in findings] == [
        ("common.tagging.required_labels", BUCKET)]
    assert f"| common.tagging.required_labels | `{BUCKET}` | " in markdown
    assert "pemc:owner" in markdown


@needs_conftest
def test_empty_policies_directory_exits_2(run, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, findings, markdown = run(load_plan("existing_bucket"), policies=empty)
    assert code == 2
    assert findings is None
    assert markdown.startswith("Policy evaluation failed: ")


@needs_conftest
def test_policies_without_deny_rules_exit_2_when_the_table_policies_did_not_run(run, tmp_path):
    lib_only = tmp_path / "lib_only"
    lib_only.mkdir()
    shutil.copy(POLICIES_DIR / "lib" / "resources.rego", lib_only)
    code, _, markdown = run(load_plan("existing_bucket"), policies=lib_only)
    assert code == 2
    assert "in the enforcement table did not run" in markdown


@needs_conftest
def test_missing_policies_directory_exits_2(run, tmp_path):
    code, _, _ = run(load_plan("existing_bucket"), policies=tmp_path / "nope")
    assert code == 2


@needs_conftest
def test_broken_input_json_exits_2(run):
    code, findings, markdown = run(input_text="{not json")
    assert code == 2
    assert findings is None
    assert markdown.startswith("Policy evaluation failed: ")


@needs_conftest
def test_missing_input_exits_2(tmp_path):
    assert main([str(tmp_path / "nope.json"), "--policies", str(POLICIES_DIR),
                 *write_tables(tmp_path)]) == 2


# enforcement levels and exemptions, end to end

def missing_owner_plan():
    plan = load_plan("existing_bucket")
    del plan["resource_changes"][0]["change"]["after"]["tags_all"]["pemc:owner"]
    return plan


def run_with(tmp_path, plan, tables):
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(normalize(plan, "s")))
    findings, markdown = tmp_path / "findings.json", tmp_path / "findings.md"
    code = main([str(input_path), "--policies", str(POLICIES_DIR), "--today", "2026-10-21",
                 "--findings", str(findings), "--markdown", str(markdown), *tables])
    return code, json.loads(findings.read_text()), markdown.read_text()


@needs_conftest
def test_warn_level_violation_exits_0_and_appears_under_warnings(tmp_path):
    code, findings, markdown = run_with(tmp_path, missing_owner_plan(), write_tables(tmp_path, "warn"))
    assert code == 0
    assert [f["status"] for f in findings] == ["warning"]
    assert markdown.startswith("## Warnings")
    assert f"`{BUCKET}`" in markdown
    assert "## Blocking" not in markdown


@needs_conftest
def test_off_level_violation_is_hidden(tmp_path):
    code, findings, markdown = run_with(tmp_path, missing_owner_plan(), write_tables(tmp_path, "off"))
    assert (code, findings, markdown) == (0, [], "No policy findings.\n")


@needs_conftest
def test_exempted_violation_exits_0_and_appears_under_exempted(tmp_path):
    exemptions = (
        "- policy_id: common.tagging.required_labels\n"
        "  stack: s\n"
        f"  address: {BUCKET}\n"
        "  reason: Owner label arrives in the next change\n"
        "  approved_by: woofle\n"
        "  expires: 2026-11-15\n")
    code, findings, markdown = run_with(tmp_path, missing_owner_plan(), write_tables(tmp_path, exemptions=exemptions))
    assert code == 0
    assert [f["status"] for f in findings] == ["exempted"]
    assert markdown.startswith("## Exempted")
    assert "exempted until 2026-11-15: Owner label arrives in the next change" in markdown
    assert "## Blocking" not in markdown


@needs_conftest
def test_invalid_exemptions_file_exits_2(tmp_path):
    tables = write_tables(tmp_path, exemptions="- policy_id: common.tagging.required_labels\n")
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(normalize(missing_owner_plan(), "s")))
    assert main([str(input_path), "--policies", str(POLICIES_DIR), *tables]) == 2


@needs_conftest
def test_missing_enforcement_table_exits_2(tmp_path):
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(normalize(load_plan("existing_bucket"), "s")))
    assert main([str(input_path), "--policies", str(POLICIES_DIR), *write_tables(tmp_path),
                 "--enforcement", str(tmp_path / "nope.yaml")]) == 2
