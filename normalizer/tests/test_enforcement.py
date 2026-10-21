"""Unit tests for the enforcement table and exemptions. "Today" is always passed in."""
import datetime

import pytest

from evaluate import (EvaluateError, apply_enforcement, check_coverage, load_enforcement, load_exemptions, render_markdown)

TODAY = datetime.date(2026, 10, 21)
STACK = "live/sandbox/ap-south-1/storage"
POLICY = "aws.ebs.encryption_required"
ADDRESS = "aws_ebs_volume.scratch"


def day(offset):
    return TODAY + datetime.timedelta(days=offset)


def table(level="deny", exemptable=True):
    return {POLICY: {"level": level, "exemptable": exemptable, "since": day(-10)}, "common.input.schema_valid": {"level": "deny", "exemptable": False, "since": day(-3)},}


def finding(policy_id=POLICY, address=ADDRESS):
    return {"policy_id": policy_id, "address": address, "msg": "bad"}


def exemption(expires=None, **overrides):
    e = {"policy_id": POLICY, "stack": STACK, "address": ADDRESS, "reason": "Throwaway volume", "approved_by": "woofle", "expires": expires or day(30)}
    return {**e, **overrides}


def apply(findings, level="deny", exemptions=(), stack=STACK):
    return apply_enforcement(findings, table(level), list(exemptions), stack, TODAY)


def write(tmp_path, text, name="file.yaml"):
    path = tmp_path / name
    path.write_text(text)
    return path


# the level table

@pytest.mark.parametrize("level, status", [("deny", "blocking"), ("warn", "warning")])
def test_deny_and_warn_findings_are_shown_with_a_status(level, status):
    findings, notes = apply([finding()], level=level)
    assert [f["status"] for f in findings] == [status]
    assert notes == []


def test_off_findings_are_hidden():
    assert apply([finding()], level="off") == ([], [])


def test_finding_from_a_policy_not_in_the_table_is_an_error():
    with pytest.raises(EvaluateError, match="mystery.rule, which is not in the enforcement table"):
        apply([finding("mystery.rule")])


def test_warn_is_rendered_under_warnings_and_not_blocking():
    findings, notes = apply([finding()], level="warn")
    markdown = render_markdown(findings, notes)
    assert "## Warnings" in markdown
    assert "## Blocking" not in markdown


# loading the table

GOOD_TABLE = """
a.b:
  level: warn
  exemptable: true
  since: 2026-10-10
"""


def test_load_enforcement(tmp_path):
    loaded = load_enforcement(write(tmp_path, GOOD_TABLE))
    assert loaded == {"a.b": {"level": "warn", "exemptable": True, "since": datetime.date(2026, 10, 10)}}


def test_unquoted_off_is_read_as_off(tmp_path):
    # YAML 1.1 turns an unquoted off into false.
    text = GOOD_TABLE.replace("warn", "off")
    assert load_enforcement(write(tmp_path, text))["a.b"]["level"] == "off"


@pytest.mark.parametrize("text", ["", "[]", "a.b: deny", "a.b: {level: deny, exemptable: true}", "a.b: {level: deny, exemptable: true, since: 2026-10-10, extra: 1}", "a.b: {level: block, exemptable: true, since: 2026-10-10}", "a.b: {level: deny, exemptable: 'yes', since: 2026-10-10}", "a.b: {level: deny, exemptable: true, since: 2026-02-30}", "a.b: {level: 'off ', exemptable: true, since: 2026-10-10}", "a.b: {level: deny, exemptable: true, since: soon}", "a.b: [unclosed",])
def test_malformed_table_is_an_error(tmp_path, text):
    with pytest.raises(EvaluateError):
        load_enforcement(write(tmp_path, text))


def test_missing_table_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="cannot read enforcement table"):
        load_enforcement(tmp_path / "nope.yaml")


# table and packages must agree

def test_policy_in_table_that_did_not_run_is_an_error():
    with pytest.raises(EvaluateError, match=f"did not run: {POLICY}"):
        check_coverage({"common.input.schema_valid"}, table())


def test_policy_that_ran_without_a_table_row_is_an_error():
    with pytest.raises(EvaluateError, match="not in the enforcement table: new.rule"):
        check_coverage(set(table()) | {"new.rule"}, table())


def test_matching_table_and_packages_pass():
    check_coverage(set(table()), table())


# exemption validation

def load(tmp_path, entries):
    import yaml
    path = write(tmp_path, yaml.safe_dump(entries, sort_keys=False), "exemptions.yaml")
    return load_exemptions(path, table(), TODAY)


def test_valid_exemption_loads(tmp_path):
    assert load(tmp_path, [exemption()]) == [exemption()]


def test_missing_exemptions_file_means_none(tmp_path):
    assert load_exemptions(tmp_path / "exemptions.yaml", table(), TODAY) == []


def test_empty_exemptions_file_means_none(tmp_path):
    assert load_exemptions(write(tmp_path, ""), table(), TODAY) == []


@pytest.mark.parametrize("field", ["policy_id", "stack", "address", "reason", "approved_by", "expires"])
def test_each_missing_field_is_an_error(tmp_path, field):
    entry = exemption()
    del entry[field]
    with pytest.raises(EvaluateError, match=f"missing {field}"):
        load(tmp_path, [entry])


def test_policy_not_in_the_table_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="not in the enforcement table"):
        load(tmp_path, [exemption(policy_id="mystery.rule")])


def test_policy_that_is_not_exemptable_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="not exemptable"):
        load(tmp_path, [exemption(policy_id="common.input.schema_valid")])


@pytest.mark.parametrize("expires, message", [("2026-02-30", "not valid YAML"), ("soon", "expires must be a real date"),])
def test_expires_that_is_not_a_real_date_is_an_error(tmp_path, expires, message):
    path = write(tmp_path, "- {policy_id: %s, stack: s, address: a, reason: r, approved_by: x, expires: %s}\n" % (POLICY, expires))
    with pytest.raises(EvaluateError, match=message):
        load_exemptions(path, table(), TODAY)


def test_expires_more_than_90_days_away_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="more than 90 days"):
        load(tmp_path, [exemption(expires=day(91))])


def test_expires_exactly_90_days_away_is_allowed(tmp_path):
    assert load(tmp_path, [exemption(expires=day(90))])


def test_duplicate_policy_stack_address_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="duplicate"):
        load(tmp_path, [exemption(), exemption(reason="again")])


def test_same_address_in_another_stack_is_not_a_duplicate(tmp_path):
    assert len(load(tmp_path, [exemption(), exemption(stack="live/prod/x")])) == 2


def test_exemptions_file_that_is_not_a_list_is_an_error(tmp_path):
    with pytest.raises(EvaluateError, match="must be a list"):
        load_exemptions(write(tmp_path, "a: b"), table(), TODAY)


# the matching table

def test_unexpired_exemption_exempts_the_finding():
    findings, notes = apply([finding()], exemptions=[exemption()])
    assert findings[0]["status"] == "exempted"
    assert (findings[0]["expires"], findings[0]["reason"]) == (str(day(30)), "Throwaway volume")
    assert notes == []


def test_exemption_valid_through_its_expiry_date():
    findings, _ = apply([finding()], exemptions=[exemption(expires=TODAY)])
    assert findings[0]["status"] == "exempted"


def test_expired_exemption_leaves_a_normal_finding_and_a_note():
    findings, notes = apply([finding()], exemptions=[exemption(expires=day(-1))])
    assert findings[0]["status"] == "blocking"
    assert [n["kind"] for n in notes] == ["expired"]
    assert "expired exemption" in notes[0]["text"]


@pytest.mark.parametrize("left, expiring", [(8, False), (7, True), (1, True), (0, True)])
def test_exemption_expiring_within_7_days_adds_a_warning(left, expiring):
    findings, notes = apply([finding()], exemptions=[exemption(expires=day(left))])
    assert findings[0]["status"] == "exempted"
    assert [n["kind"] for n in notes] == (["expiring"] if expiring else [])


def test_exemption_with_no_finding_is_unused():
    findings, notes = apply([], exemptions=[exemption()])
    assert findings == []
    assert [(n["kind"], n["text"]) for n in notes] == [("unused", "unused exemption: remove it")]


def test_expired_exemption_with_no_finding_is_unused_not_expired():
    _, notes = apply([], exemptions=[exemption(expires=day(-5))])
    assert [n["kind"] for n in notes] == ["unused"]


def test_exemption_for_another_stack_is_ignored():
    findings, notes = apply([finding()], exemptions=[exemption(stack="live/prod/x")])
    assert findings[0]["status"] == "blocking"
    assert notes == []


@pytest.mark.parametrize("other", [{"address": "aws_ebs_volume.other"}, {"policy_id": "common.input.schema_valid"}])
def test_exemption_for_another_address_or_policy_does_not_match(other):
    findings, notes = apply([finding()], exemptions=[exemption(**other)])
    assert findings[0]["status"] == "blocking"
    assert [n["kind"] for n in notes] == ["unused"]


def test_exemption_applies_to_a_warn_finding():
    findings, _ = apply([finding()], level="warn", exemptions=[exemption()])
    assert findings[0]["status"] == "exempted"


def test_finding_with_no_stack_matches_nothing():
    findings, notes = apply([finding()], exemptions=[exemption()], stack=None)
    assert findings[0]["status"] == "blocking"
    assert notes == []


def test_exempted_section_shows_expiry_and_reason():
    findings, notes = apply([finding()], exemptions=[exemption()])
    markdown = render_markdown(findings, notes)
    assert markdown.startswith("## Exempted")
    assert f"exempted until {day(30)}: Throwaway volume" in markdown
    assert "## Blocking" not in markdown


def test_sections_appear_only_with_rows():
    findings, notes = apply([finding()], level="warn")
    markdown = render_markdown(findings, notes)
    assert "## Exempted" not in markdown and "## Blocking" not in markdown
