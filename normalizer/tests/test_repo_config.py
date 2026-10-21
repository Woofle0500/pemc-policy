"""CI check on the repo's own enforcement.yaml and exemptions.yaml, so a bad entry fails here and not in every infra stack's gate after the next pin bump. The other tests use temporary files."""
import datetime

import pytest

from conftest import NORMALIZER_DIR
from evaluate import load_enforcement, load_exemptions

ENFORCEMENT = NORMALIZER_DIR.parent / "policies" / "enforcement.yaml"
EXEMPTIONS = NORMALIZER_DIR.parent / "exemptions.yaml"


def check_config(enforcement_path, exemptions_path, today):
    """Load both files as the gate does, then also reject expired exemptions. The gate stays lenient about those so a lapse can't break evaluation, but in this repo an expired entry is dead config."""
    table = load_enforcement(enforcement_path)
    entries = load_exemptions(exemptions_path, table, today)
    expired = [f"{e['policy_id']} {e['stack']} {e['address']} (expired {e['expires']})" for e in entries if e["expires"] < today]
    assert not expired, "expired exemptions, remove them from exemptions.yaml: " + "; ".join(expired)


def test_repo_enforcement_and_exemptions_are_valid_and_not_expired():
    check_config(ENFORCEMENT, EXEMPTIONS, datetime.datetime.now(datetime.timezone.utc).date())


# the check itself, on temporary files

TODAY = datetime.date(2026, 10, 21)
TABLE = "aws.ebs.encryption_required: {level: deny, exemptable: true, since: 2026-10-10}\n"


def entry(expires):
    return f"- {{policy_id: aws.ebs.encryption_required, stack: s, address: a, reason: r, approved_by: x, expires: {expires}}}\n"


def files(tmp_path, exemptions):
    enforcement = tmp_path / "enforcement.yaml"
    enforcement.write_text(TABLE)
    path = tmp_path / "exemptions.yaml"
    path.write_text(exemptions)
    return enforcement, path


def test_check_accepts_a_current_exemption(tmp_path):
    check_config(*files(tmp_path, entry("2026-11-15")), TODAY)


def test_check_accepts_an_exemption_expiring_today(tmp_path):
    check_config(*files(tmp_path, entry("2026-10-21")), TODAY)


def test_check_rejects_an_expired_exemption(tmp_path):
    with pytest.raises(AssertionError, match="expired exemptions.*expired 2026-10-20"):
        check_config(*files(tmp_path, entry("2026-10-20")), TODAY)


def test_check_rejects_an_exemption_more_than_90_days_out(tmp_path):
    with pytest.raises(Exception, match="more than 90 days"):
        check_config(*files(tmp_path, entry("2027-01-20")), TODAY)


def test_check_rejects_a_malformed_exemption(tmp_path):
    with pytest.raises(Exception, match="missing"):
        check_config(*files(tmp_path, "- policy_id: aws.ebs.encryption_required\n"), TODAY)
