"""Evaluate a normalised plan against the policies with conftest.

Usage:
    python evaluate.py input.json --policies policies/ \
        --findings findings.json --markdown findings.md

The rules always report. policies/enforcement.yaml says what each policy's findings mean (deny, warn or off) and exemptions.yaml waives individual findings for a limited time.

Exit codes:
    0  evaluated, nothing blocking
    1  evaluated, at least one blocking finding
    2  couldn't evaluate: conftest error, bad input, a missing or malformed enforcement table or exemptions file, the table and the policies that ran disagree, or a finding from a policy that isn't in the table

Conftest exits 1 for findings and for real errors alike, so the two are told apart by whether it printed a JSON result. The table is also the floor: every policy in it must have run and every policy that ran must be in it, so a policies directory with no deny rules can't pass every plan.
"""

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

LEVELS = ("deny", "warn", "off")
EXEMPTION_FIELDS = ("policy_id", "stack", "address", "reason", "approved_by", "expires")
MAX_EXEMPTION_DAYS = 90
EXPIRY_WARNING_DAYS = 7


class EvaluateError(Exception):
    """The policies could not be evaluated."""


def run_conftest(input_path, policies_dir):
    """Run conftest and return its parsed JSON results (one per namespace)."""
    # --all-namespaces is required: without it conftest only looks at the "main" package, runs 0 tests and exits 0.
    cmd = ["conftest", "test", "--policy", str(policies_dir), "--all-namespaces", "--output", "json", "--no-color", str(input_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        raise EvaluateError(f"cannot run conftest: {e.strerror}") from None

    if proc.returncode not in (0, 1):
        raise EvaluateError(f"conftest exited {proc.returncode}: {_first_line(proc.stderr)}")
    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise EvaluateError(f"conftest failed: {_first_line(proc.stderr)}") from None
    if not isinstance(results, list):
        raise EvaluateError("conftest output is not a list of results")
    return results


def _first_line(text):
    lines = text.strip().splitlines()
    return lines[0] if lines else "no output"


def ran_packages(results):
    """Names of the policy packages that produced a pass or a finding."""
    return {r.get("namespace") for r in results if r.get("successes", 0) + len(r.get("failures") or []) > 0}


def flatten(results):
    """One {policy_id, address, msg} per finding, sorted by (policy_id, address)."""
    findings = []
    for result in results:
        for failure in result.get("failures") or []:
            metadata = failure.get("metadata") or {}
            finding = {
                "policy_id": metadata.get("policy_id"),
                "address": metadata.get("address"),
                "msg": failure.get("msg"),
            }
            if not all(isinstance(v, str) and v for v in finding.values()):
                raise EvaluateError(
                    f"a finding from {result.get('namespace')} is missing msg, address or policy_id")
            findings.append(finding)
    return sorted(findings, key=lambda f: (f["policy_id"], f["address"], f["msg"]))


# the enforcement table

def _load_yaml(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except OSError as e:
        raise EvaluateError(f"cannot read {what} {path}: {e.strerror}") from None
    except (yaml.YAMLError, ValueError):
        # ValueError: PyYAML raises it for a date such as 2026-02-30.
        raise EvaluateError(f"{what} {path} is not valid YAML") from None


def load_enforcement(path):
    """Return {policy_id: {level, exemptable, since}} or raise EvaluateError."""
    table = _load_yaml(path, "enforcement table")
    if not isinstance(table, dict) or not table:
        raise EvaluateError(f"enforcement table {path} must be a non-empty mapping")
    for policy_id, row in table.items():
        if not isinstance(policy_id, str) or not isinstance(row, dict):
            raise EvaluateError(f"enforcement table: {policy_id!r} must map to a mapping")
        if set(row) != {"level", "exemptable", "since"}:
            raise EvaluateError(f"enforcement table: {policy_id} needs exactly level, exemptable and since")
        if row["level"] is False:
            row["level"] = "off"  # YAML 1.1 reads an unquoted off as false
        if row["level"] not in LEVELS:
            raise EvaluateError(f"enforcement table: {policy_id} level must be one of {', '.join(LEVELS)}")
        if not isinstance(row["exemptable"], bool):
            raise EvaluateError(f"enforcement table: {policy_id} exemptable must be true or false")
        if not _is_date(row["since"]):
            raise EvaluateError(f"enforcement table: {policy_id} since must be a date")
    return table


def check_coverage(ran, table):
    """Every policy in the table must have run, and every policy that ran must be in it."""
    missing = sorted(set(table) - ran)
    if missing:
        raise EvaluateError(f"policies in the enforcement table did not run: {', '.join(missing)}")
    unlisted = sorted(p for p in ran - set(table) if p)
    if unlisted:
        raise EvaluateError(f"policies ran but are not in the enforcement table: {', '.join(unlisted)}")


def _is_date(value):
    # yaml.safe_load turns 2026-10-10 into a date and leaves 2026-02-30 a string.
    return isinstance(value, datetime.date) and not isinstance(value, datetime.datetime)


# exemptions

def load_exemptions(path, table, today):
    """Return the exemption entries, or raise EvaluateError. A missing file means none."""
    if not Path(path).exists():
        return []
    entries = _load_yaml(path, "exemptions file")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise EvaluateError(f"exemptions file {path} must be a list")
    seen = set()
    latest = today + datetime.timedelta(days=MAX_EXEMPTION_DAYS)
    for i, e in enumerate(entries, 1):
        where = f"exemption {i}"
        if not isinstance(e, dict):
            raise EvaluateError(f"{where} must be a mapping")
        missing = [f for f in EXEMPTION_FIELDS if e.get(f) in (None, "")]
        if missing:
            raise EvaluateError(f"{where} is missing {', '.join(missing)}")
        for f in EXEMPTION_FIELDS[:-1]:
            if not isinstance(e[f], str):
                raise EvaluateError(f"{where}: {f} must be a string")
        policy = table.get(e["policy_id"])
        if policy is None:
            raise EvaluateError(f"{where}: {e['policy_id']} is not in the enforcement table")
        if not policy["exemptable"]:
            raise EvaluateError(f"{where}: {e['policy_id']} is not exemptable")
        if not _is_date(e["expires"]):
            raise EvaluateError(f"{where}: expires must be a real date (YYYY-MM-DD)")
        if e["expires"] > latest:
            raise EvaluateError(f"{where}: expires {e['expires']} is more than {MAX_EXEMPTION_DAYS} days away (latest allowed {latest})")
        key = (e["policy_id"], e["stack"], e["address"])
        if key in seen:
            raise EvaluateError(f"{where}: duplicate of an earlier entry for {' / '.join(key)}")
        seen.add(key)
    return entries


# deciding what each finding means

def apply_enforcement(findings, table, exemptions, stack, today):
    """Return (findings with a status, notes about exemptions).

    status is blocking, warning or exempted. Findings at level off are dropped. 
    An exempted finding also carries the matching entry's expires and reason. 
    A note is {kind, policy_id, address, text} with kind expired, expiring or unused.
    """
    for f in findings:
        if f["policy_id"] not in table:
            raise EvaluateError(f"finding from {f['policy_id']}, which is not in the enforcement table")

    by_key = {(e["policy_id"], e["stack"], e["address"]): e for e in exemptions}
    matched = set()
    notes = []
    out = []
    for f in findings:
        level = table[f["policy_id"]]["level"]
        if level == "off":
            continue
        key = (f["policy_id"], stack, f["address"])
        e = by_key.get(key)
        status = "blocking" if level == "deny" else "warning"
        if e is not None:
            matched.add(key)
            left = (e["expires"] - today).days
            if left < 0:
                notes.append(_note("expired", f, f"expired exemption: expired {e['expires']}, " "now counts as a normal finding"))
            else:
                status = "exempted"
                if left <= EXPIRY_WARNING_DAYS:
                    notes.append(_note("expiring", f, f"exemption expires {e['expires']} " f"({_days(left)}): {e['reason']}"))
        out.append({**f, "status": status, **({"expires": str(e["expires"]), "reason": e["reason"]} if status == "exempted" else {})})

    for e in exemptions:
        key = (e["policy_id"], e["stack"], e["address"])
        if e["stack"] == stack and key not in matched:
            notes.append(_note("unused", e, "unused exemption: remove it"))

    notes.sort(key=lambda n: (n["policy_id"], n["address"], n["kind"]))
    return out, notes


def _days(n):
    return "today" if n == 0 else f"in {n} day{'s' if n != 1 else ''}"


def _note(kind, item, text):
    return {"kind": kind, "policy_id": item["policy_id"], "address": item["address"], "text": text}


# output

def _cell(text):
    return re.sub(r"\s+", " ", text).replace("|", "\\|")


def _table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def render_markdown(findings, notes=()):
    """Blocking, Warnings and Exempted sections, each only when it has rows."""
    sections = []
    head = ["Policy", "Address", "Message"]

    def row(f, message):
        return [_cell(f["policy_id"]), f"`{_cell(f['address'])}`", _cell(message)]

    blocking = [row(f, f["msg"]) for f in findings if f["status"] == "blocking"]
    if blocking:
        sections.append("## Blocking\n\n" + _table(head, blocking))

    warnings = [(f["policy_id"], f["address"], 0, row(f, f["msg"])) for f in findings if f["status"] == "warning"]
    warnings += [(n["policy_id"], n["address"], 1, row(n, n["text"])) for n in notes]
    if warnings:
        warnings.sort(key=lambda w: w[:3])
        sections.append("## Warnings\n\n" + _table(head, [w[3] for w in warnings]))

    exempted = [row(f, f["msg"]) + [_cell(f"exempted until {f['expires']}: {f['reason']}")] for f in findings if f["status"] == "exempted"]
    if exempted:
        sections.append("## Exempted\n\n" + _table(head + ["Exemption"], exempted))



    return "\n".join(sections) if sections else "No policy findings.\n"


def render_failure(reason):
    return f"Policy evaluation failed: {_cell(reason)}\n"


def _input_stack(input_path):
    """The input's meta.stack, or None. A broken input is conftest's and schema_valid's to report."""
    try:
        with open(input_path, encoding="utf-8") as f:
            stack = json.load(f)["meta"]["stack"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return stack if isinstance(stack, str) else None


def evaluate(input_path, policies_dir, enforcement_path, exemptions_path, today):
    """Return (findings with a status, notes, number of policies that ran)."""
    table = load_enforcement(enforcement_path)
    exemptions = load_exemptions(exemptions_path, table, today)
    results = run_conftest(input_path, policies_dir)
    ran = ran_packages(results)
    check_coverage(ran, table)
    findings, notes = apply_enforcement(flatten(results), table, exemptions, _input_stack(input_path), today)
    return findings, notes, len(ran)


def _write(path, text):
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def _date(text):
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date (YYYY-MM-DD)") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate a normalised plan against the policies.")
    parser.add_argument("input", help="normalised plan, the output of normalize.py")
    parser.add_argument("--policies", required=True, help="policies directory")
    parser.add_argument("--enforcement", help="enforcement table (default: enforcement.yaml in the policies directory)")
    parser.add_argument("--exemptions", help="exemptions file (default: exemptions.yaml next to the policies directory; a missing file means no exemptions)")
    parser.add_argument("--today", type=_date, help="run date, YYYY-MM-DD (default: today in UTC)")
    parser.add_argument("--findings", help="write the findings here as JSON")
    parser.add_argument("--markdown", help="write the findings here as Markdown")
    args = parser.parse_args(argv)

    policies = Path(args.policies)
    enforcement = args.enforcement or policies / "enforcement.yaml"
    exemptions = args.exemptions or policies.parent / "exemptions.yaml"
    today = args.today or datetime.datetime.now(datetime.timezone.utc).date()
    try:
        findings, notes, ran = evaluate(args.input, policies, enforcement, exemptions, today)
    except EvaluateError as e:
        print(f"error: {e}", file=sys.stderr)
        _write(args.markdown, render_failure(str(e)))
        return 2

    _write(args.findings, json.dumps(findings, indent=2) + "\n")
    _write(args.markdown, render_markdown(findings, notes))
    counts = {s: sum(1 for f in findings if f["status"] == s) for s in ("blocking", "warning", "exempted")}
    print(f"{ran} policies evaluated, {counts['blocking']} blocking, " f"{counts['warning']} warnings, {counts['exempted']} exempted", file=sys.stderr)
    return 1 if counts["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
