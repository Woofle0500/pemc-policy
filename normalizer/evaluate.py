"""Evaluate a normalised plan against the policies with conftest.

Usage:
    python evaluate.py input.json --policies policies/ \
        --findings findings.json --markdown findings.md

Exit codes:
    0  evaluated, no findings
    1  evaluated, findings
    2  couldn't evaluate: conftest error, bad input, or fewer policies ran
       than MIN_POLICIES

Conftest exits 1 for findings and for real errors alike, so the two are told
apart by whether it printed a JSON result. The floor turns "evaluated nothing"
into a failure: a policies directory with no deny rules would otherwise find
zero violations and pass every plan.
"""

import argparse
import json
import re
import subprocess
import sys

# Policy packages that must produce a deny result. Raise it when a policy is
# added; test_evaluate.py compares it with the packages in policies/.
MIN_POLICIES = 3


class EvaluateError(Exception):
    """The policies could not be evaluated."""


def run_conftest(input_path, policies_dir):
    """Run conftest and return its parsed JSON results (one per namespace)."""
    # --all-namespaces is required: without it conftest only looks at the
    # "main" package, runs 0 tests and exits 0.
    cmd = ["conftest", "test", "--policy", str(policies_dir), "--all-namespaces",
           "--output", "json", "--no-color", str(input_path)]
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


def count_ran(results):
    """Number of policy packages that produced a pass or a finding."""
    return sum(1 for r in results if r.get("successes", 0) + len(r.get("failures") or []) > 0)


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


def _cell(text):
    return re.sub(r"\s+", " ", text).replace("|", "\\|")


def render_markdown(findings):
    if not findings:
        return "No policy findings.\n"
    rows = ["| Policy | Address | Message |", "|---|---|---|"]
    rows += [f"| {_cell(f['policy_id'])} | `{_cell(f['address'])}` | {_cell(f['msg'])} |"
             for f in findings]
    return "\n".join(rows) + "\n"


def render_failure(reason):
    return f"Policy evaluation failed: {_cell(reason)}\n"


def evaluate(input_path, policies_dir):
    results = run_conftest(input_path, policies_dir)
    ran = count_ran(results)
    if ran < MIN_POLICIES:
        raise EvaluateError(f"only {ran} policies evaluated, expected at least {MIN_POLICIES}")
    return flatten(results), ran


def _write(path, text):
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate a normalised plan against the policies.")
    parser.add_argument("input", help="normalised plan, the output of normalize.py")
    parser.add_argument("--policies", required=True, help="policies directory")
    parser.add_argument("--findings", help="write the findings here as JSON")
    parser.add_argument("--markdown", help="write the findings here as a Markdown table")
    args = parser.parse_args(argv)

    try:
        findings, ran = evaluate(args.input, args.policies)
    except EvaluateError as e:
        print(f"error: {e}", file=sys.stderr)
        _write(args.markdown, render_failure(str(e)))
        return 2

    _write(args.findings, json.dumps(findings, indent=2) + "\n")
    _write(args.markdown, render_markdown(findings))
    print(f"{ran} policies evaluated, {len(findings)} findings", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
