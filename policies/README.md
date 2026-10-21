# Policies

Rego policies that check a normalised Terraform plan. The input format is in [`docs/input-schema.md`](../docs/input-schema.md) and the tool that produces it is in [`normalizer/`](../normalizer/README.md).

## Running

```bash
python normalizer/normalize.py plan.json --stack <stack> > input.json
python normalizer/evaluate.py input.json --policies policies/ --findings findings.json --markdown findings.md
```

`evaluate.py` and its exit codes are described in [`normalizer/README.md`](../normalizer/README.md). What a finding does is set in [Enforcement](#enforcement) and [Exemptions](#exemptions) below.

To run conftest directly, for debugging:

```bash
conftest test --policy policies --all-namespaces input.json -o json
```

**Always pass `--all-namespaces`.** The policy packages are not named `main`, which is all conftest looks at by default. Without the flag it runs 0 tests and exits 0, so every plan passes.

## Findings

Every policy reports problems through a `deny` rule that produces a set of findings. Each finding is an object with three string fields, all required:

| Field | What it is | Example |
|---|---|---|
| `msg` | What is wrong, in one sentence | `required label "pemc:owner" is missing or has an unknown value` |
| `address` | Terraform address of the resource, or `<input>` for a problem with the whole input | `module.storage.aws_s3_bucket.this` |
| `policy_id` | The policy that produced it, matching its package | `common.tagging.required_labels` |

### In conftest output

Conftest shows `msg` as the message and puts the other fields under `metadata`:

```bash
$ conftest test --policy policies --all-namespaces -o json input.json
...
"failures": [
  {
    "msg": "required label \"pemc:owner\" is missing or has an unknown value",
    "metadata": {
      "address": "module.storage.aws_s3_bucket.this",
      "policy_id": "common.tagging.required_labels",
      "query": "data.common.tagging.required_labels.deny"
    }
  }
]
```

`query` is added by conftest. In plain output each finding is one line, `FAIL - <file> - <policy_id> - <msg>`.

### Writing a policy

```rego
deny contains finding if {
	some r in lib.evaluated
	# ... the condition
	finding := {
		"policy_id": "aws.ebs.encryption_required",
		"address": r.address,
		"msg": "EBS volume must set encrypted = true explicitly",
	}
}
```

Use `lib.evaluated` so resources being deleted or forgotten are skipped. The `lib` helpers in `lib/resources.rego` tell known, unknown, omitted and sensitive values apart.

## Enforcement

Rules always report. They never decide whether a finding fails the gate. `evaluate.py` does, using one table, [`enforcement.yaml`](enforcement.yaml):

```yaml
aws.ebs.encryption_required:
  level: deny
  exemptable: true
  since: 2026-10-10
```

| Level | Finding shown in the comment | Fails the gate |
|---|---|---|
| `deny` | yes | yes |
| `warn` | yes, under Warnings | no |
| `off` | no | no |

`exemptable: false` means no exemption may waive the policy. `since` is the date the level last changed.

The table is also the floor. Every policy in it must have run, and every policy that ran must be in it. A deleted or renamed rule, or a new rule without a level, makes `evaluate.py` exit 2. So adding a policy means adding its row in the same change. A finding whose `policy_id` isn't in the table exits 2 too.

Changing a level is a one-line change to `enforcement.yaml`. It doesn't touch Rego.

`off` may be written unquoted. YAML reads it as `false`, and `evaluate.py` accepts that as `off`.

### The ladder

A new rule enters as `warn`. It moves to `deny` once the existing violations it reports are fixed or exempted. Update `since` whenever a level changes.

## Exemptions

[`exemptions.yaml`](../exemptions.yaml) in this repo waives single findings for a limited time. It lives here and not in the infra repo, so granting one takes a reviewed change here plus a pin bump in infra.

```yaml
- policy_id: aws.ebs.encryption_required
  stack: live/sandbox/ap-south-1/storage
  address: aws_ebs_volume.scratch
  reason: Throwaway volume for the Step 11 test
  approved_by: woofle
  expires: 2026-11-15
```

`evaluate.py` exits 2 if any entry in `exemptions.yaml` breaks one of these rules:

- all six fields must be present
- its `policy_id` must be in the enforcement table, and that table row must have `exemptable: true`. An exemption for a policy marked `exemptable: false` is an error.
- `expires` must be a real date no more than 90 days after the run date
- no two entries may share `(policy_id, stack, address)`

A finding matches an exemption when `policy_id`, `address` and the input's `meta.stack` are all equal. A missing `exemptions.yaml` means no exemptions. The run date is today in UTC; `--today YYYY-MM-DD` overrides it.

| Situation | Effect |
|---|---|
| Matches an exemption that hasn't expired | Under Exempted as "exempted until DATE: reason". Doesn't fail. Applies to `warn` findings too. |
| Matches an exemption that has expired | Counts as a normal finding, and is also listed under Warnings as an expired exemption |
| Exemption expires within 7 days | Extra line under Warnings |
| Exemption for this stack whose finding no longer occurs | Listed under Warnings as "unused exemption: remove it". Doesn't fail. |

An exemption is valid through its `expires` date. Exemptions for other stacks are ignored in a run, and so are exemptions for a policy at level `off`, because its findings are hidden.

## Layout

| Path | What it holds |
|---|---|
| `common/` | Rules for every provider: input schema check, required labels |
| `aws/` | AWS resource rules |
| `lib/` | Shared helpers |
| `enforcement.yaml` | The level of each policy |

Tests sit beside each policy as `*_test.rego`. Run them with `opa test policies`.
