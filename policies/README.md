# Policies

Rego policies that check a normalised Terraform plan. The input format is in [`docs/input-schema.md`](../docs/input-schema.md) and the tool that produces it is in [`normalizer/`](../normalizer/README.md).

## Running

```bash
python normalizer/normalize.py plan.json --stack <stack> > input.json
python normalizer/evaluate.py input.json --policies policies/ --findings findings.json --markdown findings.md
```

`evaluate.py`, its exit codes and the `MIN_POLICIES` floor are described in [`normalizer/README.md`](../normalizer/README.md).

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

## Layout

| Path | What it holds |
|---|---|
| `common/` | Rules for every provider: input schema check, required labels |
| `aws/` | AWS resource rules |
| `lib/` | Shared helpers |

Tests sit beside each policy as `*_test.rego`. Run them with `opa test policies`.
