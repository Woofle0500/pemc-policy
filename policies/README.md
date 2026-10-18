# Policies

Rego policies that check a normalised Terraform plan. The input format is in [`docs/input-schema.md`](../docs/input-schema.md) and the tool that produces it is in [`normalizer/`](../normalizer/README.md).

## Running

```
python normalizer/normalize.py plan.json --stack <stack> > input.json
conftest test --policy policies --all-namespaces input.json -o json
```

Exit code 0 means no findings, 1 means at least one.


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
