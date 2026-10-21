# Normaliser

Turns the JSON from `terraform show -json` into the document the policies read. The format is in [`docs/input-schema.md`](../docs/input-schema.md).

It also links child resources to their parent, such as an S3 bucket's versioning, so policies never have to search for them.

## Usage

```
python normalizer/normalize.py plan.json --stack live/sandbox/ap-south-1/storage
```

The normalised JSON goes to stdout. Python 3.12, standard library only.

## Errors

On any failure the normaliser prints one line to stderr, writes nothing to stdout and exits 1:

```
error: plan complete is False, expected true
```

It fails when:

- the plan file can't be read or isn't valid JSON
- `format_version` doesn't start with `1.`
- the plan has `errored: true` or `complete: false`
- a resource has an action it doesn't know, or is missing a field
- `--stack` is missing or empty

Usage mistakes exit 1 as well, not argparse's default 2.

## Evaluating

```bash
python normalizer/evaluate.py input.json --policies policies/ --findings findings.json --markdown findings.md
```

`input.json` is the output of `normalize.py`. `evaluate.py` runs the policies with conftest, so conftest must be on `PATH`. Python 3.12 and PyYAML (`pip install -r requirements-python.txt`).

| Option | Default |
|---|---|
| `--enforcement` | `enforcement.yaml` in the policies directory |
| `--exemptions` | `exemptions.yaml` next to the policies directory. A missing file means no exemptions. |
| `--today` | today in UTC, `YYYY-MM-DD`. Tests set it. |

| Exit | Meaning |
|---|---|
| 0 | evaluated, nothing blocking |
| 1 | evaluated, at least one blocking finding |
| 2 | couldn't evaluate: conftest error, bad input, a missing or malformed enforcement table or exemptions file, the table and the policies that ran disagree, or a finding from a policy that isn't in the table |

`findings.json` is the findings sorted by policy and address, each with a `status` of `blocking`, `warning` or `exempted`. Exempted findings also carry `expires` and `reason`. Findings at level `off` are left out.

`findings.md` has three sections, each only if it has rows: **Blocking** (deny findings without a valid exemption), **Warnings** (warn findings plus expiring, expired and unused exemption notes) and **Exempted**. With nothing to show it says "No policy findings.". On exit 2 `findings.md` holds the reason, and `error: ...` goes to stderr.

How levels and exemptions work, and the rules for adding a policy, are in [`policies/README.md`](../policies/README.md).

Conftest exits 1 for findings and for real errors alike, which is why `evaluate.py` exists: it tells them apart by whether conftest printed a JSON result. The enforcement table is also a floor: every policy in it must have run and every policy that ran must be in it, so a wrong or emptied policies directory can't pass every plan.

Conftest 0.71.1 bundles OPA 1.21.1, the version in `.tool-versions` that runs `opa test`. Change them together.

## Linking children to parents

`CHILDREN` in `normalize.py` maps a child type to its parent type and to the attribute that refers to the parent:

| Child type | Parent type | Attribute |
|---|---|---|
| `aws_s3_bucket_versioning` | `aws_s3_bucket` | `bucket` |
| `aws_s3_bucket_server_side_encryption_configuration` | `aws_s3_bucket` | `bucket` |
| `aws_s3_bucket_public_access_block` | `aws_s3_bucket` | `bucket` |
| `aws_s3_bucket_policy` | `aws_s3_bucket` | `bucket` |
| `aws_s3_bucket_lifecycle_configuration` | `aws_s3_bucket` | `bucket` |

The link is read from the `configuration` section, not from values, so it works for a new bucket whose id isn't known yet. For each child the normaliser finds its entry in `configuration` and takes the reference to the parent from the attribute, such as `aws_s3_bucket.this`. It then adds the child's module address back on.

An unresolved child stays unattached and its parent's rules deny it. See "Known limits" below.

### Adding a child type

1. Add a line to `CHILDREN` with the child type, the parent type and the attribute that refers to the parent. The parent must be a resource that appears in the plan.
2. Add a plan fixture that includes the new type, if the existing ones don't, and an expected file for it for testing the linking.
3. Add a policy rule that reads `related["<child type>"]` on the parent.
4. Run the tests.

## Known limits

- A parent with its own `count` or `for_each` (plan addresses like `aws_s3_bucket.this["logs"]`) is referenced in `configuration` as plain `aws_s3_bucket.this`, which matches no address in the plan. Its children stay unattached and its rules deny it. A child with `count` or `for_each` is fine as long as its parent has neither.
- A child that points at its bucket through anything other than `aws_s3_bucket.<name>` is never linked. I.e. the reference names a module output or a variable instead, and the normaliser only follows references to the bucket resource itself. For example:
  - a versioning resource in the root module using `module.storage.bucket_id`
  - a child that takes the bucket name from a variable
  - a bucket that lives in a different stack

  The bucket ends up with nothing in `related`, so the S3 rules deny a bucket that may be configured correctly. It fails safe.
- Modules called with `count` or `for_each` are fine: the module prefix comes from the child's own `module_address`, such as `module.storage["logs"]`.
- Only the child types in `CHILDREN` are linked to a parent.
- `unknown` and `sensitive` are copied from the plan except for the label attributes. Those are removed from `config`, `unknown` and `sensitive` and kept only in `labels`.

## Tests

```bash
pip install -r requirements-python.txt
pytest normalizer/
```

- `test_unit.py`: each function, and the command line.
- `test_golden.py`: the `existing_bucket` and `new_bucket` plans in `tests/fixtures/` against their `.expected.json` files. The fixtures are listed by name in the test, so add a new one to that list. Check an expected file by hand when you change it, since output generated by the code only proves the **code** didn't change.
- `test_evaluate.py`: `evaluate.py`, including its exit codes and the warn and exempted cases end to end.
- `test_enforcement.py`: the enforcement table, exemption validation and matching, with "today" passed in.
- `test_end_to_end.py`: the same two plans, normalised and run through every policy with `evaluate.py`, expecting no findings. A negative case removes a required tag and expects the tagging rule to report it, which shows the policies are really evaluated. The tests that run conftest are skipped if it isn't installed, except in CI where they fail.
