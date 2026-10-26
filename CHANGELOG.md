## Unreleased

## 1.0.0 (2026-10-26)

### Features

* **normalizer:** normalise `terraform show -json` plans and link S3 child resources to their bucket ([#5](https://github.com/Woofle0500/pemc-policy/pull/5))
* **normalizer:** evaluate findings with conftest, writing `findings.json` and a Markdown report ([#7](https://github.com/Woofle0500/pemc-policy/pull/7))
* **normalizer:** add enforcement levels (`deny`, `warn`, `off`) and time-limited exemptions ([#8](https://github.com/Woofle0500/pemc-policy/pull/8))
* **policies:** add `common.input.schema_valid` ([#2](https://github.com/Woofle0500/pemc-policy/pull/2))
* **policies:** add `common.tagging.required_labels` ([#1](https://github.com/Woofle0500/pemc-policy/pull/1))
* **policies:** add `aws.ebs.encryption_required`, enforced as `deny` ([#1](https://github.com/Woofle0500/pemc-policy/pull/1), [#16](https://github.com/Woofle0500/pemc-policy/pull/16))
* **ci:** add OPA validate, Regal lint and normalizer test jobs ([#1](https://github.com/Woofle0500/pemc-policy/pull/1), [#3](https://github.com/Woofle0500/pemc-policy/pull/3), [#5](https://github.com/Woofle0500/pemc-policy/pull/5))

### Known issues

* A bucket with `count` or `for_each`, or a child that refers to its bucket through a module output or variable, is not linked, so the S3 rules deny it
