# Policy input schema

Every policy in `policies/` evaluates a JSON document: the normalised Terraform plan, available as `input`. It is produced by the normaliser.

Current version: `schema_version` 1.

## Example

```json
{
  "meta": {
    "schema_version": 1,
    "stack": "live/sandbox/ap-south-1/storage",
    "terraform_version": "1.15.9"
  },
  "resources": [
    {
      "address": "aws_ebs_volume.data",
      "type": "aws_ebs_volume",
      "provider": "aws",
      "action": "create",
      "labels": { "pemc:owner": "woofle" },
      "labels_state": "known",
      "config": { "size": 20, "type": "gp3" },
      "unknown": { "encrypted": true, "id": true },
      "sensitive": {},
      "related": {}
    }
  ]
}
```

## Fields

| Field | What it is | Note |
|---|---|---|
| `meta.stack` | The stack's path | |
| `meta.schema_version` | `1` | Lets a later change be detected instead of misread. |
| `meta.terraform_version` | Terraform version that produced the plan | Context for debugging. |
| `address` | Terraform resource address, e.g. `aws_ebs_volume.data` | Only unique inside one stack. |
| `type` | Terraform resource type, e.g. `aws_ebs_volume` | |
| `provider` | Short provider name from the plan | |
| `action` | `create`, `update`, `replace`, `delete`, `forget` or `no-op` | |
| `labels` | AWS `tags_all` or GCP `effective_labels` | Both include provider-level defaults, so `default_tags` count. |
| `labels_state` | `known`, `unknown` or `unsupported` | Many resource types can't be tagged at all. |
| `config` | Known attribute values after the change | For a `delete`, it holds the values being removed. |
| `unknown` | Which attributes are known only after apply | Copied from the plan, except label attributes. See below. |
| `sensitive` | Which attributes Terraform marks sensitive | Their values are removed from `config`. Label attributes are left out, see `labels`. |
| `related` | Other resources that configure this one, grouped by type | e.g. A bucket's versioning, encryption and public-access block are separate resources. |

## Known, unknown and omitted

An attribute can be in one of three states, and policies must tell them apart:

| State | In `config` | In `unknown` | Example |
|---|---|---|---|
| Known value | yes | no | `"encrypted": true` or `false` |
| Unknown until apply | no | `true` | Terraform will compute it |
| Omitted | no | no | Never set and not computed |

A missing key in `config` is not the same as `false`. Check `unknown` before concluding an attribute is absent.

## Shape of `unknown` and `sensitive`

`unknown` and `sensitive` follow the shape of `config`, with `true` at the leaves that are unknown or sensitive. Lists keep their positions, so `unknown.rule[0].blocked_encryption_types: true` points at the same item as `config.rule[0]`. `false`, `{}`, `[]` or a missing key all mean nothing at that spot is unknown or sensitive. An attribute that is unknown has no value in `config`, so it appears in `unknown` only.

A sensitive item inside a list is replaced by `null` in `config`, so positions stay aligned.

## Related resources

Some resources are configured by separate resources. E.g. an S3 bucket's versioning, encryption, public-access block, policy and lifecycle configuration are each their own resource. The normaliser links each one to its bucket under the bucket's `related`, grouped by type.

S3 rules must read `related`. They must never read the bucket's own `versioning` or `server_side_encryption_configuration` attributes: the provider deprecates them. They are unknown in a plan for a new bucket and only mirror the separate resources for an existing one.

A bucket with nothing in `related` for a type has no such resource, so the rule denies it. A child that is being deleted or forgotten is not attached, because it won't exist after the apply. Children also stay in the top-level `resources` list.

## Known limits

- A bucket created with `count` or `for_each` (addresses like `aws_s3_bucket.this["logs"]`) is not linked to its children.
- A child that points at its bucket through a module output (`module.storage.bucket_id`), a variable, or a bucket in a different stack is not linked, because it doesn't refer to `aws_s3_bucket.<name>`. The bucket then has nothing in `related`, and the S3 rules deny it even if it is configured correctly.
- A child the normaliser can't link stays unattached. Its bucket then has nothing in `related`, and the S3 rules deny it. Unresolved cases are blocked, never passed.
- Only the child types listed in `normalizer/README.md` are linked.

## Required fields and allowed values

`policies/common/input/schema_valid.rego` denies any input that breaks this contract. It checks every resource, including `delete` and `forget`.

| Check | Rule | Finding address |
|---|---|---|
| `meta.schema_version` | must be `1`; absent counts as wrong | `<input>` |
| Required fields | every resource must have `address`, `type`, `provider`, `action` and `labels_state` | the resource's `address` |
| `action` | one of `create`, `update`, `replace`, `delete`, `forget`, `no-op` | the resource's `address` |
| `labels_state` | one of `known`, `unknown`, `unsupported` | the resource's `address` |

- A required field set to `null` counts as missing.
- A resource missing several fields gets one finding that names all of them.
- A resource with no `address` is reported as `missing <resource[N]>`, where `N` is its index in `resources`.
- `labels`, `config`, `unknown`, `sensitive` and `related` are not checked.

## What findings may contain

They name the resource address, label keys and allowed values, but never `config` values or label values.
