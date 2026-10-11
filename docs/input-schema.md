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
| `unknown` | Which attributes are known only after apply | Copied from the plan. See below. |
| `sensitive` | Which attributes Terraform marks sensitive | Their values are removed from `config`. |
| `related` | Other resources that configure this one, grouped by type | e.g. A bucket's versioning, encryption and public-access block are separate resources. |

## Known, unknown and omitted

An attribute can be in one of three states, and policies must tell them apart:

| State | In `config` | In `unknown` | Example |
|---|---|---|---|
| Known value | yes | no | `"encrypted": true` or `false` |
| Unknown until apply | no | `true` | Terraform will compute it |
| Omitted | no | no | Never set and not computed |

A missing key in `config` is not the same as `false`. Check `unknown` before concluding an attribute is absent.

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
