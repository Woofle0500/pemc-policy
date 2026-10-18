"""Normalise a Terraform JSON plan into the policy input schema.

Usage:
    python normalize.py plan.json --stack live/sandbox/ap-south-1/storage

Writes the normalised document (docs/input-schema.md) to stdout. On any failure, prints "error: ..." to stderr and exits 1.

Principle: anything the normaliser can't resolve is left in the state that makes policies deny, never in a state that makes them pass.

Known limits:
- A parent with its own count/for_each (plan addresses like aws_s3_bucket.this["logs"]) is referenced from the configuration as plain "aws_s3_bucket.this", which matches no address in the plan. The child stays unattached and the bucket's rules deny. A child with count/for_each is fine as long as its parent has neither.
- Modules called with count/for_each are fine: the module prefix comes from the child's own module_address, e.g. module.storage["logs"].
- Only the child types in CHILDREN are linked to a parent.
- unknown and sensitive are copied from the plan except for the label attributes, which are removed from config, unknown and sensitive alike, kept only in labels.
"""

import argparse
import json
import re
import sys

SCHEMA_VERSION = 1

# Resources that won't exist after the apply.
REMOVED = {"delete", "forget"}

ACTIONS = {
    ("create",): "create",
    ("update",): "update",
    ("delete",): "delete",
    ("forget",): "forget",
    ("no-op",): "no-op",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}

# The attribute holding a resource's effective labels, including provider
# defaults (AWS default_tags, GCP default_labels).
LABEL_ATTR = {
    "aws": "tags_all",
    "google": "effective_labels",
    "google-beta": "effective_labels",
}

# Label attributes removed from config, since labels carries them.
LABEL_ATTRS_TO_DROP = {
    "aws": {"tags", "tags_all"},
    "google": {"labels", "effective_labels", "terraform_labels"},
    "google-beta": {"labels", "effective_labels", "terraform_labels"},
}

# child type -> (parent type, attribute on the child that refers to the parent)
CHILDREN = {
    "aws_s3_bucket_versioning": ("aws_s3_bucket", "bucket"),
    "aws_s3_bucket_server_side_encryption_configuration": ("aws_s3_bucket", "bucket"),
    "aws_s3_bucket_public_access_block": ("aws_s3_bucket", "bucket"),
    "aws_s3_bucket_policy": ("aws_s3_bucket", "bucket"),
    "aws_s3_bucket_lifecycle_configuration": ("aws_s3_bucket", "bucket"),
}

# Returned by strip_sensitive when the whole value is sensitive.
_REMOVED = object()


class NormalizeError(Exception):
    """The plan can't be normalised safely."""


def _as_dict(value):
    """Plan markers can be dict, bool or null; treat anything but a dict as {}."""
    return value if isinstance(value, dict) else {}


def check_plan(plan):
    if not isinstance(plan, dict):
        raise NormalizeError("plan must be a JSON object")

    version = plan.get("format_version")
    if not isinstance(version, str) or not version.startswith("1."):
        raise NormalizeError(f"unsupported plan format_version {version!r}, expected 1.x")

    if plan.get("errored") is not False:
        raise NormalizeError(f"plan errored is {plan.get('errored')!r}, expected false")

    if plan.get("complete") is not True:
        raise NormalizeError(f"plan complete is {plan.get('complete')!r}, expected true")


def map_action(actions):
    try:
        return ACTIONS[tuple(actions)]
    except (KeyError, TypeError):
        raise NormalizeError(f"unsupported actions {actions!r}") from None


def short_provider(provider_name):
    return provider_name.rsplit("/", 1)[-1]


def strip_sensitive(value, marker):
    """Remove values that marker flags as sensitive.

    Dict keys marked true are dropped. List items marked true become None, so
    positions still line up with unknown and sensitive. A top-level true
    returns _REMOVED. Never modifies its input.
    """
    if marker is True:
        return _REMOVED

    if isinstance(marker, dict) and isinstance(value, dict):
        out = {}
        for key, item in value.items():
            stripped = strip_sensitive(item, marker.get(key))
            if stripped is not _REMOVED:
                out[key] = stripped
        return out

    if isinstance(marker, list) and isinstance(value, list):
        out = []
        for i, item in enumerate(value):
            stripped = strip_sensitive(item, marker[i] if i < len(marker) else None)
            out.append(None if stripped is _REMOVED else stripped)
        return out

    return value


def extract_labels(provider, after, after_unknown, after_sensitive):
    attr = LABEL_ATTR.get(provider)
    if attr is None:
        return {}, "unsupported"

    after = _as_dict(after)
    unknown = _as_dict(after_unknown).get(attr)
    sensitive = _as_dict(after_sensitive).get(attr)

    # A wholly sensitive label map can't be shown or checked, so treat it as
    # unknown: required_labels denies it.
    if unknown is True or sensitive is True:
        return {}, "unknown"

    if attr not in after:
        return {}, "unsupported"

    labels = dict(_as_dict(after[attr]))
    # null makes required_labels treat the key as missing.
    for key, flag in _as_dict(unknown).items():
        if flag is True:
            labels[key] = None
    for key, flag in _as_dict(sensitive).items():
        if flag is True:
            labels[key] = None

    return labels, "known"


def build_resource(rc):
    change = rc["change"]
    provider = short_provider(rc["provider_name"])
    action = map_action(change["actions"])

    if action in REMOVED:
        values = change.get("before")
        marker = change.get("before_sensitive")
        unknown = {}
    else:
        values = change.get("after")
        marker = change.get("after_sensitive")
        unknown = _as_dict(change.get("after_unknown"))

    config = strip_sensitive(_as_dict(values), marker)
    if config is _REMOVED:
        config = {}
    labels, labels_state = extract_labels(provider, values, unknown, marker)

    # Labels live only under labels/labels_state. Drop their attributes from
    # config, unknown and sensitive (copies, so the plan isn't modified).
    drop = LABEL_ATTRS_TO_DROP.get(provider, ())
    config = {k: v for k, v in config.items() if k not in drop}
    unknown = {k: v for k, v in unknown.items() if k not in drop}
    sensitive = {k: v for k, v in _as_dict(marker).items() if k not in drop}

    return {
        "address": rc["address"],
        "type": rc["type"],
        "provider": provider,
        "action": action,
        "labels": labels,
        "labels_state": labels_state,
        "config": config,
        "unknown": unknown,
        "sensitive": sensitive,
        "related": {},
    }


def find_config_resource(configuration, module_address, resource_type, resource_name):
    """Find a resource's entry in the configuration section, or None."""
    node = _as_dict(configuration).get("root_module")
    for module_name in re.findall(r'module\.([^.\[]+)', module_address or ""):
        call = _as_dict(_as_dict(node).get("module_calls")).get(module_name)
        node = _as_dict(call).get("module")

    resources = _as_dict(node).get("resources")
    if not isinstance(resources, list):
        return None

    wanted = f"{resource_type}.{resource_name}"
    for entry in resources:
        if isinstance(entry, dict) and entry.get("address") == wanted:
            return entry
    return None


def parent_address(rc, configuration):
    """Address of the resource a child configures, read from config references."""
    if rc.get("type") not in CHILDREN:
        return None
    parent_type, link_attr = CHILDREN[rc["type"]]

    module_address = rc.get("module_address")
    entry = find_config_resource(configuration, module_address, rc["type"], rc.get("name"))
    if entry is None:
        return None

    link = _as_dict(_as_dict(entry.get("expressions")).get(link_attr))
    references = link.get("references")
    if not isinstance(references, list):
        return None

    for ref in references:
        if not isinstance(ref, str):
            continue
        parts = ref.split(".")
        # "aws_s3_bucket.this", not "aws_s3_bucket.this.id"
        if len(parts) == 2 and parts[0] == parent_type:
            return f"{module_address}.{ref}" if module_address else ref
    return None


def attach_related(resources_by_address, rcs, configuration):
    touched = []
    for rc in rcs:
        if rc.get("mode") == "data" or "deposed" in rc or rc.get("type") not in CHILDREN:
            continue

        child = resources_by_address.get(rc.get("address"))
        if child is None or child["action"] in REMOVED:
            continue

        parent = resources_by_address.get(parent_address(rc, configuration))
        if parent is None:
            continue  # unattached: the parent's rules see nothing and deny
        siblings = parent["related"].setdefault(child["type"], [])
        siblings.append({key: child[key] for key in ("address", "action", "config", "unknown", "sensitive")})
        touched.append(siblings)

    for siblings in touched:
        siblings.sort(key=lambda r: r["address"])


def normalize(plan, stack):
    check_plan(plan)

    rcs = plan.get("resource_changes", [])
    if not isinstance(rcs, list):
        raise NormalizeError("resource_changes must be a list")

    resources_by_address = {}
    for i, rc in enumerate(rcs):
        if not isinstance(rc, dict):
            raise NormalizeError(f"resource_changes[{i}] must be an object")
        if rc.get("mode") == "data" or "deposed" in rc:
            continue

        where = f"resource_changes[{i}] {rc.get('address', '<no address>')}"
        try:
            resource = build_resource(rc)
        except NormalizeError as e:
            raise NormalizeError(f"{where}: {e}") from None
        except (KeyError, TypeError, AttributeError) as e:
            raise NormalizeError(f"{where}: malformed entry ({type(e).__name__}: {e})") from None

        if resource["address"] in resources_by_address:
            raise NormalizeError(f"{where}: duplicate address")
        resources_by_address[resource["address"]] = resource

    attach_related(resources_by_address, rcs, plan.get("configuration"))

    return {
        "meta": {
            "schema_version": SCHEMA_VERSION,
            "stack": stack,
            "terraform_version": plan.get("terraform_version"),
        },
        "resources": sorted(resources_by_address.values(), key=lambda r: r["address"]),
    }


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; the contract is "error: ..." and exit 1."""

    def error(self, message):
        print(f"error: {message}", file=sys.stderr)
        sys.exit(1)


def main(argv=None):
    parser = _ArgumentParser(description="Normalise a Terraform JSON plan for policy evaluation.")
    parser.add_argument("plan", help="path to the output of `terraform show -json`")
    parser.add_argument("--stack", required=True, help="stack path, e.g. live/sandbox/ap-south-1/storage")
    args = parser.parse_args(argv)

    try:
        if not args.stack.strip():
            raise NormalizeError("--stack must not be empty")
        try:
            with open(args.plan, encoding="utf-8") as f:
                plan = json.load(f)
        except OSError as e:
            raise NormalizeError(f"cannot read {args.plan}: {e.strerror}") from None
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise NormalizeError(f"{args.plan} is not valid JSON: {e}") from None

        result = normalize(plan, args.stack)
    except NormalizeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
