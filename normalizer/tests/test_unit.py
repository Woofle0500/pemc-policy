import copy
import json

import pytest

from conftest import FIXTURES_DIR
from normalize import (
    NormalizeError,
    attach_related,
    build_resource,
    check_plan,
    extract_labels,
    find_config_resource,
    main,
    map_action,
    normalize,
    parent_address,
    short_provider,
    strip_sensitive,
)

AWS = "registry.terraform.io/hashicorp/aws"
BUCKET = "module.storage.aws_s3_bucket.this"
VERSIONING = "module.storage.aws_s3_bucket_versioning.this"


def make_rc(type_="aws_ebs_volume", name="data", actions=("create",), module=None, **change):
    address = f"{type_}.{name}"
    rc = {
        "address": f"{module}.{address}" if module else address,
        "mode": "managed",
        "type": type_,
        "name": name,
        "provider_name": AWS,
        "change": {"actions": list(actions), **change},
    }
    if module:
        rc["module_address"] = module
    return rc


def make_plan(rcs, configuration=None):
    return {
        "format_version": "1.2",
        "terraform_version": "1.15.9",
        "errored": False,
        "complete": True,
        "resource_changes": rcs,
        "configuration": configuration or {"root_module": {}},
    }


# check_plan

def test_check_plan_ok():
    check_plan(make_plan([]))


@pytest.mark.parametrize("change", [
    {"format_version": "2.0"},
    {"format_version": "1"},
    {"format_version": 1.2},
    {"format_version": None},
    {"errored": True},
    {"complete": False},
])
def test_check_plan_rejects(change):
    with pytest.raises(NormalizeError):
        check_plan({**make_plan([]), **change})


@pytest.mark.parametrize("key", ["format_version", "errored", "complete"])
def test_check_plan_rejects_missing_key(key):
    plan = make_plan([])
    del plan[key]
    with pytest.raises(NormalizeError):
        check_plan(plan)


def test_check_plan_rejects_non_object():
    with pytest.raises(NormalizeError):
        check_plan([])


# map_action

@pytest.mark.parametrize("actions, expected", [
    (["create"], "create"),
    (["update"], "update"),
    (["delete"], "delete"),
    (["forget"], "forget"),
    (["no-op"], "no-op"),
    (["delete", "create"], "replace"),
    (["create", "delete"], "replace"),
])
def test_map_action(actions, expected):
    assert map_action(actions) == expected


@pytest.mark.parametrize("actions", [[], ["read"], ["create", "create"], ["update", "delete"], None, "create"])
def test_map_action_rejects(actions):
    with pytest.raises(NormalizeError):
        map_action(actions)


# short_provider

@pytest.mark.parametrize("name, expected", [
    ("registry.terraform.io/hashicorp/aws", "aws"),
    ("registry.terraform.io/hashicorp/google-beta", "google-beta"),
])
def test_short_provider(name, expected):
    assert short_provider(name) == expected


# strip_sensitive

def test_strip_sensitive_nested():
    value = {
        "name": "db",
        "password": "hunter2",
        "settings": {"user": "admin", "token": "abc"},
        "rules": [{"cidr": "10.0.0.0/8", "secret": "x"}, {"cidr": "0.0.0.0/0", "secret": "y"}],
        "keys": ["public", "private"],
    }
    marker = {
        "password": True,
        "settings": {"token": True, "user": False},
        "rules": [{"secret": True}, {"secret": True}],
        "keys": [False, True],
    }
    assert strip_sensitive(value, marker) == {
        "name": "db",
        "settings": {"user": "admin"},
        "rules": [{"cidr": "10.0.0.0/8"}, {"cidr": "0.0.0.0/0"}],
        "keys": ["public", None],
    }


@pytest.mark.parametrize("marker", [False, {}, [], None])
def test_strip_sensitive_unchanged(marker):
    value = {"a": [1, {"b": 2}]}
    assert strip_sensitive(value, marker) == value


def test_strip_sensitive_short_or_mismatched_marker():
    assert strip_sensitive([1, 2, 3], [True]) == [None, 2, 3]
    assert strip_sensitive({"a": 1}, [True]) == {"a": 1}
    assert strip_sensitive([1], {"a": True}) == [1]


def test_strip_sensitive_does_not_modify_input():
    value = {"a": {"b": 1, "c": 2}, "l": [1, 2]}
    marker = {"a": {"b": True}, "l": [True]}
    before = copy.deepcopy(value)
    strip_sensitive(value, marker)
    assert value == before


def test_strip_sensitive_real_bucket_unchanged(load_fixture):
    rc = load_fixture("existing_bucket.plan.json")["resource_changes"][0]
    after, marker = rc["change"]["after"], rc["change"]["after_sensitive"]
    assert rc["address"] == BUCKET
    assert strip_sensitive(after, marker) == after


# extract_labels

def test_extract_labels_known():
    after = {"tags_all": {"pemc:owner": "woofle"}}
    assert extract_labels("aws", after, {}, {}) == ({"pemc:owner": "woofle"}, "known")


def test_extract_labels_google():
    after = {"effective_labels": {"pemc-owner": "woofle"}, "labels": {"x": "y"}}
    assert extract_labels("google-beta", after, {}, {}) == ({"pemc-owner": "woofle"}, "known")


def test_extract_labels_unsupported_provider():
    assert extract_labels("azurerm", {"tags": {"a": "b"}}, {}, {}) == ({}, "unsupported")


def test_extract_labels_whole_map_unknown():
    assert extract_labels("aws", {}, {"tags_all": True}, {}) == ({}, "unknown")


def test_extract_labels_unknown_key_becomes_null():
    after = {"tags_all": {"pemc:owner": "woofle"}}
    unknown = {"tags_all": {"pemc:environment": True, "pemc:owner": False}}
    assert extract_labels("aws", after, unknown, {}) == (
        {"pemc:owner": "woofle", "pemc:environment": None}, "known")


def test_extract_labels_attr_absent():
    assert extract_labels("aws", {"size": 1}, {}, {}) == ({}, "unsupported")


def test_extract_labels_null_map_is_known_empty():
    assert extract_labels("aws", {"tags_all": None}, {}, {}) == ({}, "known")


def test_extract_labels_whole_map_sensitive():
    after = {"tags_all": {"pemc:owner": "woofle"}}
    assert extract_labels("aws", after, {}, {"tags_all": True}) == ({}, "unknown")


def test_extract_labels_sensitive_key_becomes_null():
    after = {"tags_all": {"pemc:owner": "woofle", "secret": "s3cr3t"}}
    labels, state = extract_labels("aws", after, {}, {"tags_all": {"secret": True}})
    assert (labels, state) == ({"pemc:owner": "woofle", "secret": None}, "known")


def test_extract_labels_tolerates_non_dict_markers():
    after = {"tags_all": {"a": "b"}}
    assert extract_labels("aws", after, None, False) == ({"a": "b"}, "known")


# build_resource

def test_build_resource_create():
    rc = make_rc(
        after={"size": 20, "type": "gp3", "tags": {"pemc:owner": "woofle"}, "tags_all": {"pemc:owner": "woofle"}},
        after_unknown={"encrypted": True, "id": True, "tags_all": {}},
        after_sensitive={"tags": {}, "tags_all": {}},
    )
    assert build_resource(rc) == {
        "address": "aws_ebs_volume.data",
        "type": "aws_ebs_volume",
        "provider": "aws",
        "action": "create",
        "labels": {"pemc:owner": "woofle"},
        "labels_state": "known",
        "config": {"size": 20, "type": "gp3"},
        "unknown": {"encrypted": True, "id": True},
        "sensitive": {},
        "related": {},
    }


def test_build_resource_strips_sensitive_from_config():
    rc = make_rc("aws_db_instance", "db", after={"engine": "pg", "password": "hunter2"},
                 after_unknown={}, after_sensitive={"password": True})
    r = build_resource(rc)
    assert r["config"] == {"engine": "pg"}
    assert r["sensitive"] == {"password": True}


@pytest.mark.parametrize("action", ["delete", "forget"])
def test_build_resource_removed_uses_before(action):
    rc = make_rc(
        actions=(action,),
        before={"size": 20, "password": "x", "tags_all": {"pemc:owner": "woofle"}},
        after=None,
        after_unknown={},
        before_sensitive={"password": True},
        after_sensitive=False,
    )
    r = build_resource(rc)
    assert r["action"] == action
    assert r["config"] == {"size": 20}
    assert r["unknown"] == {}
    assert r["sensitive"] == {"password": True}
    assert (r["labels"], r["labels_state"]) == ({"pemc:owner": "woofle"}, "known")


def test_build_resource_replace_uses_after():
    rc = make_rc(actions=("delete", "create"), before={"size": 10}, after={"size": 20},
                 after_unknown={"id": True}, after_sensitive={})
    r = build_resource(rc)
    assert r["action"] == "replace"
    assert r["config"] == {"size": 20}
    assert r["unknown"] == {"id": True}


def test_build_resource_false_sensitive_becomes_empty():
    rc = make_rc(after={"size": 1}, after_unknown={}, after_sensitive=False)
    assert build_resource(rc)["sensitive"] == {}


def test_build_resource_drops_google_label_attrs():
    rc = make_rc("google_storage_bucket", "b", after={
        "name": "b", "labels": {"a": "1"}, "effective_labels": {"a": "1"}, "terraform_labels": {"a": "1"},
    }, after_unknown={}, after_sensitive={})
    rc["provider_name"] = "registry.terraform.io/hashicorp/google"
    r = build_resource(rc)
    assert r["config"] == {"name": "b"}
    assert (r["labels"], r["labels_state"]) == ({"a": "1"}, "known")


# find_config_resource

def test_find_config_resource_in_module(load_fixture):
    config = load_fixture("new_bucket.plan.json")["configuration"]
    entry = find_config_resource(config, "module.storage", "aws_s3_bucket_versioning", "this")
    assert entry["address"] == "aws_s3_bucket_versioning.this"


def test_find_config_resource_root():
    config = {"root_module": {"resources": [{"address": "aws_s3_bucket.b"}]}}
    assert find_config_resource(config, None, "aws_s3_bucket", "b") == {"address": "aws_s3_bucket.b"}


def test_find_config_resource_nested_and_indexed_modules():
    target = {"address": "aws_s3_bucket.b"}
    config = {"root_module": {"module_calls": {"outer": {"module": {
        "module_calls": {"inner": {"module": {"resources": [target]}}}}}}}}
    assert find_config_resource(config, 'module.outer["x"].module.inner[0]', "aws_s3_bucket", "b") == target


@pytest.mark.parametrize("config, module", [
    (None, None),
    ({}, None),
    ({"root_module": {}}, None),
    ({"root_module": {"resources": [{"address": "aws_s3_bucket.other"}]}}, None),
    ({"root_module": {"resources": [{"address": "aws_s3_bucket.b"}]}}, "module.missing"),
])
def test_find_config_resource_missing(config, module):
    assert find_config_resource(config, module, "aws_s3_bucket", "b") is None


# parent_address

@pytest.mark.parametrize("fixture", ["new_bucket.plan.json", "existing_bucket.plan.json"])
def test_parent_address_from_fixture(load_fixture, fixture):
    plan = load_fixture(fixture)
    children = [rc for rc in plan["resource_changes"] if rc["type"] != "aws_s3_bucket"]
    assert len(children) == 3
    for rc in children:
        assert parent_address(rc, plan["configuration"]) == BUCKET


def test_parent_address_root_module():
    config = {"root_module": {"resources": [{
        "address": "aws_s3_bucket_policy.p",
        "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
    }]}}
    rc = make_rc("aws_s3_bucket_policy", "p")
    assert parent_address(rc, config) == "aws_s3_bucket.b"


def test_parent_address_not_a_child(load_fixture):
    plan = load_fixture("new_bucket.plan.json")
    assert parent_address(plan["resource_changes"][0], plan["configuration"]) is None


@pytest.mark.parametrize("expressions", [
    {},
    {"bucket": {"constant_value": "literal-name"}},
    {"bucket": {"references": ["var.bucket_name"]}},
    {"bucket": {"references": ["aws_s3_bucket.b.id"]}},
])
def test_parent_address_unresolved(expressions):
    config = {"root_module": {"resources": [{"address": "aws_s3_bucket_versioning.v", "expressions": expressions}]}}
    assert parent_address(make_rc("aws_s3_bucket_versioning", "v"), config) is None


# attach_related

def two_bucket_setup(versioning_action="create", parent_ref="aws_s3_bucket.a"):
    rcs = [
        make_rc("aws_s3_bucket", "a", after={}, after_unknown={}, after_sensitive={}),
        make_rc("aws_s3_bucket", "b", after={}, after_unknown={}, after_sensitive={}),
        make_rc("aws_s3_bucket_versioning", "v", actions=(versioning_action,),
                before={"status": "Enabled"}, after={"status": "Enabled"}, after_unknown={}, after_sensitive={}),
    ]
    config = {"root_module": {"resources": [{
        "address": "aws_s3_bucket_versioning.v",
        "expressions": {"bucket": {"references": [f"{parent_ref}.id", parent_ref]}},
    }]}}
    by_address = {rc["address"]: build_resource(rc) for rc in rcs}
    return by_address, rcs, config


def test_attach_related_attaches_to_right_parent():
    by_address, rcs, config = two_bucket_setup()
    attach_related(by_address, rcs, config)
    assert by_address["aws_s3_bucket.a"]["related"] == {"aws_s3_bucket_versioning": [{
        "address": "aws_s3_bucket_versioning.v",
        "action": "create",
        "config": {"status": "Enabled"},
        "unknown": {},
        "sensitive": {},
    }]}
    assert by_address["aws_s3_bucket.b"]["related"] == {}


@pytest.mark.parametrize("action", ["delete", "forget"])
def test_attach_related_skips_removed_child(action):
    by_address, rcs, config = two_bucket_setup(versioning_action=action)
    attach_related(by_address, rcs, config)
    assert by_address["aws_s3_bucket.a"]["related"] == {}


def test_attach_related_missing_parent_leaves_child_unattached():
    by_address, rcs, config = two_bucket_setup(parent_ref="aws_s3_bucket.gone")
    attach_related(by_address, rcs, config)
    assert all(r["related"] == {} for r in by_address.values())


def test_attach_related_sorts_by_address():
    rcs = [make_rc("aws_s3_bucket", "a", after={}, after_unknown={}, after_sensitive={})]
    resources = []
    for name in ["z", "m", "b"]:
        rcs.append(make_rc("aws_s3_bucket_policy", name, after={}, after_unknown={}, after_sensitive={}))
        resources.append({"address": f"aws_s3_bucket_policy.{name}",
                          "expressions": {"bucket": {"references": ["aws_s3_bucket.a"]}}})
    by_address = {rc["address"]: build_resource(rc) for rc in rcs}
    attach_related(by_address, rcs, {"root_module": {"resources": resources}})
    related = by_address["aws_s3_bucket.a"]["related"]["aws_s3_bucket_policy"]
    assert [r["address"] for r in related] == [
        "aws_s3_bucket_policy.b", "aws_s3_bucket_policy.m", "aws_s3_bucket_policy.z"]


# normalize

@pytest.mark.parametrize("fixture, action", [
    ("new_bucket.plan.json", "create"),
    ("existing_bucket.plan.json", "no-op"),
])
def test_normalize_fixture(load_fixture, fixture, action):
    out = normalize(load_fixture(fixture), "live/sandbox/ap-south-1/storage")
    assert out["meta"] == {
        "schema_version": 1,
        "stack": "live/sandbox/ap-south-1/storage",
        "terraform_version": "1.15.9",
    }

    addresses = [r["address"] for r in out["resources"]]
    assert addresses == sorted(addresses)
    assert len(addresses) == 4
    assert all(r["action"] == action for r in out["resources"])

    bucket = out["resources"][0]
    assert bucket["address"] == BUCKET
    assert bucket["labels_state"] == "known"
    assert bucket["labels"]["pemc:owner"] == "woofle"
    for field in ("config", "unknown", "sensitive"):
        assert "tags" not in bucket[field] and "tags_all" not in bucket[field]
    assert {t: len(v) for t, v in bucket["related"].items()} == {
        "aws_s3_bucket_public_access_block": 1,
        "aws_s3_bucket_server_side_encryption_configuration": 1,
        "aws_s3_bucket_versioning": 1,
    }
    versioning = bucket["related"]["aws_s3_bucket_versioning"][0]
    assert versioning["address"] == VERSIONING
    assert versioning["config"]["versioning_configuration"][0]["status"] == "Enabled"

    for child in out["resources"][1:]:
        assert child["labels_state"] == "unsupported"
        assert child["related"] == {}


def test_normalize_new_bucket_child_bucket_unknown(load_fixture):
    out = normalize(load_fixture("new_bucket.plan.json"), "s")
    versioning = out["resources"][0]["related"]["aws_s3_bucket_versioning"][0]
    assert "bucket" not in versioning["config"]
    assert versioning["unknown"]["bucket"] is True


def test_normalize_skips_data_and_deposed():
    data = make_rc("aws_kms_alias", "k", actions=("read",), after={})
    data["mode"] = "data"
    deposed = make_rc("aws_instance", "web", actions=("delete",), before={}, after=None)
    deposed["deposed"] = "00000001"
    current = make_rc("aws_instance", "web", after={}, after_unknown={}, after_sensitive={})
    out = normalize(make_plan([data, deposed, current]), "s")
    assert [r["address"] for r in out["resources"]] == ["aws_instance.web"]
    assert out["resources"][0]["action"] == "create"


def test_normalize_no_resource_changes():
    plan = make_plan([])
    del plan["resource_changes"]
    assert normalize(plan, "s")["resources"] == []


def test_normalize_rejects_bad_plan():
    with pytest.raises(NormalizeError):
        normalize({**make_plan([]), "errored": True}, "s")


def test_normalize_bad_action_names_resource():
    with pytest.raises(NormalizeError, match=r"resource_changes\[0\] aws_ebs_volume.data: unsupported actions"):
        normalize(make_plan([make_rc(actions=("read",), after={})]), "s")


@pytest.mark.parametrize("rc", [
    {"address": "x.y", "mode": "managed"},
    {"address": "x.y", "mode": "managed", "type": "x", "provider_name": AWS, "change": None},
    "not an object",
])
def test_normalize_malformed_entry(rc):
    with pytest.raises(NormalizeError, match=r"resource_changes\[0\]"):
        normalize(make_plan([rc]), "s")


def test_normalize_duplicate_address():
    rc = make_rc(after={}, after_unknown={}, after_sensitive={})
    with pytest.raises(NormalizeError, match="duplicate address"):
        normalize(make_plan([rc, copy.deepcopy(rc)]), "s")


# CLI

def test_main_success(capsys):
    path = str(FIXTURES_DIR / "existing_bucket.plan.json")
    assert main([path, "--stack", "live/sandbox/ap-south-1/storage"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["meta"]["stack"] == "live/sandbox/ap-south-1/storage"
    assert len(out["resources"]) == 4


def test_main_missing_file(capsys, tmp_path):
    assert main([str(tmp_path / "nope.json"), "--stack", "s"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: cannot read")


def test_main_invalid_json(capsys, tmp_path):
    path = tmp_path / "plan.json"
    path.write_text("{not json")
    assert main([str(path), "--stack", "s"]) == 1
    assert capsys.readouterr().err.startswith("error: ")


def test_main_bad_plan(capsys, tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({**make_plan([]), "complete": False}))
    assert main([str(path), "--stack", "s"]) == 1
    assert capsys.readouterr().err.startswith("error: plan complete")


def test_main_non_object_plan(capsys, tmp_path):
    path = tmp_path / "plan.json"
    path.write_text("[]")
    assert main([str(path), "--stack", "s"]) == 1
    assert capsys.readouterr().err == "error: plan must be a JSON object\n"


@pytest.mark.parametrize("argv", [["plan.json"], ["plan.json", "--stack", "  "], []])
def test_main_usage_errors_exit_1(capsys, argv):
    with pytest.raises(SystemExit) as exc:
        code = main(argv)
        raise SystemExit(code)
    assert exc.value.code == 1
    assert capsys.readouterr().err.startswith("error: ")
