package lib_test

import data.lib

res(action, config, unknown) := {
	"address": "aws_ebs_volume.data",
	"action": action,
	"config": config,
	"unknown": unknown,
}

test_evaluated_skips_delete_and_forget if {
	plan := {"resources": [
		res("create", {}, {}),
		res("update", {}, {}),
		res("no-op", {}, {}),
		res("delete", {}, {}),
		res("forget", {}, {}),
	]}
	count(lib.evaluated) == 3 with input as plan
}

test_is_true_when_known_true if {
	lib.is_true(res("create", {"encrypted": true}, {}), "encrypted")
}

test_is_true_false_when_known_false if {
	not lib.is_true(res("create", {"encrypted": false}, {}), "encrypted")
}

test_is_true_false_when_omitted if {
	not lib.is_true(res("create", {}, {"encrypted": true}), "encrypted")
}

test_is_true_false_when_absent if {
	not lib.is_true(res("create", {}, {}), "encrypted")
}

test_is_attr_set_when_known_value if {
	lib.is_attr_set(res("create", {"kms_key_id": "k"}, {}), "kms_key_id")
}

test_is_attr_set_when_unknown_after_apply if {
	lib.is_attr_set(res("create", {}, {"kms_key_id": true}), "kms_key_id")
}

test_is_attr_set_false_when_null if {
	not lib.is_attr_set(res("create", {"kms_key_id": null}, {}), "kms_key_id")
}

test_is_attr_set_false_when_absent if {
	not lib.is_attr_set(res("create", {}, {}), "kms_key_id")
}

test_is_attr_set_when_sensitive if {
	r := object.union(res("create", {}, {}), {"sensitive": {"kms_key_id": true}})
	lib.is_attr_set(r, "kms_key_id")
}

test_is_attr_set_false_when_sensitive_false if {
	r := object.union(res("create", {}, {}), {"sensitive": {"kms_key_id": false}})
	not lib.is_attr_set(r, "kms_key_id")
}

# path helpers

kms_path := ["rule", 0, "apply_server_side_encryption_by_default", 0, "kms_master_key_id"]

nested(config, unknown, sensitive) := object.union(
	res("create", config, unknown),
	{"sensitive": sensitive},
)

rule_config(value) := {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": value}]}]}

rule_marker(value) := {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": value}]}]}

test_is_true_at_when_known_true if {
	lib.is_true_at(res("create", {"a": [{"b": true}]}, {}), ["a", 0, "b"])
}

test_is_true_at_false_when_known_false if {
	not lib.is_true_at(res("create", {"a": [{"b": false}]}, {}), ["a", 0, "b"])
}

test_is_true_at_false_when_omitted if {
	not lib.is_true_at(res("create", {"a": [{}]}, {"a": [{"b": true}]}), ["a", 0, "b"])
}

test_is_true_at_false_when_absent if {
	not lib.is_true_at(res("create", {}, {}), ["a", 0, "b"])
}

test_is_true_at_false_when_index_out_of_range if {
	not lib.is_true_at(res("create", {"a": [{"b": true}]}, {}), ["a", 1, "b"])
}

test_is_true_at_false_when_unknown_true_at_path if {
	not lib.is_true_at(res("create", {"a": [{"b": true}]}, {"a": [{"b": true}]}), ["a", 0, "b"])
}

test_is_true_at_ignores_unknown_elsewhere if {
	lib.is_true_at(res("create", {"a": [{"b": true}]}, {"a": [{"c": true}]}), ["a", 0, "b"])
}

test_is_set_at_when_known_value if {
	lib.is_set_at(res("create", rule_config("k"), {}), kms_path)
}

test_is_set_at_when_unknown_after_apply if {
	lib.is_set_at(res("create", {}, rule_marker(true)), kms_path)
}

test_is_set_at_false_when_null if {
	not lib.is_set_at(res("create", rule_config(null), {}), kms_path)
}

test_is_set_at_false_when_absent if {
	not lib.is_set_at(res("create", {}, {}), kms_path)
}

test_is_set_at_false_when_index_out_of_range if {
	not lib.is_set_at(res("create", {"rule": []}, {}), kms_path)
}

test_is_set_at_when_sensitive if {
	lib.is_set_at(nested({}, {}, rule_marker(true)), kms_path)
}

test_is_set_at_false_when_sensitive_false if {
	not lib.is_set_at(nested({}, {}, rule_marker(false)), kms_path)
}

test_is_set_at_false_when_sensitive_elsewhere if {
	not lib.is_set_at(nested({}, {}, {"rule": [{"other": true}]}), kms_path)
}
