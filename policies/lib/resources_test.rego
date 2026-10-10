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

test_is_set_when_known_value if {
	lib.is_set(res("create", {"kms_key_id": "k"}, {}), "kms_key_id")
}

test_is_set_when_unknown_after_apply if {
	lib.is_set(res("create", {}, {"kms_key_id": true}), "kms_key_id")
}

test_is_set_false_when_null if {
	not lib.is_set(res("create", {"kms_key_id": null}, {}), "kms_key_id")
}

test_is_set_false_when_absent if {
	not lib.is_set(res("create", {}, {}), "kms_key_id")
}
