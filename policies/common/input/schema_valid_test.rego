package common.input.schema_valid_test

import data.common.input.schema_valid

meta := {
	"schema_version": 1,
	"stack": "live/sandbox/ap-south-1/storage",
	"terraform_version": "1.15.9",
}

resource := {
	"address": "aws_ebs_volume.data",
	"type": "aws_ebs_volume",
	"provider": "aws",
	"action": "create",
	"labels": {"pemc:owner": "woofle"},
	"labels_state": "known",
	"config": {"size": 20},
	"unknown": {"id": true},
	"sensitive": {},
	"related": {},
}

plan(resources) := {"meta": meta, "resources": resources}

findings(p) := fs if {
	fs := schema_valid.deny with input as p
}

mentions(fs, text) if {
	some f in fs
	contains(f.msg, text)
}

# complete input

test_complete_input_passes if {
	count(findings(plan([resource]))) == 0
}

test_no_resources_passes if {
	count(findings(plan([]))) == 0
}

test_every_allowed_action_passes if {
	rs := [object.union(resource, {"action": a}) |
		some a in ["create", "update", "replace", "delete", "forget", "no-op"]
	]
	count(findings(plan(rs))) == 0
}

test_every_allowed_labels_state_passes if {
	rs := [object.union(resource, {"labels_state": s}) |
		some s in ["known", "unknown", "unsupported"]
	]
	count(findings(plan(rs))) == 0
}

# schema_version

test_wrong_schema_version_denied if {
	p := {"meta": object.union(meta, {"schema_version": 2}), "resources": [resource]}
	fs := findings(p)
	count(fs) == 1
	mentions(fs, "schema_version 2")
	some f in fs
	f.policy_id == "common.input.schema_valid"
	f.address == "<input>"
}

test_string_schema_version_denied if {
	p := {"meta": object.union(meta, {"schema_version": "1"}), "resources": [resource]}
	count(findings(p)) == 1
}

test_missing_schema_version_denied if {
	p := {"meta": object.remove(meta, ["schema_version"]), "resources": [resource]}
	fs := findings(p)
	count(fs) == 1
	some f in fs
	f.address == "<input>"
}

test_missing_meta_denied if {
	fs := findings({"resources": [resource]})
	count(fs) == 1
	some f in fs
	f.address == "<input>"
}

test_wrong_schema_version_is_one_finding_for_many_resources if {
	p := {"meta": object.union(meta, {"schema_version": 2}), "resources": [resource, resource]}
	count(findings(p)) == 1
}

# missing required fields

test_missing_address_denied_with_index_placeholder if {
	ok := object.union(resource, {"address": "a.b"})
	bad := object.remove(resource, ["address"])
	fs := findings(plan([ok, ok, bad]))
	count(fs) == 1
	mentions(fs, "address")
	some f in fs
	f.address == "missing <resource[2]>"
}

test_missing_type_denied if {
	fs := findings(plan([object.remove(resource, ["type"])]))
	count(fs) == 1
	mentions(fs, "type")
}

test_missing_provider_denied if {
	fs := findings(plan([object.remove(resource, ["provider"])]))
	count(fs) == 1
	mentions(fs, "provider")
}

test_missing_action_denied if {
	fs := findings(plan([object.remove(resource, ["action"])]))
	count(fs) == 1
	mentions(fs, "action")
}

test_missing_labels_state_denied if {
	fs := findings(plan([object.remove(resource, ["labels_state"])]))
	count(fs) == 1
	mentions(fs, "labels_state")
}

test_null_field_counts_as_missing if {
	fs := findings(plan([object.union(resource, {"provider": null})]))
	count(fs) == 1
	mentions(fs, "provider")
}

test_several_missing_fields_one_finding_naming_all if {
	fs := findings(plan([object.remove(resource, ["type", "provider"])]))
	count(fs) == 1
	mentions(fs, "provider, type")
}

test_missing_field_on_delete_still_denied if {
	r := object.remove(object.union(resource, {"action": "delete"}), ["type"])
	count(findings(plan([r]))) == 1
}

test_missing_action_not_also_reported_as_invalid if {
	fs := findings(plan([object.remove(resource, ["action"])]))
	count(fs) == 1
	not mentions(fs, "invalid action")
}

test_one_finding_per_broken_resource if {
	a := object.union(resource, {"address": "a.one"})
	b := object.union(object.remove(resource, ["type"]), {"address": "a.two"})
	c := object.union(object.remove(resource, ["provider"]), {"address": "a.three"})
	fs := findings(plan([a, b, c]))
	count(fs) == 2
	{f.address | some f in fs} == {"a.two", "a.three"}
}

# action

test_invalid_action_denied if {
	fs := findings(plan([object.union(resource, {"action": "destroy"})]))
	count(fs) == 1
	mentions(fs, "invalid action destroy")
	some f in fs
	f.address == "aws_ebs_volume.data"
}

test_action_is_case_sensitive if {
	count(findings(plan([object.union(resource, {"action": "Create"})]))) == 1
}

test_action_array_denied if {
	count(findings(plan([object.union(resource, {"action": ["create"]})]))) == 1
}

test_invalid_action_one_finding_per_resource if {
	a := object.union(resource, {"address": "a.one", "action": "destroy"})
	b := object.union(resource, {"address": "a.two", "action": "remove"})
	fs := findings(plan([a, b, resource]))
	count(fs) == 2
}

# labels_state

test_invalid_labels_state_denied if {
	fs := findings(plan([object.union(resource, {"labels_state": "maybe"})]))
	count(fs) == 1
	mentions(fs, "invalid labels_state maybe")
	some f in fs
	f.address == "aws_ebs_volume.data"
}

test_labels_state_is_case_sensitive if {
	count(findings(plan([object.union(resource, {"labels_state": "Known"})]))) == 1
}

test_invalid_labels_state_one_finding_per_resource if {
	a := object.union(resource, {"address": "a.one", "labels_state": "x"})
	b := object.union(resource, {"address": "a.two", "labels_state": "y"})
	count(findings(plan([a, b, resource]))) == 2
}

# independent failures add up

test_all_failure_modes_together if {
	p := {
		"meta": object.union(meta, {"schema_version": 2}),
		"resources": [
			object.remove(resource, ["type"]),
			object.union(resource, {"action": "destroy"}),
			object.union(resource, {"labels_state": "maybe"}),
		],
	}
	count(findings(p)) == 4
}
