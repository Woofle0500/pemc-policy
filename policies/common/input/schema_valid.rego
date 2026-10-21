package common.input.schema_valid

policy_id := "common.input.schema_valid"

supported_schema_version := 1

required_fields := {"address", "type", "provider", "action", "labels_state"}

allowed_actions := {"create", "update", "replace", "delete", "forget", "no-op"}

allowed_labels_states := {"known", "unknown", "unsupported"}

# METADATA
# description: >-
#   Unsupported (or absent) schema version, reported once for the whole input.
# scope: document
# entrypoint: true
deny contains finding if {
	not input.meta.schema_version == supported_schema_version
	finding := {
		"policy_id": policy_id,
		"address": "<input>",
		"msg": sprintf(
			"unsupported schema_version %v, expected %d",
			[object.get(input, ["meta", "schema_version"], null), supported_schema_version],
		),
	}
}

# Missing (absent or null) required fields, one finding per resource.
deny contains finding if {
	some i, r in input.resources
	missing := {f |
		some f in required_fields
		not is_present(r, f)
	}
	count(missing) > 0
	finding := {
		"policy_id": policy_id,
		"address": address_of(r, i),
		"msg": sprintf("missing required fields: %s", [concat(", ", sort(missing))]),
	}
}

# action value besides the allowed six
deny contains finding if {
	some i, r in input.resources
	is_present(r, "action")
	not r.action in allowed_actions
	finding := {
		"policy_id": policy_id,
		"address": address_of(r, i),
		"msg": sprintf("invalid action %v, expected one of %v", [r.action, sort(allowed_actions)]),
	}
}

# labels_state value besides the allowed three
deny contains finding if {
	some i, r in input.resources
	is_present(r, "labels_state")
	not r.labels_state in allowed_labels_states
	finding := {
		"policy_id": policy_id,
		"address": address_of(r, i),
		"msg": sprintf("invalid labels_state %v, expected one of %v", [r.labels_state, sort(allowed_labels_states)]),
	}
}

is_present(resource, field) if resource[field] != null

address_of(resource, idx) := resource.address if {
	is_present(resource, "address")
} else := sprintf("missing <resource[%d]>", [idx])
