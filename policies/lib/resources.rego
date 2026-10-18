package lib

removed := {"delete", "forget"}

evaluated contains r if {
	some r in input.resources
	not r.action in removed
}

is_true(r, attr) if {
	r.config[attr] == true
	not r.unknown[attr]
}

is_attr_set(r, attr) if {
	r.config[attr] != null
	not r.unknown[attr]
}

is_attr_set(r, attr) if r.unknown[attr] == true

is_attr_set(r, attr) if r.sensitive[attr] == true

# Path variants of the helpers above, for nested attributes. A path is a list of
# keys and indexes, e.g. ["rule", 0, "apply_server_side_encryption_by_default", 0, "kms_master_key_id"].
# config, unknown and sensitive share one shape, so the same path works in each.
# object.get is needed: a path of unknown length can't be written as a reference.
is_true_at(r, path) if {
	# regal ignore:superfluous-object-get
	object.get(r.config, path, null) == true
	not unknown_at(r, path)
}

is_set_at(r, path) if {
	object.get(r.config, path, null) != null
	not unknown_at(r, path)
}

is_set_at(r, path) if unknown_at(r, path)

# regal ignore:superfluous-object-get
is_set_at(r, path) if object.get(r.sensitive, path, null) == true

# regal ignore:superfluous-object-get
unknown_at(r, path) if object.get(r.unknown, path, null) == true
