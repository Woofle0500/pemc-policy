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
