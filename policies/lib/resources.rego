package lib

removed := {"delete", "forget"}

evaluated := {r |
	some r in input.resources
	not r.action in removed
}

is_true(r, attr) if {
	r.config[attr] == true
	not r.unknown[attr]
}

is_set(r, attr) if {
	r.config[attr] != null
	not r.unknown[attr]
}

is_set(r, attr) if r.unknown[attr] == true
