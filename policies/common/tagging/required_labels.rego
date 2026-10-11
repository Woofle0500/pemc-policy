package common.tagging.required_labels

import data.lib

policy_id := "common.tagging.required_labels"

# AWS tags use "pemc:", GCP labels can't contain ":" so they use "pemc-".
prefixes := {
	"aws": "pemc:",
	"google": "pemc-",
	"google-beta": "pemc-",
}

required_names := {"owner", "environment", "cost-center"}

allowed_environments := {"platform", "sandbox"}

# METADATA
# description: Labels that can't be read at plan time can't be verified.
# scope: document
# entrypoint: true
deny contains finding if {
	some r in lib.evaluated
	r.labels_state == "unknown"
	finding := {
		"policy_id": policy_id,
		"address": r.address,
		"message": "labels are unknown until apply and cannot be verified",
	}
}

# Missing, or present but unknown (null) required label.
deny contains finding if {
	some r in lib.evaluated
	r.labels_state == "known"
	prefix := prefixes[r.provider]
	some name in required_names
	key := concat("", [prefix, name])
	not is_present(r.labels, key)
	finding := {
		"policy_id": policy_id,
		"address": r.address,
		"message": sprintf("required label %q is missing or has an unknown value", [key]),
	}
}

# Un-allowed value for environment label
deny contains finding if {
	some r in lib.evaluated
	r.labels_state == "known"
	prefix := prefixes[r.provider]
	key := concat("", [prefix, "environment"])
	value := r.labels[key]
	value != null
	not value in allowed_environments
	finding := {
		"policy_id": policy_id,
		"address": r.address,
		"message": sprintf("label %q has a value that is not allowed, expected one of %v", [key, sort(allowed_environments)]),
	}
}

# unknown identifier is denied
deny contains finding if {
	some r in lib.evaluated
	r.labels_state == "known"
	not prefixes[r.provider]
	finding := {
		"policy_id": policy_id,
		"address": r.address,
		"message": sprintf("no label convention defined for provider %s", [r.provider]),
	}
}

is_present(labels, key) if labels[key] != null
