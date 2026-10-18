package common.tagging.required_labels_test

import data.common.tagging.required_labels

aws_labels := {
	"pemc:owner": "woofle",
	"pemc:environment": "sandbox",
	"pemc:cost-center": "cc-1001",
}

gcp_labels := {
	"pemc-owner": "woofle",
	"pemc-environment": "sandbox",
	"pemc-cost-center": "cc-1001",
}

resource(provider, action, state, labels) := {
	"address": "res.example",
	"type": "res",
	"provider": provider,
	"action": action,
	"labels": labels,
	"labels_state": state,
	"config": {},
	"unknown": {},
}

findings(r) := fs if {
	fs := required_labels.deny with input as {"resources": [r]}
}

mentions(fs, text) if {
	some f in fs
	contains(f.message, text)
}

# labels_state

test_unsupported_labels_state_passes if {
	r := resource("aws", "create", "unsupported", {})
	count(findings(r)) == 0
}

test_unknown_labels_state_denied if {
	r := resource("aws", "create", "unknown", {})
	fs := findings(r)
	count(fs) == 1
	some f in fs
	f.policy_id == "common.tagging.required_labels"
	f.address == "res.example"
}

# valid labels, one per provider prefix

test_aws_colon_prefix_sandbox_passes if {
	r := resource("aws", "create", "known", aws_labels)
	count(findings(r)) == 0
}

test_aws_colon_prefix_platform_passes if {
	r := resource("aws", "create", "known", object.union(aws_labels, {"pemc:environment": "platform"}))
	count(findings(r)) == 0
}

test_google_dash_prefix_sandbox_passes if {
	r := resource("google", "create", "known", gcp_labels)
	count(findings(r)) == 0
}

test_google_dash_prefix_platform_passes if {
	r := resource("google", "create", "known", object.union(gcp_labels, {"pemc-environment": "platform"}))
	count(findings(r)) == 0
}

# missing keys

test_aws_one_key_missing_denied_naming_key if {
	r := resource("aws", "create", "known", object.remove(aws_labels, ["pemc:owner"]))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc:owner")
}

test_aws_two_keys_missing_two_findings if {
	r := resource("aws", "create", "known", object.remove(aws_labels, ["pemc:owner", "pemc:cost-center"]))
	fs := findings(r)
	count(fs) == 2
	mentions(fs, "pemc:owner")
	mentions(fs, "pemc:cost-center")
}

test_google_one_key_missing_denied_naming_key if {
	r := resource("google", "create", "known", object.remove(gcp_labels, ["pemc-cost-center"]))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc-cost-center")
}

test_google_two_keys_missing_two_findings if {
	r := resource("google", "create", "known", object.remove(gcp_labels, ["pemc-owner", "pemc-environment"]))
	fs := findings(r)
	count(fs) == 2
	mentions(fs, "pemc-owner")
	mentions(fs, "pemc-environment")
}

test_no_labels_at_all_three_findings if {
	r := resource("aws", "create", "known", {})
	count(findings(r)) == 3
}

# environment value

test_aws_prod_environment_denied if {
	r := resource("aws", "create", "known", object.union(aws_labels, {"pemc:environment": "prod"}))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc:environment")
	not mentions(fs, "prod")
}

test_google_prod_environment_denied if {
	r := resource("google", "create", "known", object.union(gcp_labels, {"pemc-environment": "prod"}))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc-environment")
	not mentions(fs, "prod")
}

test_aws_environment_null_denied if {
	r := resource("aws", "create", "known", object.union(aws_labels, {"pemc:environment": null}))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc:environment")
}

test_google_environment_null_denied if {
	r := resource("google", "create", "known", object.union(gcp_labels, {"pemc-environment": null}))
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "pemc-environment")
}

# removed resources

test_missing_keys_delete_passes if {
	r := resource("aws", "delete", "known", {})
	count(findings(r)) == 0
}

test_missing_keys_forget_passes if {
	r := resource("google", "forget", "known", {})
	count(findings(r)) == 0
}

# provider and prefix must match

test_aws_with_dash_prefix_denied if {
	r := resource("aws", "create", "known", gcp_labels)
	fs := findings(r)
	count(fs) == 3
	mentions(fs, "pemc:owner")
	mentions(fs, "pemc:environment")
	mentions(fs, "pemc:cost-center")
}

test_google_with_colon_prefix_denied if {
	r := resource("google", "create", "known", aws_labels)
	fs := findings(r)
	count(fs) == 3
	mentions(fs, "pemc-owner")
	mentions(fs, "pemc-environment")
	mentions(fs, "pemc-cost-center")
}

# providers

test_google_beta_dash_prefix_passes if {
	r := resource("google-beta", "create", "known", gcp_labels)
	count(findings(r)) == 0
}

test_google_beta_with_colon_prefix_denied if {
	r := resource("google-beta", "create", "known", aws_labels)
	fs := findings(r)
	count(fs) == 3
	mentions(fs, "pemc-owner")
}

test_unknown_provider_with_known_labels_denied if {
	r := resource("azurerm", "create", "known", aws_labels)
	fs := findings(r)
	count(fs) == 1
	mentions(fs, "no label convention defined for provider azurerm")
}

test_unknown_provider_with_unsupported_labels_passes if {
	r := resource("azurerm", "create", "unsupported", {})
	count(findings(r)) == 0
}

test_unknown_provider_delete_passes if {
	r := resource("azurerm", "delete", "known", aws_labels)
	count(findings(r)) == 0
}
