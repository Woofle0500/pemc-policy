package aws.ebs.encryption_required

import data.lib

# METADATA
# scope: document
# entrypoint: true
deny contains finding if {
	some r in lib.evaluated
	r.type == "aws_ebs_volume"
	not lib.is_true(r, "encrypted")
	finding := {
		"policy_id": "aws.ebs.encryption_required",
		"address": r.address,
		"msg": "EBS volume must set encrypted = true explicitly",
	}
}
