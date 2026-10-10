package aws.ebs.encryption_required

import data.lib

deny contains finding if {
	some r in lib.evaluated
	r.type == "aws_ebs_volume"
	not lib.is_true(r, "encrypted")
	finding := {
		"policy_id": "aws.ebs.encryption_required",
		"address": r.address,
		"message": "EBS volume must set encrypted = true explicitly",
	}
}
