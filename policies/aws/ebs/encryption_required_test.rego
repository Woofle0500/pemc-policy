package aws.ebs.encryption_required_test

import data.aws.ebs.encryption_required

plan(action, config, unknown) := {"resources": [{
	"address": "aws_ebs_volume.data",
	"type": "aws_ebs_volume",
	"provider": "aws",
	"action": action,
	"config": config,
	"unknown": unknown,
}]}

finding := {
	"policy_id": "aws.ebs.encryption_required",
	"address": "aws_ebs_volume.data",
	"msg": "EBS volume must set encrypted = true explicitly",
}

test_encrypted_true_passes if {
	count(encryption_required.deny) == 0 with input as plan("create", {"encrypted": true}, {})
}

test_encrypted_false_denied if {
	encryption_required.deny == {finding} with input as plan("create", {"encrypted": false}, {})
}

test_encrypted_unknown_until_apply_denied if {
	encryption_required.deny == {finding} with input as plan("create", {}, {"encrypted": true})
}

test_encrypted_absent_denied if {
	encryption_required.deny == {finding} with input as plan("create", {}, {})
}

test_encrypted_false_noop_denied if {
	encryption_required.deny == {finding} with input as plan("no-op", {"encrypted": false}, {})
}

test_encrypted_false_delete_passes if {
	count(encryption_required.deny) == 0 with input as plan("delete", {"encrypted": false}, {})
}

test_encrypted_false_forget_passes if {
	count(encryption_required.deny) == 0 with input as plan("forget", {"encrypted": false}, {})
}

test_non_ebs_resource_encrypted_false_passes if {
	p := {"resources": [{
		"address": "aws_rds_cluster.main",
		"type": "aws_rds_cluster",
		"provider": "aws",
		"action": "create",
		"config": {"encrypted": false},
		"unknown": {},
	}]}
	count(encryption_required.deny) == 0 with input as p
}
