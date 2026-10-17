package chainshield.authz

import future.keywords.if

base_input := {
	"action": "get",
	"resource_type": "pod",
	"resource_name": "x",
	"namespace": "default",
	"labels": {},
	"annotations": {},
	"owner": "team",
	"is_system_namespace": false,
	"has_protection_label": false,
	"is_prod": false,
	"user_roles": ["operator"],
	"current_hour": 14,
	"action_count_1h": 1,
}

test_read_non_system_allowed if {
	decision == "allow" with input as base_input
	risk_level == "low" with input as base_input
}

test_read_system_ns_denied_without_operator_role if {
	decision == "deny" with input as object.union(base_input, {
		"namespace": "kube-system",
		"is_system_namespace": true,
		"user_roles": ["viewer"],
	})
}

test_read_system_ns_allowed_for_operator if {
	decision == "allow" with input as object.union(base_input, {
		"namespace": "kube-system",
		"is_system_namespace": true,
	})
}

test_write_non_prod_requires_approval if {
	decision == "requires_approval" with input as object.union(base_input, {"action": "patch"})
	risk_level == "medium" with input as object.union(base_input, {"action": "patch"})
}

test_write_prod_requires_cluster_admin_approval if {
	inp := object.union(base_input, {"action": "patch", "is_prod": true})
	decision == "requires_approval" with input as inp
	risk_level == "high" with input as inp
	required_roles == ["cluster-admin"] with input as inp
}

test_write_prod_allowed_for_cluster_admin if {
	decision == "allow" with input as object.union(base_input, {
		"action": "patch",
		"is_prod": true,
		"user_roles": ["cluster-admin"],
	})
}

test_delete_prod_denied if {
	inp := object.union(base_input, {"action": "delete", "is_prod": true})
	decision == "deny" with input as inp
	reason == "禁止直接删除生产环境资源" with input as inp
}

test_delete_system_ns_denied if {
	decision == "deny" with input as object.union(base_input, {
		"action": "delete",
		"namespace": "kube-system",
		"is_system_namespace": true,
	})
}

test_delete_protected_denied if {
	decision == "deny" with input as object.union(base_input, {
		"action": "delete",
		"has_protection_label": true,
	})
}

test_delete_non_prod_requires_approval if {
	decision == "requires_approval" with input as object.union(base_input, {"action": "delete"})
}

test_admin_action_denied_without_role if {
	decision == "deny" with input as object.union(base_input, {"action": "scale"})
}

test_admin_action_requires_approval_for_admin if {
	decision == "requires_approval" with input as object.union(base_input, {
		"action": "scale",
		"user_roles": ["cluster-admin"],
	})
}

test_high_risk_outside_working_hours_denied if {
	decision == "deny" with input as object.union(base_input, {
		"action": "delete",
		"current_hour": 22,
	})
}

test_frequency_limit_denied_even_for_reads if {
	decision == "deny" with input as object.union(base_input, {"action_count_1h": 99})
	reason == "操作频率超限,触发限流" with input as object.union(base_input, {"action_count_1h": 99})
}

test_unknown_action_denied_by_default if {
	decision == "deny" with input as object.union(base_input, {"action": "exec"})
}
