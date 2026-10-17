package chainshield.authz

import future.keywords.if
import future.keywords.in

default allow := false
default decision := "deny"
default risk_level := "high"
default reason := "策略未覆盖此操作"
default required_roles := []

read_actions := {"get", "list", "describe", "logs", "watch"}
write_actions := {"create", "apply", "patch", "update", "replace"}
delete_actions := {"delete", "remove", "destroy"}
admin_actions := {"bind-rbac", "scale", "rollout-restart"}

is_read if input.action in read_actions
is_write if input.action in write_actions
is_delete if input.action in delete_actions
is_admin if input.action in admin_actions
is_protected if input.has_protection_label == true
is_prod if input.is_prod == true
is_system_ns if input.is_system_namespace == true
is_working_hours if {
    hour := to_number(input.current_hour)
    hour >= 9
    hour < 18
}
has_admin_role if "cluster-admin" in input.user_roles
has_operator_role if input.user_roles[_] in {"admin", "operator"}
frequency_too_high if input.action_count_1h > 20
is_high_risk_action if is_delete
is_high_risk_action if is_admin

decision := "deny" if {
    frequency_too_high
} else := "deny" if {
    is_system_ns
    is_write
} else := "deny" if {
    is_system_ns
    is_delete
} else := "deny" if {
    is_protected
    is_delete
} else := "deny" if {
    is_prod
    is_delete
} else := "deny" if {
    is_high_risk_action
    not is_working_hours
    not has_admin_role
} else := "deny" if {
    is_admin
    not has_admin_role
} else := "requires_approval" if {
    is_admin
} else := "allow" if {
    is_write
    is_prod
    has_admin_role
} else := "requires_approval" if {
    is_write
    is_prod
} else := "requires_approval" if {
    is_write
} else := "requires_approval" if {
    is_delete
} else := "allow" if {
    is_read
    is_system_ns
    has_operator_role
} else := "allow" if {
    is_read
    not is_system_ns
} else := "deny"

risk_level := "high" if {
    frequency_too_high
} else := "high" if {
    is_system_ns
    is_write
} else := "high" if {
    is_system_ns
    is_delete
} else := "high" if {
    is_protected
    is_delete
} else := "high" if {
    is_prod
    is_delete
} else := "high" if {
    is_high_risk_action
    not is_working_hours
    not has_admin_role
} else := "high" if {
    is_admin
    not has_admin_role
} else := "high" if {
    is_admin
} else := "low" if {
    is_write
    is_prod
    has_admin_role
} else := "high" if {
    is_write
    is_prod
} else := "medium" if {
    is_write
} else := "medium" if {
    is_delete
} else := "low" if {
    is_read
    is_system_ns
    has_operator_role
} else := "low" if {
    is_read
    not is_system_ns
} else := "high"

reason := "操作频率超限,触发限流" if {
    frequency_too_high
} else := "禁止修改系统命名空间" if {
    is_system_ns
    is_write
} else := "禁止删除系统命名空间资源" if {
    is_system_ns
    is_delete
} else := "受保护资源禁止删除" if {
    is_protected
    is_delete
} else := "禁止直接删除生产环境资源" if {
    is_prod
    is_delete
} else := "非工作时间禁止高危操作" if {
    is_high_risk_action
    not is_working_hours
    not has_admin_role
} else := "管理操作需集群管理员角色" if {
    is_admin
    not has_admin_role
} else := "管理操作需管理员二次审批" if {
    is_admin
} else := "管理员写生产,放行" if {
    is_write
    is_prod
    has_admin_role
} else := "生产环境写操作,需管理员审批" if {
    is_write
    is_prod
} else := "写操作需人工审批" if {
    is_write
} else := "删除操作需人工审批" if {
    is_delete
} else := "系统命名空间只读,操作员放行" if {
    is_read
    is_system_ns
    has_operator_role
} else := "只读操作,放行" if {
    is_read
    not is_system_ns
} else := "策略未覆盖此操作"

allow if decision == "allow"

required_roles := ["cluster-admin"] if {
    is_admin
} else := ["cluster-admin"] if {
    is_write
    is_prod
} else := ["operator"] if {
    is_write
} else := ["operator"] if {
    is_delete
} else := []
