DECISION_ALLOW="allow"
DECISION_APPROVAL="requires_approval"
DECISION_DENY="deny"
def make_decision(opa_result:dict)->dict:
    decision=opa_result.get("decision",DECISION_DENY)
    risk_level=opa_result.get("risk_level","high")
    reason=opa_result.get("reason","")
    required_roles=opa_result.get("required_roles",[])
    if decision==DECISION_ALLOW:
        return{
            "action":"allow",
            "risk_level":risk_level,
            "reason":reason,
            "required_roles":required_roles,
            "status_code":200
        }
    if decision==DECISION_DENY:
        return{
            "action":"deny",
            "risk_level":risk_level,
            "reason":reason,
            "required_roles":[],
            "status_code":403
        }
    if decision==DECISION_APPROVAL:
        return{
            "action":"requires_approval",
            "risk_level":risk_level,
            "reason":reason,
            "required_roles":required_roles,
            "status_code":202
        }
    return{
        "action":"deny",
        "risk_level":"high",
        "reason":f"未知决策:{decision}",
        "required_roles":[],
        "status_code":403
    }
