import json 
from dataclasses import dataclass
RISK_LEVEL={
    "LOW":"放行",
    "MEDIUM":"确认",
    "HIGH":"拦截"
}
LOW_ACTIONS={"get","list","describe","logs"}
MEDIUM_ACTIONS={"scan","check","probe"}
HIGH_ACTIONS={"delete","patch","create","update","bind-rbac"}
@dataclass
class AgentAction:
    action: str
    source: str
    source_name: str
    namespace: str
def prase_agent_json(raw_json_str:str) ->AgentAction:
    data=json.loads(raw_json_str)
    return AgentAction(
        action=data["action"]
        resource=data["resource"]
        resources_name=data["name"]
        namespace=data["namespace"]
    )
def fengxian (action:AgentAction) -> tuple[str:str]:
    act=action.action.lower()
    if act in LOW_ACTIONS:
        return RISK_LEVEL["LOW"],f"{act}低风险操作,放行"
    elif act in MEDIUM_ACTIONS:
        return RISK_LEVEL["MEDIUM"],f"{act}风险操作,通过需人工确认"
    elif act in RISK_LEVEL:
        return RISK_LEVEL["HIGH"],f"{act}高危操作,获批后方可执行"
    else:
        return "未知风险",f"{act}无法识别"



    