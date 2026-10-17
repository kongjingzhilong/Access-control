import json
import os
import time
from pathlib import Path
AUDIT_DIR=Path(os.getenv("AUDIT_DIR","./audit_logs"))
def write_log(entry:dict)->None:
    try:
        AUDIT_DIR.mkdir(parents=True,exist_ok=True)
        entry["timestamp"]=int(time.time())
        date_str=time.strftime("%Y-%m-%d")
        log_file=AUDIT_DIR/f"audit_{date_str}.log"
        with open(log_file,"a",encoding="utf-8")as f:
            f.write(json.dumps(entry,ensure_ascii=False)+"\n")
    except Exception as e:
        print(f"[audit] 日志写入失败(fail-open):{e}")
def record_decision(agent_input:dict,k8s_info:dict,opa_result:dict,final_action:str,approval_id:str=None)->None:
    entry={
        "agent_input":agent_input,
        "k8s_info":k8s_info,
        "opa_result":opa_result,
        "final_action":final_action,
        "approval_id":approval_id
    }
    write_log(entry)
def record_approval(approval_id:str,action:str,approver:str)->None:
    entry={
        "type":"approval",
        "approval_id":approval_id,
        "action":action,
        "approver":approver
    }
    write_log(entry)
def get_recent_logs(n:int=20)->list:
    date_str=time.strftime("%Y-%m-%d")
    log_file=AUDIT_DIR/f"audit_{date_str}.log"
    if not log_file.exists():
        return[]
    try:
        lines=log_file.read_text(encoding="utf-8").strip().split("\n")
    except Exception:
        return[]
    entries=[]
    for line in lines[-n:]:
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    return list(reversed(entries))
