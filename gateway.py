import os
import json
import time
import asyncio
import httpx
from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse,StreamingResponse,HTMLResponse
from contextlib import asynccontextmanager
import k8s_client
import opa_client
from decision import make_decision
from approval import queue
import audit
def _norm_url(u:str)->str:
    return u if u.startswith(("http://","https://")) else f"http://{u}"
OLLAMA_UPSTREAM=_norm_url(os.getenv("OLLAMA_HOST","http://127.0.0.1:12000"))
DEFAULT_ROLES=[r.strip() for r in os.getenv("USER_ROLES","operator").split(",") if r.strip()]
ACTION_WINDOW={}
HOP_BY_HOP={"connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade","content-length","host"}
_audit_tasks:set=set()
def _spawn_audit(func,*args)->None:
    try:
        task=asyncio.create_task(asyncio.to_thread(func,*args))
        _audit_tasks.add(task)
        task.add_done_callback(_audit_tasks.discard)
    except RuntimeError:
        func(*args)
@asynccontextmanager
async def lifespan(app:FastAPI):
    client=httpx.AsyncClient(timeout=None)
    app.state.httpx_client=client
    yield
    await client.aclose()
app=FastAPI(title="链盾 chainshield 安全网关",lifespan=lifespan)
def load_ban_words(file_path="ban.txt"):
    word_list=[]
    try:
        with open(file_path,"r",encoding="utf-8")as f:
            for line in f:
                word=line.strip()
                if word:
                    word_list.append(word)
    except FileNotFoundError:
        pass
    return word_list
ban_list=load_ban_words()
def parse_roles(request:Request)->list[str]:
    raw=request.headers.get("x-user-roles")
    if raw:
        return[r.strip() for r in raw.split(",")if r.strip()]
    return DEFAULT_ROLES
def parse_approver_roles(request:Request)->set[str]:
    raw=request.headers.get("x-approver-roles","")
    return{r.strip() for r in raw.split(",")if r.strip()}
def extract_tool_call(req_json:dict)->dict|None:
    if not isinstance(req_json,dict):
        return None
    if "action" in req_json and "resource" in req_json:
        return{
            "action":req_json.get("action",""),
            "resource":req_json.get("resource",""),
            "name":req_json.get("name",""),
            "namespace":req_json.get("namespace","default")
        }
    if "tool_calls" in req_json:
        for tc in req_json["tool_calls"]:
            fn=tc.get("function",{})
            args=fn.get("arguments",{})
            if isinstance(args,str):
                try:
                    args=json.loads(args)
                except (json.JSONDecodeError,ValueError):
                    continue
            if isinstance(args,dict) and "action" in args and "resource" in args:
                return{
                    "action":args.get("action",""),
                    "resource":args.get("resource",""),
                    "name":args.get("name",""),
                    "namespace":args.get("namespace","default")
                }
    return None
def get_action_count(action:str)->int:
    now=int(time.time())
    window_start=now-3600
    if action not in ACTION_WINDOW:
        ACTION_WINDOW[action]=[]
    ACTION_WINDOW[action]=[t for t in ACTION_WINDOW[action]if t>window_start]
    ACTION_WINDOW[action].append(now)
    return len(ACTION_WINDOW[action])
def _approved_token_response(approval_id:str,tool_call:dict)->tuple[dict,int]:
    item=queue.get(approval_id)
    if item is None:
        return{"error":"审批单不存在或已过期","approval_id":approval_id},404
    if item.status=="pending":
        return{
            "decision":"requires_approval",
            "approval_id":approval_id,
            "risk_level":item.opa_result.get("risk_level"),
            "reason":"审批尚未完成",
            "required_roles":item.opa_result.get("required_roles",[])
        },202
    if item.status=="rejected":
        return{"error":"审批已被拒绝","approval_id":approval_id},403
    if item.consumed:
        return{"error":"审批令牌已使用,禁止重放","approval_id":approval_id},403
    if not queue.matches(item,tool_call):
        return{"error":"审批单与当前工具调用不匹配","approval_id":approval_id},400
    queue.consume(approval_id)
    _spawn_audit(audit.record_decision,tool_call,item.k8s_info,item.opa_result,"allow_after_approval",approval_id)
    return{
        "decision":"allow",
        "risk_level":item.opa_result.get("risk_level","medium"),
        "reason":"人工审批已通过,放行",
        "approval_id":approval_id,
        "approver":item.approver
    },200
async def run_policy_chain(tool_call:dict,client:httpx.AsyncClient,roles:list[str],approved_id:str|None=None)->tuple[dict,int]:
    if approved_id:
        return _approved_token_response(approved_id,tool_call)
    k8s_info=k8s_client.get_resource_info(
        tool_call["resource"],
        tool_call["name"],
        tool_call["namespace"]
    )
    opa_input={
        "action":tool_call["action"],
        "resource_type":tool_call["resource"],
        "resource_name":tool_call["name"],
        "namespace":k8s_info["namespace"],
        "labels":k8s_info["labels"],
        "annotations":k8s_info["annotations"],
        "owner":k8s_info["owner"],
        "is_system_namespace":k8s_info["is_system_namespace"],
        "has_protection_label":k8s_info["has_protection_label"],
        "is_prod":k8s_info["is_prod"],
        "user_roles":roles,
        "current_hour":time.localtime().tm_hour,
        "action_count_1h":get_action_count(tool_call["action"])
    }
    opa_result=await opa_client.evaluate(opa_input,client)
    decision=make_decision(opa_result)
    approval_id=None
    if decision["action"]=="requires_approval":
        item=queue.create(tool_call,k8s_info,opa_result)
        approval_id=item.id
    _spawn_audit(audit.record_decision,tool_call,k8s_info,opa_result,decision["action"],approval_id)
    body={
        "decision":decision["action"],
        "risk_level":decision["risk_level"],
        "reason":decision["reason"],
        "required_roles":decision["required_roles"]
    }
    if approval_id:
        body["approval_id"]=approval_id
    return body,decision["status_code"]
@app.get("/health")
async def health():
    return{"status":"ok","service":"chainshield-gateway"}
@app.get("/",response_class=HTMLResponse)
async def panel():
    with open("panel.html","r",encoding="utf-8")as f:
        return f.read()
@app.get("/api/status")
async def status():
    client:httpx.AsyncClient=app.state.httpx_client
    opa_ok=False
    ollama_ok=False
    try:
        r=await client.get(f"{opa_client.OPA_URL}/health",timeout=3)
        opa_ok=r.status_code==200
    except Exception:
        pass
    try:
        r=await client.get(f"{OLLAMA_UPSTREAM}/api/tags",timeout=3)
        ollama_ok=r.status_code==200
    except Exception:
        pass
    return{
        "gateway":True,
        "opa":opa_ok,
        "ollama":ollama_ok,
        "ollama_url":OLLAMA_UPSTREAM,
        "opa_url":opa_client.OPA_URL,
        "user_roles":DEFAULT_ROLES
    }
@app.get("/api/audit/recent")
async def audit_recent(n:int=20):
    return audit.get_recent_logs(n)
@app.post("/api/v1/evaluate")
async def pdp_evaluate(request:Request):
    try:
        body=await request.json()
    except Exception:
        return JSONResponse(status_code=400,content={"error":"请求体必须是JSON"})
    tool_call=extract_tool_call(body)
    if not tool_call:
        return JSONResponse(status_code=400,content={"error":"缺少 action/resource 字段"})
    roles=parse_roles(request)
    approved_id=body.get("approved_id")
    client:httpx.AsyncClient=request.app.state.httpx_client
    result,status_code=await run_policy_chain(tool_call,client,roles,approved_id)
    return JSONResponse(status_code=status_code,content=result)
@app.get("/approvals")
async def list_approvals():
    items=queue.list_pending()
    return{
        "count":len(items),
        "approvals":[{
            "id":i.id,
            "action":i.agent_input.get("action"),
            "resource":i.agent_input.get("resource"),
            "name":i.agent_input.get("name"),
            "namespace":i.agent_input.get("namespace"),
            "risk_level":i.opa_result.get("risk_level"),
            "reason":i.opa_result.get("reason"),
            "required_roles":i.opa_result.get("required_roles",[]),
            "created_at":i.created_at
        }for i in items]
    }
@app.post("/approve/{approval_id}")
async def approve(approval_id:str,request:Request):
    approver_roles=parse_approver_roles(request)
    if not approver_roles:
        return JSONResponse(status_code=401,content={"error":"缺少审批人身份,请通过 X-Approver-Roles 头声明角色"})
    item=queue.get(approval_id)
    if not item:
        return JSONResponse(status_code=404,content={"error":"审批单不存在或已处理"})
    required=set(item.opa_result.get("required_roles",[]))
    if required and not(approver_roles&required):
        return JSONResponse(status_code=403,content={"error":"审批人角色不足","required_roles":sorted(required),"your_roles":sorted(approver_roles)})
    body={}
    try:
        body=await request.json()
    except Exception:
        pass
    approver=body.get("approver","unknown")
    approved=queue.approve(approval_id,approver)
    if not approved:
        return JSONResponse(status_code=404,content={"error":"审批单不存在或已处理"})
    _spawn_audit(audit.record_approval,approval_id,"approve",approver)
    return{
        "status":"approved",
        "approval_id":approval_id,
        "action":item.agent_input.get("action"),
        "resource":item.agent_input.get("resource"),
        "next_step":"Agent 携带 approved_id 重新调用 /api/v1/evaluate 完成执行"
    }
@app.post("/reject/{approval_id}")
async def reject(approval_id:str,request:Request):
    approver_roles=parse_approver_roles(request)
    if not approver_roles:
        return JSONResponse(status_code=401,content={"error":"缺少审批人身份,请通过 X-Approver-Roles 头声明角色"})
    body={}
    try:
        body=await request.json()
    except Exception:
        pass
    approver=body.get("approver","unknown")
    item=queue.reject(approval_id,approver)
    if not item:
        return JSONResponse(status_code=404,content={"error":"审批单不存在或已处理"})
    _spawn_audit(audit.record_approval,approval_id,"reject",approver)
    return{
        "status":"rejected",
        "approval_id":approval_id,
        "action":item.agent_input.get("action"),
        "resource":item.agent_input.get("resource")
    }
def _filter_headers(headers:dict)->dict:
    return{k:v for k,v in headers.items()if k.lower() not in HOP_BY_HOP}
@app.api_route("/{path:path}",methods=["GET","POST","PUT","DELETE"])
async def proxy(request:Request,path:str):
    method=request.method
    headers=_filter_headers(dict(request.headers))
    body=await request.body()
    upstream_url=f"{OLLAMA_UPSTREAM}/{path}"
    req_json=None
    if method=="POST" and body:
        try:
            req_json=json.loads(body.decode("utf-8"))
        except Exception:
            pass
    if req_json:
        req_str=json.dumps(req_json)
        for word in ban_list:
            if word in req_str:
                return JSONResponse(
                    status_code=403,
                    content={"error":"链盾拦截:检测到高危指令","matched":word}
                )
        tool_call=extract_tool_call(req_json)
        if tool_call:
            client:httpx.AsyncClient=request.app.state.httpx_client
            roles=parse_roles(request)
            approved_id=req_json.get("approved_id")
            result,status_code=await run_policy_chain(tool_call,client,roles,approved_id)
            if status_code!=200:
                return JSONResponse(status_code=status_code,content=result)
    client:httpx.AsyncClient=request.app.state.httpx_client
    upstream_req=client.build_request(
        url=upstream_url,
        method=method,
        headers=headers,
        content=body
    )
    upstream_resp=await client.send(upstream_req,stream=True)
    resp_headers=_filter_headers(dict(upstream_resp.headers))
    async def stream_generator():
        try:
            async for chunk in upstream_resp.aiter_bytes():
                yield chunk
        except Exception as e:
            print(f"流式传输异常:{str(e)}")
    return StreamingResponse(
        stream_generator(),
        status_code=upstream_resp.status_code,
        headers=resp_headers
    )
if __name__=="__main__":
    import uvicorn
    uvicorn.run("gateway:app",host="0.0.0.0",port=12001)
