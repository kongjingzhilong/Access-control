import os
import httpx
_opa_url=os.getenv("OPA_URL","http://127.0.0.1:8181")
OPA_URL=_opa_url if _opa_url.startswith(("http://","https://")) else f"http://{_opa_url}"
POLICY_PATH="v1/data/chainshield/authz"
async def evaluate(input_data:dict,client:httpx.AsyncClient=None)->dict:
    payload={"input":input_data}
    url=f"{OPA_URL}/{POLICY_PATH}"
    own_client=False
    if client is None:
        client=httpx.AsyncClient(timeout=10)
        own_client=True
    try:
        resp=await client.post(url,json=payload)
        resp.raise_for_status()
        body=resp.json()
        result=body.get("result",{})
        return{
            "allow":result.get("allow",False),
            "decision":result.get("decision","deny"),
            "risk_level":result.get("risk_level","high"),
            "reason":result.get("reason","策略未覆盖此操作"),
            "required_roles":result.get("required_roles",[])
        }
    except httpx.HTTPStatusError as e:
        return{
            "allow":False,
            "decision":"deny",
            "risk_level":"high",
            "reason":f"OPA服务异常:{e.response.status_code}",
            "required_roles":[]
        }
    except Exception as e:
        return{
            "allow":False,
            "decision":"deny",
            "risk_level":"high",
            "reason":f"OPA连接失败:{str(e)}",
            "required_roles":[]
        }
    finally:
        if own_client:
            await client.aclose()
