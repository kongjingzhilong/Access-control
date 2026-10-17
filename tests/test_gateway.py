import pytest
from fastapi.testclient import TestClient
import gateway
from approval import queue

async def fake_evaluate(input_data:dict,client=None)->dict:
    action=input_data["action"]
    if action in{"get","list","describe","logs","watch"}:
        return{"allow":True,"decision":"allow","risk_level":"low","reason":"只读操作,放行","required_roles":[]}
    if action=="delete" and input_data["is_system_namespace"]:
        return{"allow":False,"decision":"deny","risk_level":"high","reason":"禁止删除系统命名空间资源","required_roles":[]}
    if action=="scale" and "cluster-admin" not in input_data["user_roles"]:
        return{"allow":False,"decision":"deny","risk_level":"high","reason":"管理操作需集群管理员角色","required_roles":[]}
    return{"allow":False,"decision":"requires_approval","risk_level":"high","reason":"生产环境写操作,需管理员审批","required_roles":["cluster-admin"]}

@pytest.fixture
def client(monkeypatch,tmp_path):
    monkeypatch.setattr(gateway.audit,"AUDIT_DIR",tmp_path)
    monkeypatch.setattr(gateway,"_spawn_audit",lambda func,*args:func(*args))
    monkeypatch.setattr(gateway.opa_client,"evaluate",fake_evaluate)
    queue._items.clear()
    gateway.ACTION_WINDOW.clear()
    with TestClient(gateway.app) as c:
        yield c

def test_health(client):
    r=client.get("/health")
    assert r.status_code==200
    assert r.json()["status"]=="ok"

def test_read_action_allowed(client):
    r=client.post("/api/v1/evaluate",json={"action":"get","resource":"pod","name":"x","namespace":"default"})
    assert r.status_code==200
    assert r.json()["decision"]=="allow"

def test_system_ns_delete_denied(client):
    r=client.post("/api/v1/evaluate",json={"action":"delete","resource":"pod","name":"etcd","namespace":"kube-system"})
    assert r.status_code==403
    assert r.json()["decision"]=="deny"

def test_write_requires_approval(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default"})
    assert r.status_code==202
    body=r.json()
    assert body["decision"]=="requires_approval"
    assert body["approval_id"]
    assert body["required_roles"]==["cluster-admin"]

def test_evaluate_rejects_bad_payload(client):
    r=client.post("/api/v1/evaluate",json={"foo":"bar"})
    assert r.status_code==400

def test_approve_requires_identity_header(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default"})
    aid=r.json()["approval_id"]
    r=client.post(f"/approve/{aid}",json={"approver":"tester"})
    assert r.status_code==401

def test_approve_rejects_insufficient_role(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default"})
    aid=r.json()["approval_id"]
    r=client.post(f"/approve/{aid}",json={"approver":"tester"},headers={"X-Approver-Roles":"operator"})
    assert r.status_code==403
    assert "cluster-admin" in r.json()["required_roles"]

def test_full_approval_then_token_retry_allows(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default"})
    aid=r.json()["approval_id"]
    r=client.post(f"/approve/{aid}",json={"approver":"admin1"},headers={"X-Approver-Roles":"cluster-admin"})
    assert r.status_code==200
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default","approved_id":aid})
    assert r.status_code==200
    assert r.json()["decision"]=="allow"
    assert r.json()["approver"]=="admin1"

def test_approval_token_cannot_be_replayed(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default"})
    aid=r.json()["approval_id"]
    client.post(f"/approve/{aid}",json={"approver":"admin1"},headers={"X-Approver-Roles":"cluster-admin"})
    payload={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default","approved_id":aid}
    assert client.post("/api/v1/evaluate",json=payload).status_code==200
    r=client.post("/api/v1/evaluate",json=payload)
    assert r.status_code==403
    assert "重放" in r.json()["error"]

def test_approval_token_must_match_tool_call(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"redis-master-0","namespace":"default"})
    aid=r.json()["approval_id"]
    client.post(f"/approve/{aid}",json={"approver":"admin1"},headers={"X-Approver-Roles":"cluster-admin"})
    r=client.post("/api/v1/evaluate",json={"action":"delete","resource":"pod","name":"redis-master-0","namespace":"default","approved_id":aid})
    assert r.status_code==400
    assert "不匹配" in r.json()["error"]

def test_pending_token_returns_202(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default"})
    aid=r.json()["approval_id"]
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default","approved_id":aid})
    assert r.status_code==202
    assert r.json()["decision"]=="requires_approval"

def test_rejected_token_denied(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default"})
    aid=r.json()["approval_id"]
    r=client.post(f"/reject/{aid}",json={"approver":"admin1"},headers={"X-Approver-Roles":"cluster-admin"})
    assert r.status_code==200
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default","approved_id":aid})
    assert r.status_code==403

def test_unknown_approval_id_404(client):
    r=client.post("/api/v1/evaluate",json={"action":"patch","resource":"pod","name":"x","namespace":"default","approved_id":"nope1234"})
    assert r.status_code==404

def test_malformed_tool_call_arguments_ignored():
    from gateway import extract_tool_call
    req={"tool_calls":[{"function":{"arguments":"{not valid json"}}]}
    assert extract_tool_call(req) is None
    req2={"tool_calls":[{"function":{"arguments":{"action":"delete","resource":"pod","name":"a","namespace":"default"}}}]}
    assert extract_tool_call(req2)["action"]=="delete"

def test_per_request_roles_header(client):
    r=client.post("/api/v1/evaluate",json={"action":"scale","resource":"deployment","name":"nginx","namespace":"default"},headers={"X-User-Roles":"viewer"})
    assert r.status_code==403
    r=client.post("/api/v1/evaluate",json={"action":"scale","resource":"deployment","name":"nginx","namespace":"default"},headers={"X-User-Roles":"cluster-admin"})
    assert r.status_code==202
