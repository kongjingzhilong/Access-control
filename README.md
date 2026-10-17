# 链盾 ChainShield

K8s Agent 操作安全网关 —— 拦截大模型生成的 Kubernetes 工具调用，经 OPA 策略引擎判定后执行 **放行 / 人工审批 / 拦截**，全程审计留痕。

## 架构

```
┌─────────┐   工具调用    ┌──────────────┐   资产查询   ┌───────────┐
│ Agent    │ ──────────> │  链盾网关      │ ─────────> │ K8s(模拟)  │
│ (PEP)    │             │  FastAPI:12001│ <───────── │           │
└─────────┘              └──────┬───────┘   属性打包   └───────────┘
     │  ^                        │
     │  │ 200 allow              │ POST /v1/data
     │  │ 202 需审批              ▼
     │  │ 403 deny        ┌──────────────┐
     │  │                 │  OPA 策略引擎 │  Rego
     │  │                 │  :8181       │  authz.rego
     │  │                 └──────────────┘
     │  │                        │
     │  └── approved_id 重试 ────┤
     │                           ▼
     │                    ┌──────────────┐
     └────────────────────│ 审批队列+审计  │
        人工批准(面板/API)  └──────────────┘
```

网关定位为 **PDP（策略决策点）**：只输出决策，不执行 K8s 操作。Agent 作为 **PEP（策略执行点）**，收到 `allow` 后才真正执行。

## 工作流

1. Agent 执行工具调用前，把 `action/resource/name/namespace` POST 给网关 `/api/v1/evaluate`
2. 网关查询 K8s（当前为 mock）补全 namespace、labels、annotations 等资产属性
3. 网关把 `动作 + 资产属性 + 用户角色 + 上下文` 打包成 JSON 发给 OPA
4. OPA 执行 Rego 策略，返回 `decision + risk_level + reason + required_roles`
5. 网关根据决策返回：`200 放行` / `202 挂起等待审批` / `403 拦截`
6. 每次判定写入审计日志（异步、fail-open），面板可实时查看

## 项目结构

```
链盾/
├── gateway.py          # 网关主程序：PDP 端点、审批编排、Ollama 透明代理
├── approval.py         # 审批队列：TTL 过期、一次性令牌、调用指纹匹配
├── decision.py         # 决策器：OPA 结果 -> HTTP 状态码映射（纯函数）
├── opa_client.py       # OPA HTTP 客户端（fail-closed）
├── k8s_client.py       # K8s 资产查询（当前为 mock，预置 nginx/redis 数据）
├── audit.py            # 审计日志：按天分文件、异步落盘、fail-open
├── panel.html          # Web 控制台（自包含，无外部依赖）
├── policy/authz.rego   # Rego 策略：按优先级 else 链，单一判定出口
├── tests/
│   ├── authz_test.rego # 策略测试（15 条）
│   └── test_gateway.py # 网关编排测试（15 条，stub OPA）
├── ban.txt             # 透传代理关键词黑名单（当前为空）
├── docker-compose.yaml / dockerfile / requirements.txt
└── pytest.ini
```

## 快速启动

三个服务按顺序启动，各占一个终端：

**1. Ollama（端口 12000）**

```powershell
$env:OLLAMA_HOST="127.0.0.1:12000"
ollama serve
```

**2. OPA（端口 8181）**

```powershell
cd d:\链盾
.\opa.exe run --server .\policy
```

**3. 链盾网关（端口 12001）**

```powershell
cd d:\链盾
python gateway.py
```

浏览器打开 **http://127.0.0.1:12001/** 进入控制台面板。

环境变量（均有默认值）：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OLLAMA_HOST` | `http://127.0.0.1:12000` | 上游 Ollama 地址（不带协议头自动补） |
| `OPA_URL` | `http://127.0.0.1:8181` | OPA 服务地址 |
| `USER_ROLES` | `operator` | 未携带身份头时的默认角色 |
| `AUDIT_DIR` | `./audit_logs` | 审计日志目录 |

## 核心 API

### 策略判定 `POST /api/v1/evaluate`

请求体（Agent 用户身份通过 `X-User-Roles` 头声明，逗号分隔）：

```json
{
  "action": "patch",
  "resource": "pod",
  "name": "redis-master-0",
  "namespace": "default"
}
```

响应（三态）：

| 状态码 | decision | 含义 | Agent 侧动作 |
|--------|----------|------|--------------|
| 200 | `allow` | 放行 | 立即执行操作 |
| 202 | `requires_approval` | 需人工审批，附 `approval_id` | 挂起，等待审批 |
| 403 | `deny` | 拦截，附风险原因 | 放弃并上报 |

带 `approved_id` 重试（审批通过后）：

```json
{
  "action": "patch",
  "resource": "pod",
  "name": "redis-master-0",
  "namespace": "default",
  "approved_id": "f491ec32"
}
```

审批令牌安全机制：

- **一次性消费**：`approved_id` 用一次即失效，重放返回 403
- **指纹匹配**：重试时 `action/resource/name/namespace` 必须与审批单一致，篡改返回 400
- **TTL 过期**：审批单 30 分钟未处理自动过期（404）

### 审批操作

```powershell
# 待审批列表（含每个单子要求的审批角色）
curl http://127.0.0.1:12001/approvals

# 批准 / 拒绝（审批人身份通过 X-Approver-Roles 头声明）
curl -X POST http://127.0.0.1:12001/approve/f491ec32 \
  -H "Content-Type: application/json" \
  -H "X-Approver-Roles: cluster-admin" \
  -d '{"approver": "sec-lead"}'

curl -X POST http://127.0.0.1:12001/reject/f491ec32 \
  -H "X-Approver-Roles: cluster-admin" \
  -d '{"approver": "sec-lead"}'
```

- 无身份头 → 401；角色不足（策略返回的 `required_roles` 与审批人角色无交集）→ 403

### 辅助端点

| 端点 | 说明 |
|------|------|
| `GET /health` | 网关健康检查 |
| `GET /api/status` | 网关 / OPA / Ollama 三方连通状态 |
| `GET /api/audit/recent?n=20` | 最近 N 条审计记录 |
| `GET /` | Web 控制台（模拟器 + 审批 + 审计实时刷新） |
| `ANY /{path}` | Ollama 透明代理（对工具调用请求自动走判定链路） |

## 策略规则（policy/authz.rego）

动作分类：

| 分类 | 动作 |
|------|------|
| 只读 | `get` `list` `describe` `logs` `watch` |
| 写 | `create` `apply` `patch` `update` `replace` |
| 删除 | `delete` `remove` `destroy` |
| 管理 | `bind-rbac` `scale` `rollout-restart` |

判定优先级（从高到低，首个命中即生效）：

| 条件 | 决策 | 风险 |
|------|------|------|
| 1 小时内操作次数 > 20 | deny | high |
| 系统命名空间（kube-system 等）+ 写/删 | deny | high |
| 受保护资源（`chainshield.io/protected` 标签）+ 删 | deny | high |
| 生产环境 + 删 | deny | high |
| 高危操作（删/管理）且非工作时间（9-18 点）且无 cluster-admin | deny | high |
| 管理操作且无 cluster-admin 角色 | deny | high |
| 管理操作 | 需审批 | high |
| 生产写 + cluster-admin 角色 | allow | low |
| 生产写 | 需审批 | high |
| 写 / 删 | 需审批 | medium |
| 系统命名空间只读 + operator/admin 角色 | allow | low |
| 普通只读 | allow | low |
| 未覆盖的操作 | deny | high |

需审批的策略会返回 `required_roles`（如 `["cluster-admin"]`），审批端点据此校验审批人角色。

## 测试

```powershell
# 策略测试（15 条）
.\opa.exe test .\policy .\tests

# 网关编排测试（15 条：三态判定、审批闭环、防重放、鉴权、畸形输入）
python -m pytest tests -q
```

## 典型调用时序（Agent 接入示例）

```python
import requests

def safe_execute(tool_call: dict) -> dict:
    r = requests.post(
        "http://127.0.0.1:12001/api/v1/evaluate",
        json=tool_call,
        headers={"X-User-Roles": "operator"},
        timeout=15,
    )
    if r.status_code == 200:
        return do_k8s_operation(tool_call)      # 放行，真正执行
    if r.status_code == 202:
        approval_id = r.json()["approval_id"]
        notify_human(approval_id)               # 通知人工在面板/接口审批
        r2 = requests.post(
            "http://127.0.0.1:12001/api/v1/evaluate",
            json={**tool_call, "approved_id": approval_id},
            headers={"X-User-Roles": "operator"},
            timeout=15,
        )
        if r2.status_code == 200:
            return do_k8s_operation(tool_call)  # 批准后放行
        raise PermissionError(r2.json())        # 403 拒绝 / 404 过期
    raise PermissionError(r.json())             # 403 直接拦截
```

## 已知限制

- **身份是自报的**：`X-User-Roles` / `X-Approver-Roles` 由调用方声明，未接 JWT 验签或 mTLS，生产部署需在网关层前置认证或改为验证签名令牌
- **K8s 为 mock**：`k8s_client.py` 返回预置数据，未接真实集群；资源不存在（`found=false`）时仍按请求参数评估
- **审批队列在内存**：网关重启丢单，多 worker 不共享，生产需 Redis/SQLite 持久化
- **OPA 调用无显式超时**：OPA 挂起时 `/api/v1/evaluate` 可能长时间等待（fail-closed 异常分支依赖连接错误触发）
- **`/reject` 不校验角色**：任何携带身份头的用户可拒绝待审批单（approve 有校验）
- **透传代理与 PDP 双链路**：ban.txt 关键词仅对透传路径生效，`/api/v1/evaluate` 不检查，建议统一收敛到 Rego
- **审计 fire-and-forget**：进程退出时在途写盘任务可能丢失，多线程 append 无文件锁
