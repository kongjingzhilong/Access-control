import uuid
import time
from dataclasses import dataclass,field
from typing import Optional
DEFAULT_TTL=1800
@dataclass
class ApprovalItem:
    id:str
    agent_input:dict
    k8s_info:dict
    opa_result:dict
    created_at:float=field(default_factory=time.time)
    status:str="pending"
    resolved_at:Optional[float]=None
    approver:Optional[str]=None
    consumed:bool=False
    consumed_at:Optional[float]=None
class ApprovalQueue:
    def __init__(self,ttl:int=DEFAULT_TTL):
        self._items:dict[str,ApprovalItem]={}
        self._ttl=ttl
    def _expired(self,item:ApprovalItem)->bool:
        return item.status=="pending" and time.time()-item.created_at>self._ttl
    def create(self,agent_input:dict,k8s_info:dict,opa_result:dict)->ApprovalItem:
        item=ApprovalItem(
            id=str(uuid.uuid4())[:8],
            agent_input=agent_input,
            k8s_info=k8s_info,
            opa_result=opa_result
        )
        self._items[item.id]=item
        return item
    def get(self,approval_id:str)->Optional[ApprovalItem]:
        item=self._items.get(approval_id)
        if item is None:
            return None
        if self._expired(item):
            item.status="expired"
            return None
        return item
    def list_pending(self)->list[ApprovalItem]:
        result=[]
        for item in self._items.values():
            if item.status=="pending" and not self._expired(item):
                result.append(item)
            elif item.status=="pending":
                item.status="expired"
        return result
    def approve(self,approval_id:str,approver:str="unknown")->Optional[ApprovalItem]:
        item=self._items.get(approval_id)
        if item and item.status=="pending" and not self._expired(item):
            item.status="approved"
            item.resolved_at=time.time()
            item.approver=approver
            return item
        return None
    def reject(self,approval_id:str,approver:str="unknown")->Optional[ApprovalItem]:
        item=self._items.get(approval_id)
        if item and item.status=="pending" and not self._expired(item):
            item.status="rejected"
            item.resolved_at=time.time()
            item.approver=approver
            return item
        return None
    def matches(self,item:ApprovalItem,tool_call:dict)->bool:
        src=item.agent_input
        return all(src.get(k)==tool_call.get(k) for k in("action","resource","name","namespace"))
    def consume(self,approval_id:str)->Optional[ApprovalItem]:
        item=self._items.get(approval_id)
        if item and item.status=="approved" and not item.consumed:
            item.consumed=True
            item.consumed_at=time.time()
            return item
        return None
queue=ApprovalQueue()
