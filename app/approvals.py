import secrets
import time
from dataclasses import dataclass

from .config import get_settings


@dataclass
class Approval:
    approval_id: str
    tenant_id: str
    subject: str | None
    tool: str
    params: dict
    expires_at: float
    approved: bool = False


class ApprovalStore:
    def __init__(self) -> None:
        self._items: dict[str, Approval] = {}

    def create(
        self,
        tenant_id: str,
        subject: str | None,
        tool: str = "",
        params: dict | None = None,
        **kwargs,
    ) -> Approval:
        tool_val = tool or kwargs.get("tool_name", "")
        params_val = params if params is not None else kwargs.get("arguments", {})
        approval = Approval(
            approval_id=secrets.token_urlsafe(18),
            tenant_id=tenant_id,
            subject=subject,
            tool=tool_val,
            params=params_val,
            expires_at=time.time() + get_settings().approval_ttl_seconds,
        )
        self._items[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> Approval:
        item = self._items.get(approval_id)
        if not item or item.expires_at < time.time():
            raise KeyError('Approval not found or expired')
        return item

    def approve(self, approval_id: str) -> Approval:
        item = self.get(approval_id)
        item.approved = True
        return item

    def consume(self, approval_id: str, tenant_id: str, subject: str | None, tool: str, params: dict) -> bool:
        item = self._items.get(approval_id)
        if not item or item.expires_at < time.time() or not item.approved:
            return False
        if item.tenant_id != tenant_id or item.subject != subject or item.tool != tool:
            return False
        if item.params != params:
            return False
        del self._items[approval_id]
        return True

    def list_all(self) -> list[Approval]:
        now = time.time()
        # Clean expired
        expired = [k for k, v in self._items.items() if v.expires_at < now]
        for k in expired:
            del self._items[k]
        return sorted(self._items.values(), key=lambda a: a.expires_at, reverse=True)
