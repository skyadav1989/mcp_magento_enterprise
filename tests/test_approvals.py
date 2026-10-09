import pytest
import time
from app.approvals import ApprovalStore

def test_approval_lifecycle():
    store = ApprovalStore()
    params = {"sku": "TEST-SKU", "description": "New description"}
    approval = store.create(
        tenant_id="tenant_1",
        subject="agent_1",
        tool="update_product_description",
        params=params,
    )

    assert approval.approval_id is not None
    assert approval.approved is False
    assert approval.tenant_id == "tenant_1"

    # Cannot consume before being approved
    consumed = store.consume(
        approval.approval_id,
        "tenant_1",
        "agent_1",
        "update_product_description",
        params,
    )
    assert consumed is False

    # Approve
    approved_obj = store.approve(approval.approval_id)
    assert approved_obj.approved is True

    # Reject consumption if tenant mismatch
    assert store.consume(
        approval.approval_id,
        "tenant_2",
        "agent_1",
        "update_product_description",
        params,
    ) is False

    # Reject consumption if param mismatch
    assert store.consume(
        approval.approval_id,
        "tenant_1",
        "agent_1",
        "update_product_description",
        {"sku": "OTHER-SKU", "description": "tampered"},
    ) is False

    # Successful consumption
    assert store.consume(
        approval.approval_id,
        "tenant_1",
        "agent_1",
        "update_product_description",
        params,
    ) is True

    # Consuming again fails (one-time use)
    assert store.consume(
        approval.approval_id,
        "tenant_1",
        "agent_1",
        "update_product_description",
        params,
    ) is False

def test_approval_expiration():
    store = ApprovalStore()
    approval = store.create("t1", "s1", "update_product_description", {})
    # Manually expire
    approval.expires_at = time.time() - 1

    with pytest.raises(KeyError, match="Approval not found or expired"):
        store.get(approval.approval_id)

    assert store.consume(approval.approval_id, "t1", "s1", "update_product_description", {}) is False
