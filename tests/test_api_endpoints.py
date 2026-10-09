import time
import jwt
import pytest
from starlette.testclient import TestClient
from app.main import app, approvals
from app.config import get_settings

@pytest.fixture
def client():
    return TestClient(app)

def create_test_token(role="admin", tenant_id="tenant_123", subject="admin_user"):
    settings = get_settings()
    secret = settings.oauth_signing_secret or settings.dev_jwt_secret
    now = int(time.time())
    payload = {
        "iss": settings.oauth_issuer_url.rstrip("/"),
        "sub": subject,
        "aud": settings.mcp_resource_url,
        "tenant_id": tenant_id,
        "role": role,
        "scope": "magento.read magento.write",
        "client_id": "test_client",
        "iat": now,
        "exp": now + 3600,
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "version" in data

def test_approve_endpoint_authorization_checks(client):
    # 1. Without token -> 401/403
    res = client.post("/approvals/fake-id/approve")
    assert res.status_code in (401, 403)

    # 2. With support_agent role (not admin/cms_admin) -> 403
    agent_token = create_test_token(role="support_agent", tenant_id="tenant_123")
    res = client.post(
        "/approvals/fake-id/approve",
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert res.status_code == 403
    assert "Admin approval required" in res.text

    # 3. With admin token but non-existent approval -> 404
    admin_token = create_test_token(role="admin", tenant_id="tenant_123")
    res = client.post(
        "/approvals/fake-id/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 404

    # 4. Create an approval under tenant_123
    approval = approvals.create(
        tenant_id="tenant_123",
        subject="agent_1",
        tool="update_product_description",
        params={"sku": "SKU-99", "description": "desc"},
    )

    # 5. Admin from another tenant -> 403 tenant mismatch
    other_tenant_admin = create_test_token(role="admin", tenant_id="other_tenant")
    res = client.post(
        f"/approvals/{approval.approval_id}/approve",
        headers={"Authorization": f"Bearer {other_tenant_admin}"},
    )
    assert res.status_code == 403
    assert "belongs to another tenant" in res.text

    # 6. Admin from correct tenant -> 200 Approved
    res = client.post(
        f"/approvals/{approval.approval_id}/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["approval_id"] == approval.approval_id
    assert res_data["approved"] is True
