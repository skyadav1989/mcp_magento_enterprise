from app.rbac import ROLE_TOOLS, allowed_tools, can_use, tenant_and_role
from unittest.mock import Mock

def test_rbac_roles_tools():
    assert "get_orders_by_status" in allowed_tools("support_agent")
    assert "update_product_description" not in allowed_tools("support_agent")

    assert "get_orders_by_status" in allowed_tools("cms_admin")
    assert "update_product_description" in allowed_tools("cms_admin")

    assert "get_orders_by_status" in allowed_tools("admin")
    assert "update_product_description" in allowed_tools("admin")

    assert allowed_tools("unknown_role") == set()

def test_can_use():
    assert can_use("admin", "get_orders_by_status") is True
    assert can_use("admin", "update_product_description") is True
    assert can_use("support_agent", "update_product_description") is False
    assert can_use("unknown", "get_orders_by_status") is False

def test_tenant_and_role():
    assert tenant_and_role(None) == (None, None)

    token = Mock()
    token.claims = {"tenant_id": "tenant_123", "role": "cms_admin"}
    tenant, role = tenant_and_role(token)
    assert tenant == "tenant_123"
    assert role == "cms_admin"

    # Default fallback
    token.claims = {"tenant_id": "tenant_456"}
    tenant, role = tenant_and_role(token)
    assert tenant == "tenant_456"
    assert role == "support_agent"
