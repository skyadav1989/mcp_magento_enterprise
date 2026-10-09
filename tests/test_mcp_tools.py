import ast
from unittest.mock import patch, AsyncMock
import pytest
import mcp.types as t
from mcp.server.auth.provider import AccessToken

from app.mcp_server import build_server
from app.approvals import ApprovalStore
from app.magento import TenantConfig

def make_token(role="admin", tenant_id="test_tenant", subject="test_user"):
    return AccessToken(
        token="jwt-token",
        client_id="chatgpt",
        scopes=["magento.read", "magento.write"],
        expires_at=9999999999,
        issuer="http://localhost:8000",
        subject=subject,
        resource="http://localhost:8000/mcp",
        claims={"tenant_id": tenant_id, "role": role},
    )

@pytest.fixture
def approvals():
    return ApprovalStore()

@pytest.fixture
def server(approvals):
    return build_server(approvals=approvals)

@pytest.mark.anyio
async def test_mcp_list_tools(server):
    list_handler = server.request_handlers[t.ListToolsRequest]

    # 1. Unauthenticated -> empty
    with patch("app.mcp_server.get_access_token", return_value=None):
        res = await list_handler(t.ListToolsRequest(method="tools/list"))
        assert res.root.tools == []

    # 2. Support agent role -> only get_orders_by_status
    agent_tok = make_token(role="support_agent")
    with patch("app.mcp_server.get_access_token", return_value=agent_tok):
        res = await list_handler(t.ListToolsRequest(method="tools/list"))
        tools = [t.name for t in res.root.tools]
        assert tools == ["get_orders_by_status"]

    # 3. Admin role -> both tools
    admin_tok = make_token(role="admin")
    with patch("app.mcp_server.get_access_token", return_value=admin_tok):
        res = await list_handler(t.ListToolsRequest(method="tools/list"))
        tools = [t.name for t in res.root.tools]
        assert "get_orders_by_status" in tools
        assert "update_product_description" in tools

@pytest.mark.anyio
async def test_mcp_call_tool_unauthenticated_and_rbac(server):
    call_handler = server.request_handlers[t.CallToolRequest]

    # 1. Unauthenticated
    with patch("app.mcp_server.get_access_token", return_value=None):
        req = t.CallToolRequest(
            method="tools/call",
            params=t.CallToolRequestParams(name="get_orders_by_status", arguments={"status": "pending"}),
        )
        res = await call_handler(req)
        assert "Authentication required" in res.root.content[0].text

    # 2. Support agent calling update_product_description -> Not permitted
    agent_tok = make_token(role="support_agent")
    with patch("app.mcp_server.get_access_token", return_value=agent_tok):
        req = t.CallToolRequest(
            method="tools/call",
            params=t.CallToolRequestParams(
                name="update_product_description",
                arguments={"sku": "TEST", "description": "desc"},
            ),
        )
        res = await call_handler(req)
        assert "not permitted" in res.root.content[0].text

@pytest.mark.anyio
async def test_mcp_call_tool_get_orders(server):
    call_handler = server.request_handlers[t.CallToolRequest]
    admin_tok = make_token(role="admin")
    fake_config = TenantConfig(base_url="https://magento.test", token="secret")

    mock_orders = {
        "total_count": 1,
        "orders": [{"entity_id": 101, "increment_id": "000000101", "status": "processing"}],
    }

    with patch("app.mcp_server.get_access_token", return_value=admin_tok), \
         patch("app.mcp_server.TenantRegistry.get", return_value=fake_config), \
         patch("app.mcp_server.MagentoClient.get_orders_by_status", new_callable=AsyncMock, return_value=mock_orders):

        req = t.CallToolRequest(
            method="tools/call",
            params=t.CallToolRequestParams(
                name="get_orders_by_status",
                arguments={"status": "processing", "page_size": 10},
            ),
        )
        res = await call_handler(req)
        assert "000000101" in res.root.content[0].text

@pytest.mark.anyio
async def test_mcp_update_product_approval_flow(server, approvals):
    call_handler = server.request_handlers[t.CallToolRequest]
    admin_tok = make_token(role="admin", tenant_id="test_tenant", subject="admin_user")
    fake_config = TenantConfig(base_url="https://magento.test", token="secret")

    with patch("app.mcp_server.get_access_token", return_value=admin_tok), \
         patch("app.mcp_server.TenantRegistry.get", return_value=fake_config):

        # 1. Initial call without approval_id -> triggers approval requirement
        req = t.CallToolRequest(
            method="tools/call",
            params=t.CallToolRequestParams(
                name="update_product_description",
                arguments={"sku": "SKU-PROD-1", "description": "High performance widget"},
            ),
        )
        res = await call_handler(req)
        res_text = res.root.content[0].text
        data = ast.literal_eval(res_text)
        assert data["approval_required"] is True
        approval_id = data["approval_id"]

        # 2. Call with approval_id before approval granted -> rejected
        req_with_id = t.CallToolRequest(
            method="tools/call",
            params=t.CallToolRequestParams(
                name="update_product_description",
                arguments={
                    "sku": "SKU-PROD-1",
                    "description": "High performance widget",
                    "approval_id": approval_id,
                },
            ),
        )
        res_unapproved = await call_handler(req_with_id)
        assert "Invalid, expired, or already consumed approval" in res_unapproved.root.content[0].text

        # 3. Approve it
        approvals.approve(approval_id)

        # 4. Call with approval_id after approval -> successfully calls MagentoClient
        mock_result = {
            "sku": "SKU-PROD-1",
            "name": "Widget",
            "message": "Product description updated successfully",
        }
        with patch("app.mcp_server.MagentoClient.update_product_description", new_callable=AsyncMock, return_value=mock_result):
            res_approved = await call_handler(req_with_id)
            assert "Product description updated successfully" in res_approved.root.content[0].text
