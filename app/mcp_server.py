from typing import Any
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import Route

from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.fastmcp.server import StreamableHTTPASGIApp, RequireAuthMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from starlette.middleware.authentication import AuthenticationMiddleware
from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.provider import TokenVerifier
from mcp.server.transport_security import TransportSecuritySettings

from .approvals import ApprovalStore
from .config import get_settings
from .db.database import SessionLocal
from .magento import MagentoClient, TenantRegistry
from .rbac import allowed_tools, can_use, tenant_and_role


class GatewayServer(Server):
    """MCP Server with Streamable HTTP Starlette app integration."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._session_manager: StreamableHTTPSessionManager | None = None

    @property
    def session_manager(self) -> StreamableHTTPSessionManager:
        if self._session_manager is None:
            raise RuntimeError(
                "Session manager can only be accessed after calling streamable_http_app()."
            )
        return self._session_manager

    def streamable_http_app(
        self,
        streamable_http_path: str = "/mcp",
        stateless_http: bool = False,
        json_response: bool = False,
        auth: AuthSettings | None = None,
        token_verifier: TokenVerifier | None = None,
        transport_security: TransportSecuritySettings | None = None,
        debug: bool = False,
        **kwargs: Any,
    ) -> Starlette:
        if self._session_manager is None:
            self._session_manager = StreamableHTTPSessionManager(
                app=self,
                json_response=json_response,
                stateless=stateless_http,
                security_settings=transport_security,
            )

        streamable_http_asgi = StreamableHTTPASGIApp(self._session_manager)

        routes: list[Route] = []
        middleware: list[Middleware] = []
        required_scopes: list[str] = []

        if auth:
            required_scopes = auth.required_scopes or []

            if token_verifier:
                middleware = [
                    Middleware(
                        AuthenticationMiddleware,
                        backend=BearerAuthBackend(
                            token_verifier,
                            resource_server_url=(
                                auth.resource_server_url
                                if auth.validate_token_resource
                                else None
                            ),
                        ),
                    ),
                    Middleware(AuthContextMiddleware),
                ]

        routes.append(
            Route(
                streamable_http_path,
                endpoint=streamable_http_asgi,
            )
        )

        if auth and auth.resource_server_url:
            routes.extend(
                create_protected_resource_routes(
                    resource_url=auth.resource_server_url,
                    authorization_servers=[auth.issuer_url],
                    scopes_supported=auth.required_scopes,
                )
            )

        return Starlette(
            debug=debug,
            routes=routes,
            middleware=middleware,
            lifespan=lambda app: self.session_manager.run(),
        )


TOOL_DEFINITIONS = {
    "get_orders_by_status": Tool(
        name="get_orders_by_status",
        description=(
            "Get Magento orders for the authenticated Magento store "
            "filtered by order status."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Magento order status.",
                },
                "page_size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20,
                },
            },
            "required": ["status"],
        },
    ),

    "update_product_description": Tool(
        name="update_product_description",
        description=(
            "Update a Magento product description. "
            "This operation requires approval when approval "
            "workflow is enabled."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "sku": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "description": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 5000,
                },
                "approval_id": {
                    "type": "string",
                },
            },
            "required": [
                "sku",
                "description",
            ],
        },
    ),
}


def build_server(
    approvals_or_verifier: Any = None,
    approvals: ApprovalStore | None = None,
) -> GatewayServer:

    settings = get_settings()

    if isinstance(approvals_or_verifier, ApprovalStore):
        store = approvals_or_verifier
    elif approvals is not None:
        store = approvals
    elif approvals_or_verifier is not None and hasattr(approvals_or_verifier, "create"):
        store = approvals_or_verifier
    else:
        store = ApprovalStore()

    approvals = store

    # Phase 6 resolves connections directly from the database,
    # with TenantRegistry providing backwards compatibility.
    tenants = TenantRegistry(db_factory=SessionLocal)

    server = GatewayServer(
        "Magento MCP Gateway",
        version=settings.app_version,
        instructions=(
            "Secure multi-tenant MCP gateway for Magento."
        ),
    )

    @server.list_tools()
    async def list_tools() -> list[Tool]:

        token = get_access_token()

        if not token:
            return []

        _, role = tenant_and_role(token)

        if not role:
            return []

        names = allowed_tools(role)

        return [
            TOOL_DEFINITIONS[name]
            for name in TOOL_DEFINITIONS
            if name in names
        ]

    @server.call_tool()
    async def call_tool(
        name: str,
        arguments: dict,
    ):

        token = get_access_token()
        print(f"[MCP DEBUG] Tool: {name}")
        print(f"[MCP DEBUG] Access token available: {token is not None}")

        if token is None:
            print("[MCP DEBUG] Auth context has no access token")
            return [
                TextContent(
                    type="text",
                    text="Authentication required."
                )
            ]

        tenant_id, role = tenant_and_role(token)

        if not token:
            return [
                TextContent(
                    type="text",
                    text="Authentication required.",
                )
            ]

        tenant_id, role = tenant_and_role(token)

        if not tenant_id:
            return [
                TextContent(
                    type="text",
                    text="Tenant not found.",
                )
            ]

        if not can_use(role or "", name):
            return [
                TextContent(
                    type="text",
                    text=f"Tool '{name}' is not permitted.",
                )
            ]

        arguments = arguments or {}

        try:

            # --------------------------------------------------
            # Resolve Magento tenant
            # --------------------------------------------------

            tenant = tenants.get(tenant_id, token.subject)

            if not tenant:
                return [
                    TextContent(
                        type="text",
                        text=f"No active Magento connection for tenant '{tenant_id}'.",
                    )
                ]

            client = MagentoClient(tenant)

            # --------------------------------------------------
            # GET ORDERS
            # --------------------------------------------------

            if name == "get_orders_by_status":

                status = str(
                    arguments.get("status", "")
                ).strip()

                if not status:
                    raise ValueError(
                        "status is required"
                    )

                page_size = int(
                    arguments.get(
                        "page_size",
                        20,
                    )
                )

                if page_size < 1 or page_size > 100:
                    raise ValueError(
                        "page_size must be between 1 and 100"
                    )

                result = await client.get_orders_by_status(
                    status=status,
                    page_size=page_size,
                )

                return [
                    TextContent(
                        type="text",
                        text=str(result),
                    )
                ]

            # --------------------------------------------------
            # UPDATE PRODUCT DESCRIPTION
            # --------------------------------------------------

            if name == "update_product_description":

                sku = str(
                    arguments.get("sku", "")
                ).strip()

                description = str(
                    arguments.get(
                        "description",
                        "",
                    )
                )

                if not sku:
                    raise ValueError(
                        "sku is required"
                    )

                if not description:
                    raise ValueError(
                        "description is required"
                    )

                if len(description) > settings.max_description_length:
                    raise ValueError(
                        "description exceeds maximum allowed length"
                    )

                # ----------------------------------------------
                # Approval workflow
                # ----------------------------------------------

                if settings.require_product_update_approval:

                    approval_id = arguments.get(
                        "approval_id"
                    )

                    if not approval_id:

                        approval = approvals.create(
                            tenant_id=tenant_id,
                            subject=token.subject,
                            tool=name,
                            params={
                                "sku": sku,
                                "description": description,
                            },
                        )

                        return [
                            TextContent(
                                type="text",
                                text=str(
                                    {
                                        "approval_required": True,
                                        "approval_id": (
                                            approval.approval_id
                                        ),
                                        "expires_at": (
                                            approval.expires_at
                                        ),
                                        "message": (
                                            "Human approval is "
                                            "required before the "
                                            "product description "
                                            "can be updated."
                                        ),
                                    }
                                ),
                            )
                        ]

                    # ------------------------------------------
                    # Validate approval
                    # ------------------------------------------

                    approved = approvals.consume(
                        approval_id,
                        tenant_id,
                        token.subject,
                        name,
                        {
                            "sku": sku,
                            "description": description,
                        },
                    )

                    if not approved:
                        raise PermissionError(
                            "Invalid, expired, or already "
                            "consumed approval."
                        )

                # ----------------------------------------------
                # Magento update
                # ----------------------------------------------

                result = await client.update_product_description(
                    sku=sku,
                    description=description,
                )

                return [
                    TextContent(
                        type="text",
                        text=str(result),
                    )
                ]

            # --------------------------------------------------
            # UNKNOWN TOOL
            # --------------------------------------------------

            raise ValueError(
                f"Unknown tool: {name}"
            )

        except Exception as exc:

            return [
                TextContent(
                    type="text",
                    text=f"Operation failed: {exc}",
                )
            ]

    return server