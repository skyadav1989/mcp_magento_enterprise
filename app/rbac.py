ROLE_TOOLS = {
    'support_agent': {'get_orders_by_status', 'get_product_by_sku', 'get_product_list'},
    'cms_admin': {
        'get_orders_by_status',
        'get_product_by_sku',
        'get_product_list',
        'update_product_description',
        'add_media_for_sku',
    },
    'admin': {
        'get_orders_by_status',
        'get_product_by_sku',
        'get_product_list',
        'update_product_description',
        'add_media_for_sku',
    },
}


def tenant_and_role(token):
    if not token:
        return None, None
    claims = token.claims or {}
    return claims.get('tenant_id'), claims.get('role', 'support_agent')


def allowed_tools(role: str) -> set[str]:
    return ROLE_TOOLS.get(role, set())


def can_use(role: str, tool_name: str) -> bool:
    return tool_name in allowed_tools(role)
