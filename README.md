# Magento MCP Gateway — Phase 1–6 Combined

Universal Magento MCP gateway with:

- Streamable HTTP MCP at `/mcp`
- OAuth 2.1 authorization-code + PKCE S256
- ChatGPT MCP discovery metadata
- CIMD-compatible client identification metadata
- Persistent OAuth authorization codes
- Persistent Magento connections
- Fernet encryption for Magento Integration Access Tokens
- User/tenant isolation through OAuth subject + tenant ID
- RBAC for read/write tools
- Human approval for product description updates
- Legacy `TENANTS_JSON` migration fallback
- SQLite locally / PostgreSQL recommended for production

## Local

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Set `MCP_RESOURCE_URL=http://localhost:8000/mcp` and `OAUTH_ISSUER_URL=http://localhost:8000` for local browser/API testing. ChatGPT itself needs a public HTTPS endpoint; use a tunnel for development or deploy to Render.

## Render

Set:

```text
MCP_RESOURCE_URL=https://<service>.onrender.com/mcp
OAUTH_ISSUER_URL=https://<service>.onrender.com
OAUTH_ALLOWED_REDIRECT_URIS=<exact ChatGPT redirect URI>
OAUTH_SIGNING_SECRET=<strong random secret>
DATABASE_URL=<PostgreSQL URL>
CONNECTION_ENCRYPTION_KEY=<Fernet key>
```

Then add the custom MCP server in ChatGPT using the public `/mcp` URL and OAuth authentication.

## Important

The gateway expects a Magento Integration Access Token from the store owner/admin. It validates the token against `/rest/V1/store/storeConfigs`, encrypts it at rest, and uses it only for downstream Magento API calls.
