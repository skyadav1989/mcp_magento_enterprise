# Magento MCP Gateway — Combined Phase 1–5

This package combines the gateway foundation with the first five architecture phases.

## Phase 1 — Foundation
- FastAPI application
- MCP Streamable HTTP
- configuration and environment handling
- JWT/OAuth gateway authentication foundation
- database bootstrap

## Phase 2 — Users / Connections / Encryption
- user model
- Magento connection model
- encrypted Integration token storage using Fernet
- tenant ID derived per owner/store

## Phase 3 — Magento URL Validation / Connection API
- `POST /connections/validate`
- `POST /connections`
- HTTPS/http URL validation
- Magento REST endpoint reachability check

## Phase 4 — Magento Authorization
- explicit separation between ChatGPT OAuth 2.1 and Magento Integration authentication
- Integration-token validation helper
- no Magento credential is placed in the ChatGPT JWT

## Phase 5 — Magento Client
- secure Bearer header construction
- encrypted-token decryption only at API-call time
- generic GET/PUT helpers
- product lookup helper

The existing `app/oauth_server.py`, `app/security.py`, `app/mcp_server.py`, `app/approvals.py`, and `app/magento.py` remain intact from the working Render gateway.

### Production requirements
Set `CONNECTION_ENCRYPTION_KEY` to a Fernet key and `DATABASE_URL` to PostgreSQL. The current legacy `TENANTS_JSON` path remains available for backward compatibility.
