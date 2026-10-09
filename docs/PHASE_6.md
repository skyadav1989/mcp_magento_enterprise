# Phase 6 — ChatGPT-ready DB-backed Magento connections

Phase 6 keeps the Phase 1–5 prototype and makes the universal connection path real.

## Flow

ChatGPT -> OAuth 2.1 + PKCE S256 -> Gateway -> persisted MagentoConnection -> encrypted Integration token -> Magento REST API.

The Magento Integration token is never stored in the ChatGPT JWT.

## What changed

- OAuth authorization codes are persisted in the database and are single-use.
- Magento connections are persisted in `magento_connections`.
- MCP tool calls resolve the connection by authenticated OAuth `sub` + `tenant_id`.
- The encrypted Magento Integration token is decrypted only when making the Magento request.
- OAuth metadata advertises PKCE S256, CIMD support, issuer identification, and `none` token endpoint authentication.
- MCP tools advertise OAuth security schemes and return an OAuth challenge when authentication/tool permission is missing.
- `/oauth/jwks.json` is provided for metadata compatibility; current MVP tokens are HS256 and are verified directly by the gateway.
- Legacy `TENANTS_JSON` remains as a migration fallback.

## Production requirements

Use PostgreSQL instead of SQLite, configure `CONNECTION_ENCRYPTION_KEY`, use a strong `OAUTH_SIGNING_SECRET`, configure the exact ChatGPT redirect URI shown in the MCP server management UI, and do not log Magento tokens.

OpenAI's current guidance recommends an established identity provider for production. This gateway's built-in OAuth server is intended for the MVP/dogfood phase; migrate authorization to an established IdP before broad production rollout if required by your security model.
