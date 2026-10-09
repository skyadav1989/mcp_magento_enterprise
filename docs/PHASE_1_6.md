# Phase 1–6 Combined

Phase 1–5 foundation is retained. Phase 6 completes the DB-backed identity-to-Magento path required for a universal MCP gateway.

## End-to-end request path

1. ChatGPT discovers `/.well-known/oauth-protected-resource`.
2. ChatGPT discovers the gateway OAuth metadata.
3. ChatGPT starts authorization-code + PKCE S256.
4. The user supplies the Magento Store URL and Integration Access Token on the gateway authorization page.
5. The gateway validates the Magento token, encrypts it with Fernet, and persists the connection.
6. The gateway issues a short-lived OAuth access token containing `sub`, `tenant_id`, `aud`, scopes, and no Magento secret.
7. MCP validates the access token for issuer, audience and expiry.
8. Each tool call resolves the active Magento connection by `tenant_id + subject`.
9. The encrypted Integration token is decrypted only for the outbound Magento request.

## ChatGPT compatibility

The implementation advertises:
- OAuth authorization code
- PKCE S256
- issuer identification (`iss`)
- CIMD support
- token endpoint auth method `none`
- protected resource metadata
- per-tool OAuth security schemes
- OAuth challenge metadata for missing authorization

The exact redirect URI should be copied from ChatGPT's MCP server management page and placed in `OAUTH_ALLOWED_REDIRECT_URIS`.

## Production note

The built-in OAuth server is suitable for MVP/dogfood testing. For broad production use, migrate the user identity/authorization portion to an established IdP that supports MCP OAuth requirements. PostgreSQL is supported through `DATABASE_URL`; SQLite remains the local default.
