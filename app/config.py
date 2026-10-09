from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    app_name: str = 'Magento MCP Gateway'
    app_version: str = '1.1.0'
    host: str = '0.0.0.0'
    port: int = 10000

    # Canonical public MCP resource URL, normally https://<render-host>/mcp
    mcp_resource_url: str = 'http://localhost:8000/mcp'

    # OAuth 2.1 authorization server operated by this gateway for the MVP.
    # Production recommendation: move authorization to Auth0/Okta/Entra/etc.
    oauth_issuer_url: str = 'http://localhost:8000'
    oauth_allowed_redirect_uris: str = 'https://chatgpt.com/connector_platform_oauth_redirect'
    oauth_scopes: str = 'magento.read magento.write'
    oauth_access_token_ttl_seconds: int = 3600
    oauth_code_ttl_seconds: int = 300
    oauth_state_ttl_seconds: int = 600
    oauth_signing_secret: str = ''

    # Development-only fallback for the existing prototype.
    jwt_audience: str = ''
    jwt_jwks_url: str = ''
    jwt_algorithms: str = 'HS256'
    dev_jwt_secret: str = ''

    # Existing static tenants remain supported during migration.
    tenants_json: str = '{}'

    # Update protection
    require_product_update_approval: bool = True
    max_description_length: int = 5000
    approval_ttl_seconds: int = 600
    http_timeout_seconds: float = 30.0

    # CORS / transport security
    allowed_origins: str = ''
    allowed_hosts: str = ''

    # Phase 1-5 persistence/security
    database_url: str = 'sqlite:///./magento_mcp.db'
    connection_encryption_key: str = ''


@lru_cache
def get_settings() -> Settings:
    return Settings()

# Phase 1-5 optional persistence/security settings are read through properties
# below so older deployments can continue using TENANTS_JSON.
