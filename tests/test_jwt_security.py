import time
import jwt
import pytest
from app.config import get_settings
from app.security import JWTVerifier

@pytest.fixture
def settings():
    return get_settings()

@pytest.fixture
def verifier():
    return JWTVerifier()

@pytest.mark.anyio
async def test_jwt_verification_valid_token(settings, verifier):
    secret = settings.oauth_signing_secret or settings.dev_jwt_secret
    now = int(time.time())
    payload = {
        "iss": settings.oauth_issuer_url.rstrip("/"),
        "sub": "user_42",
        "aud": settings.mcp_resource_url,
        "tenant_id": "tenant_abc",
        "role": "admin",
        "scope": "magento.read magento.write",
        "client_id": "chatgpt_client",
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    access_token = await verifier.verify_token(token)
    assert access_token is not None
    assert access_token.subject == "user_42"
    assert access_token.scopes == ["magento.read", "magento.write"]
    assert access_token.claims.get("tenant_id") == "tenant_abc"
    assert access_token.claims.get("role") == "admin"

@pytest.mark.anyio
async def test_jwt_verification_expired_token(settings, verifier):
    secret = settings.oauth_signing_secret or settings.dev_jwt_secret
    now = int(time.time())
    payload = {
        "iss": settings.oauth_issuer_url.rstrip("/"),
        "sub": "user_42",
        "aud": settings.mcp_resource_url,
        "tenant_id": "tenant_abc",
        "iat": now - 7200,
        "exp": now - 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    result = await verifier.verify_token(token)
    assert result is None

@pytest.mark.anyio
async def test_jwt_verification_invalid_signature(settings, verifier):
    now = int(time.time())
    payload = {
        "iss": settings.oauth_issuer_url.rstrip("/"),
        "sub": "user_42",
        "aud": settings.mcp_resource_url,
        "tenant_id": "tenant_abc",
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, "wrong-secret-key-123456-very-long-secret-key", algorithm="HS256")
    result = await verifier.verify_token(token)
    assert result is None

@pytest.mark.anyio
async def test_jwt_verification_wrong_audience(settings, verifier):
    secret = settings.oauth_signing_secret or settings.dev_jwt_secret
    now = int(time.time())
    payload = {
        "iss": settings.oauth_issuer_url.rstrip("/"),
        "sub": "user_42",
        "aud": "http://malicious-resource.com",
        "tenant_id": "tenant_abc",
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    result = await verifier.verify_token(token)
    assert result is None
