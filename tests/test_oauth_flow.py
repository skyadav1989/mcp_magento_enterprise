import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch, AsyncMock
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.config import get_settings

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge

def test_well_known_metadata(client):
    settings = get_settings()

    res = client.get("/.well-known/oauth-protected-resource")
    assert res.status_code == 200
    data = res.json()
    assert data["resource"] == settings.mcp_resource_url
    assert settings.oauth_issuer_url.rstrip("/") in data["authorization_servers"]

    res_auth = client.get("/.well-known/oauth-authorization-server")
    assert res_auth.status_code == 200
    auth_data = res_auth.json()
    assert auth_data["issuer"] == settings.oauth_issuer_url.rstrip("/")
    assert "authorization_code" in auth_data["grant_types_supported"]
    assert "S256" in auth_data["code_challenge_methods_supported"]

def test_oauth_authorize_get_validation(client, pkce_pair):
    settings = get_settings()
    allowed_redirect = settings.oauth_allowed_redirect_uris.split(",")[0].strip()
    _, code_challenge = pkce_pair

    # Missing parameters
    res = client.get("/oauth/authorize")
    assert res.status_code == 400

    # Unregistered redirect_uri
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test_client",
            "redirect_uri": "https://evil.com/callback",
            "response_type": "code",
            "code_challenge": code_challenge,
            "resource": settings.mcp_resource_url,
        },
    )
    assert res.status_code == 400
    assert "Unregistered redirect_uri" in res.text

    # Valid GET returns HTML form
    res = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test_client",
            "redirect_uri": allowed_redirect,
            "response_type": "code",
            "code_challenge": code_challenge,
            "resource": settings.mcp_resource_url,
        },
    )
    assert res.status_code == 200
    assert "Connect Magento" in res.text

def test_oauth_full_pkce_flow(client, pkce_pair):
    settings = get_settings()
    allowed_redirect = settings.oauth_allowed_redirect_uris.split(",")[0].strip()
    code_verifier, code_challenge = pkce_pair
    client_id = "test-agent-client-id"

    validation_mock = {
        "reachable": True,
        "status_code": 200,
        "store_url": "https://magento.test.local",
        "magento_version": "2.4.6",
    }

    with patch("app.oauth_server.validate_magento_url", new_callable=AsyncMock, return_value=validation_mock), \
         patch("app.services.magento_connection.validate_magento_url", new_callable=AsyncMock, return_value=validation_mock):
        # 1. Authorize POST
        auth_res = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": allowed_redirect,
                "response_type": "code",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "resource": settings.mcp_resource_url,
                "store_url": "https://magento.test.local",
                "magento_token": "test-integration-token-xyz",
                "state": "random-state-1234",
            },
            follow_redirects=False,
        )

        assert auth_res.status_code == 303
        redirect_url = auth_res.headers.get("location")
        assert redirect_url is not None
        assert redirect_url.startswith(allowed_redirect)

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        assert "code" in params
        assert params.get("state") == ["random-state-1234"]
        auth_code = params["code"][0]

        # 2. Token Exchange with Invalid PKCE Verifier should fail
        fail_res = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code,
                "code_verifier": "wrong-verifier",
            },
        )
        assert fail_res.status_code == 400
        assert fail_res.json()["error"] == "invalid_grant"

    # 3. New auth code with correct verifier
    with patch("app.oauth_server.validate_magento_url", new_callable=AsyncMock, return_value=validation_mock), \
         patch("app.services.magento_connection.validate_magento_url", new_callable=AsyncMock, return_value=validation_mock):
        auth_res2 = client.post(
            "/oauth/authorize",
            data={
                "client_id": client_id,
                "redirect_uri": allowed_redirect,
                "response_type": "code",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "resource": settings.mcp_resource_url,
                "store_url": "https://magento.test.local",
                "magento_token": "test-integration-token-xyz",
            },
            follow_redirects=False,
        )
        auth_code2 = parse_qs(urlparse(auth_res2.headers["location"]).query)["code"][0]

        token_res = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": auth_code2,
                "code_verifier": code_verifier,
            },
        )
        assert token_res.status_code == 200
        token_data = token_res.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert token_data["expires_in"] == settings.oauth_access_token_ttl_seconds
