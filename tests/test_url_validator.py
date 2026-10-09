import pytest
from unittest.mock import patch, AsyncMock
import httpx
from app.services.url_validator import validate_magento_url

@pytest.mark.anyio
async def test_invalid_scheme():
    with pytest.raises(ValueError, match="Store URL must be a valid http"):
        await validate_magento_url("ftp://example.com")

@pytest.mark.anyio
async def test_url_with_embedded_credentials():
    with pytest.raises(ValueError, match="Store URL must not contain credentials"):
        await validate_magento_url("https://user:pass@example.com")

@pytest.mark.anyio
async def test_url_missing_netloc():
    with pytest.raises(ValueError):
        await validate_magento_url("http://")

@pytest.mark.anyio
async def test_url_network_error():
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused")):
        result = await validate_magento_url("https://unreachable.example.com")
        assert result["reachable"] is False
        assert result["status_code"] == 0
        assert "error" in result

@pytest.mark.anyio
async def test_url_success():
    mock_response = httpx.Response(
        status_code=200,
        json=[{"id": 1, "code": "default"}],
        headers={"x-magento-version": "2.4.6"},
    )
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
        result = await validate_magento_url("https://mystore.example.com", access_token="token123")
        assert result["reachable"] is True
        assert result["status_code"] == 200
        assert result["magento_version"] == "2.4.6"
        assert result["store_configs"] == [{"id": 1, "code": "default"}]
