"""Phase 4 Magento authorization notes/helpers.

Magento Integration authorization is OAuth 1.0a. This module deliberately does
not pretend Magento is an OAuth 2.1 provider. For stores using pre-created
Integration access tokens, the gateway can accept and validate the token.
"""
from dataclasses import dataclass
from urllib.parse import urljoin
import httpx

@dataclass(frozen=True)
class MagentoCredential:
    store_url: str
    access_token: str

async def validate_integration_token(credential: MagentoCredential, timeout: float = 15.0) -> dict:
    base = credential.store_url.rstrip('/')
    async with httpx.AsyncClient(timeout=timeout, headers={'Authorization': f'Bearer {credential.access_token}', 'Accept':'application/json'}) as client:
        r = await client.get(urljoin(base + '/', 'rest/V1/store/storeConfigs'))
        r.raise_for_status()
        return {'valid': True, 'store_url': base, 'store_config': r.json()}
