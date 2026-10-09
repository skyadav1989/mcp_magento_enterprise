"""Phase 5 Magento API client with safe Integration Bearer authentication."""
from urllib.parse import quote
import httpx
from .crypto import decrypt
from ..db.models import MagentoConnection

class SecureMagentoClient:
    def __init__(self, connection: MagentoConnection, timeout: float = 30.0):
        self.connection = connection
        self.timeout = timeout

    def _headers(self):
        return {'Authorization': f'Bearer {decrypt(self.connection.encrypted_access_token)}', 'Accept':'application/json', 'Content-Type':'application/json'}

    def _client(self):
        return httpx.AsyncClient(base_url=self.connection.store_url.rstrip('/'), timeout=self.timeout, headers=self._headers())

    async def get(self, path: str, **kwargs):
        async with self._client() as client:
            response = await client.get(path, **kwargs)
            response.raise_for_status()
            return response.json()

    async def put(self, path: str, payload: dict):
        async with self._client() as client:
            response = await client.put(path, json=payload)
            response.raise_for_status()
            return response.json()

    async def product(self, sku: str):
        return await self.get(f'/rest/V1/products/{quote(sku, safe="")}')
