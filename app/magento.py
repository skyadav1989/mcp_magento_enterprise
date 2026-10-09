import json
from dataclasses import dataclass
from urllib.parse import quote
import httpx
from .config import get_settings
from .services.connection_repository import get_connection
from .services.crypto import decrypt

@dataclass(frozen=True)
class TenantConfig:
    base_url: str
    token: str

class ConnectionStore:
    """Compatibility adapter for the legacy static tenant path."""
    def __init__(self):
        self._items = {}
    def tenant_id_for(self, store_url: str, subject: str) -> str:
        from .services.connection_repository import tenant_id_for
        return tenant_id_for(store_url, subject)
    def put(self, tenant_id: str, base_url: str, token: str):
        self._items[tenant_id] = TenantConfig(base_url.rstrip('/'), token)
    def get(self, tenant_id: str):
        return self._items.get(tenant_id)

class TenantRegistry:
    def __init__(self, db_factory=None, connections=None):
        self.db_factory = db_factory
        self.connections = connections
        raw = json.loads(get_settings().tenants_json or '{}')
        self._tenants = {k: TenantConfig(v['base_url'].rstrip('/'), v['token']) for k,v in raw.items()}

    def get_for_identity(self, tenant_id: str, subject: str) -> TenantConfig:
        if self.db_factory:
            db = self.db_factory()
            try:
                connection = get_connection(db, tenant_id, subject)
                if connection:
                    return TenantConfig(connection.store_url.rstrip('/'), decrypt(connection.encrypted_access_token))
            finally:
                db.close()
        if self.connections:
            dynamic = self.connections.get(tenant_id)
            if dynamic:
                return dynamic
        config = self._tenants.get(tenant_id)
        if not config:
            raise PermissionError('No active Magento connection for authenticated identity')
        return config

    def get(self, tenant_id: str, subject: str = "") -> TenantConfig | None:
        if subject:
            try:
                return self.get_for_identity(tenant_id, subject)
            except Exception:
                pass
        return self._tenants.get(tenant_id)

class MagentoClient:
    def __init__(self, config: TenantConfig):
        self.config = config
        self.timeout = get_settings().http_timeout_seconds
    def _client(self):
        return httpx.AsyncClient(base_url=self.config.base_url, timeout=self.timeout,
            headers={'Authorization': f'Bearer {self.config.token}', 'Accept':'application/json', 'Content-Type':'application/json'})
    async def get_orders_by_status(self, status: str, page_size: int = 20) -> dict:
        page_size = min(max(page_size, 1), 100)
        params = {'searchCriteria[filter_groups][0][filters][0][field]':'status', 'searchCriteria[filter_groups][0][filters][0][value]':status,
                  'searchCriteria[filter_groups][0][filters][0][condition_type]':'eq','searchCriteria[pageSize]':page_size,'searchCriteria[currentPage]':1}
        async with self._client() as client:
            response = await client.get('/rest/V1/orders', params=params); response.raise_for_status(); data=response.json()
        return {'total_count':data.get('total_count',0),'orders':[{k:item.get(k) for k in ('entity_id','increment_id','status','state','grand_total','created_at','customer_email')} for item in data.get('items',[])]}
    async def update_product_description(self, sku: str, description: str) -> dict:
        payload={'product':{'sku':sku,'custom_attributes':[{'attribute_code':'description','value':description}]}}
        async with self._client() as client:
            response=await client.put(f'/rest/V1/products/{quote(sku,safe="")}',json=payload); response.raise_for_status(); data=response.json()
        return {'sku':data.get('sku',sku),'name':data.get('name'),'status':data.get('status'),'message':'Product description updated successfully'}

    async def get_product_by_sku(self, sku: str) -> dict:
        async with self._client() as client:
            response = await client.get(f'/rest/V1/products/{quote(sku, safe="")}')
            response.raise_for_status()
            data = response.json()
        return {
            'id': data.get('id'),
            'sku': data.get('sku', sku),
            'name': data.get('name'),
            'price': data.get('price'),
            'status': data.get('status'),
            'type_id': data.get('type_id'),
            'weight': data.get('weight'),
            'attribute_set_id': data.get('attribute_set_id'),
            'custom_attributes': data.get('custom_attributes', []),
            'media_gallery_entries': data.get('media_gallery_entries', []),
        }

    async def get_product_list(self, page_size: int = 20, current_page: int = 1, search_term: str = "") -> dict:
        page_size = min(max(page_size, 1), 100)
        current_page = max(current_page, 1)
        params = {
            'searchCriteria[pageSize]': page_size,
            'searchCriteria[currentPage]': current_page,
        }
        if search_term:
            params.update({
                'searchCriteria[filter_groups][0][filters][0][field]': 'name',
                'searchCriteria[filter_groups][0][filters][0][value]': f'%{search_term}%',
                'searchCriteria[filter_groups][0][filters][0][condition_type]': 'like',
            })
        async with self._client() as client:
            response = await client.get('/rest/V1/products', params=params)
            response.raise_for_status()
            data = response.json()
        return {
            'total_count': data.get('total_count', 0),
            'page_size': page_size,
            'current_page': current_page,
            'products': [
                {
                    'id': item.get('id'),
                    'sku': item.get('sku'),
                    'name': item.get('name'),
                    'price': item.get('price'),
                    'status': item.get('status'),
                    'type_id': item.get('type_id'),
                }
                for item in data.get('items', [])
            ],
        }

    async def add_media_for_sku(
        self,
        sku: str,
        base64_data: str,
        label: str = "Product Image",
        mime_type: str = "image/jpeg",
        file_name: str = "",
        types: list[str] | None = None,
        position: int = 1,
        disabled: bool = False,
    ) -> dict:
        if types is None:
            types = ["image", "small_image", "thumbnail"]
        if not file_name:
            ext = "png" if "png" in mime_type.lower() else ("webp" if "webp" in mime_type.lower() else "jpg")
            file_name = f"{sku}_image.{ext}"

        payload = {
            "entry": {
                "media_type": "image",
                "label": label,
                "position": position,
                "disabled": disabled,
                "types": types,
                "content": {
                    "base64_encoded_data": base64_data,
                    "type": mime_type,
                    "name": file_name,
                },
            }
        }
        async with self._client() as client:
            response = await client.post(f'/rest/V1/products/{quote(sku, safe="")}/media', json=payload)
            response.raise_for_status()
            result = response.json()
        return {
            'sku': sku,
            'media_id': result,
            'label': label,
            'file_name': file_name,
            'types': types,
            'message': 'Product media added successfully',
        }

