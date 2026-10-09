from urllib.parse import urlparse
import httpx

async def validate_magento_url(store_url: str, access_token: str | None = None) -> dict:
    value = store_url.strip().rstrip('/')
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        raise ValueError('Store URL must be a valid http(s) URL')
    if parsed.username or parsed.password:
        raise ValueError('Store URL must not contain credentials')
    headers = {'Accept': 'application/json'}
    if access_token:
        headers['Authorization'] = f'Bearer {access_token}'
    endpoint = f'{value}/rest/V1/store/storeConfigs'
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers=headers) as client:
            response = await client.get(endpoint)
        result = {'reachable': response.is_success, 'status_code': response.status_code, 'store_url': value}
        if response.is_success:
            try:
                data = response.json()
                result['store_configs'] = data if isinstance(data, list) else None
            except Exception:
                pass
            result['magento_version'] = response.headers.get('x-magento-version')
        return result
    except httpx.HTTPError as exc:
        return {'reachable': False, 'status_code': 0, 'store_url': value, 'error': str(exc)}
