import hashlib
from sqlalchemy import select
from ..db.models import MagentoConnection
from .crypto import encrypt
from .url_validator import validate_magento_url
from .connection_repository import tenant_id_for

async def connect(db, owner_subject: str, store_url: str, access_token: str, role: str = 'admin') -> MagentoConnection:
    validation = await validate_magento_url(store_url, access_token=access_token)
    if not validation['reachable']:
        raise ValueError(f'Magento endpoint returned HTTP {validation["status_code"]}')
    tenant_id = tenant_id_for(validation['store_url'], owner_subject)
    existing = db.scalar(select(MagentoConnection).where(MagentoConnection.tenant_id == tenant_id))
    if existing:
        existing.encrypted_access_token = encrypt(access_token)
        existing.store_url = validation['store_url']
        existing.magento_version = validation.get('magento_version')
        existing.active = True
        db.commit(); db.refresh(existing)
        return existing
    item = MagentoConnection(
        owner_subject=owner_subject,
        tenant_id=tenant_id,
        store_url=validation['store_url'],
        encrypted_access_token=encrypt(access_token),
        magento_version=validation.get('magento_version'),
    )
    db.add(item); db.commit(); db.refresh(item)
    return item
