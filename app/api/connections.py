"""Phase 3 connection API: validate URL and create a stored connection."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl, SecretStr
from sqlalchemy.orm import Session
from ..db.database import get_db
from ..services.url_validator import validate_magento_url
from ..services.magento_connection import connect

router = APIRouter(prefix='/connections', tags=['Magento Connections'])

class ConnectionRequest(BaseModel):
    store_url: HttpUrl
    access_token: SecretStr

@router.post('/validate')
async def validate(payload: ConnectionRequest):
    try:
        return await validate_magento_url(str(payload.store_url))
    except Exception as exc:
        raise HTTPException(400, str(exc))

@router.post('')
async def create(payload: ConnectionRequest, db: Session = Depends(get_db)):
    try:
        item = await connect(db, 'api-user', str(payload.store_url), payload.access_token.get_secret_value())
        return {'tenant_id': item.tenant_id, 'store_url': item.store_url, 'active': item.active}
    except Exception as exc:
        raise HTTPException(400, str(exc))
