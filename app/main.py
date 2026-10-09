from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from .approvals import ApprovalStore
from .config import get_settings
from .mcp_server import build_server
from .oauth_server import OAuthStore, register_routes
from .security import JWTVerifier
from .db.database import init_db, SessionLocal

settings=get_settings(); approvals=ApprovalStore(); oauth=OAuthStore(SessionLocal); verifier=JWTVerifier()
mcp_server=build_server(verifier,approvals)

def _csv(value): return [x.strip() for x in value.split(',') if x.strip()]
def _normalize_hosts(hosts):
    out = []
    for h in hosts:
        out.append(h)
        if ':' not in h:
            out.append(f'{h}:*')
    return list(dict.fromkeys(out))

allowed_hosts = _normalize_hosts(_csv(settings.allowed_hosts))
allowed_origins = _csv(settings.allowed_origins)

mcp_app=mcp_server.streamable_http_app(
    streamable_http_path='/mcp',stateless_http=False,json_response=False,
    auth=AuthSettings(issuer_url=settings.oauth_issuer_url,resource_server_url=settings.mcp_resource_url,required_scopes=[],validate_token_resource=True),
    token_verifier=verifier,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,allowed_hosts=allowed_hosts,allowed_origins=allowed_origins) if allowed_hosts or allowed_origins else TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

@asynccontextmanager
async def lifespan(app):
    init_db()
    async with mcp_server.session_manager.run(): yield

app=FastAPI(title=settings.app_name,version=settings.app_version,lifespan=lifespan)
register_routes(app,settings,oauth)
bearer=HTTPBearer(auto_error=True)

@app.get('/health')
async def health(): return {'status':'ok','service':settings.app_name,'version':settings.app_version,'phase':'1-6'}

async def require_approver(credentials:HTTPAuthorizationCredentials=Depends(bearer)):
    token=await verifier.verify_token(credentials.credentials)
    if not token or (token.claims or {}).get('role') not in {'admin','cms_admin'}: raise HTTPException(403,'Admin approval required')
    return token

@app.post('/approvals/{approval_id}/approve')
async def approve(approval_id:str,token=Depends(require_approver)):
    try:
        approval=approvals.get(approval_id)
        if approval.tenant_id!=(token.claims or {}).get('tenant_id'): raise HTTPException(403,'Approval belongs to another tenant')
        approval=approvals.approve(approval_id)
    except KeyError: raise HTTPException(404,'Approval not found or expired')
    return {'approval_id':approval.approval_id,'approved':approval.approved,'expires_at':approval.expires_at,'tool':approval.tool,'tenant_id':approval.tenant_id}

app.mount('/',mcp_app)
