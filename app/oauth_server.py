"""MCP-compatible OAuth 2.1 authorization server for the gateway MVP.

ChatGPT -> this gateway uses OAuth authorization-code + PKCE (S256).
Gateway -> Magento uses the customer's Magento Integration Access Token.
Magento credentials are encrypted in the database and never placed in JWTs.
"""
import base64, hashlib, html, secrets, time
from datetime import datetime, timedelta
from urllib.parse import urlencode
import jwt
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy import delete, select
from .config import Settings
from .db.models import OAuthAuthorizationCode
from .services.magento_connection import connect
from .services.connection_repository import upsert_user
from .services.url_validator import validate_magento_url
from .services.crypto import decrypt

class OAuthStore:
    def __init__(self, session_factory): self.session_factory = session_factory
    @staticmethod
    def _hash(code): return hashlib.sha256(code.encode()).hexdigest()
    def put(self, **kwargs):
        db=self.session_factory()
        try:
            db.add(OAuthAuthorizationCode(code_hash=self._hash(kwargs['code']), client_id=kwargs['client_id'],
                redirect_uri=kwargs['redirect_uri'], code_challenge=kwargs['code_challenge'], resource=kwargs['resource'],
                tenant_id=kwargs['tenant_id'], subject=kwargs['subject'], role=kwargs['role'], scopes=' '.join(kwargs['scopes']),
                expires_at=datetime.utcnow()+timedelta(seconds=kwargs['ttl']))); db.commit()
        finally: db.close()
    def pop(self, code):
        db=self.session_factory()
        try:
            item=db.scalar(select(OAuthAuthorizationCode).where(OAuthAuthorizationCode.code_hash==self._hash(code)))
            if not item or item.expires_at < datetime.utcnow():
                if item: db.delete(item); db.commit()
                return None
            data={k:getattr(item,k) for k in ('client_id','redirect_uri','code_challenge','resource','tenant_id','subject','role')}
            data['scopes']=item.scopes.split() if item.scopes else []
            db.delete(item); db.commit(); return data
        finally: db.close()

def _b64(data: bytes) -> str: return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def _verify_pkce(verifier, challenge): return secrets.compare_digest(_b64(hashlib.sha256(verifier.encode()).digest()), challenge)
def _redirect_allowed(settings, uri): return uri in [x.strip() for x in settings.oauth_allowed_redirect_uris.split(',') if x.strip()]
def _secret(settings):
    value=settings.oauth_signing_secret or settings.dev_jwt_secret
    if not value: raise RuntimeError('OAUTH_SIGNING_SECRET must be configured')
    return value

def oauth_metadata(settings):
    issuer=settings.oauth_issuer_url.rstrip('/')
    return {'issuer':issuer,'authorization_endpoint':f'{issuer}/oauth/authorize','token_endpoint':f'{issuer}/oauth/token',
        'scopes_supported':settings.oauth_scopes.split(),'response_types_supported':['code'],'grant_types_supported':['authorization_code'],
        'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],
        'client_id_metadata_document_supported':True,'authorization_response_iss_parameter_supported':True}

def protected_resource_metadata(settings):
    return {'resource':settings.mcp_resource_url,'authorization_servers':[settings.oauth_issuer_url.rstrip('/')],
            'scopes_supported':settings.oauth_scopes.split()}

def register_routes(app, settings, oauth: OAuthStore):
    @app.get('/.well-known/oauth-protected-resource')
    async def protected_resource(): return protected_resource_metadata(settings)
    @app.get('/.well-known/oauth-authorization-server')
    async def authorization_server(): return oauth_metadata(settings)

    @app.get('/oauth/authorize', response_class=HTMLResponse)
    async def authorize(request: Request):
        q=request.query_params
        required=['client_id','redirect_uri','response_type','code_challenge','resource']
        missing=[x for x in required if not q.get(x)]
        if missing: raise HTTPException(400, f'Missing OAuth parameters: {", ".join(missing)}')
        if q['response_type']!='code' or q.get('code_challenge_method','S256')!='S256': raise HTTPException(400,'Only authorization code + PKCE S256 is supported')
        if not _redirect_allowed(settings,q['redirect_uri']): raise HTTPException(400,'Unregistered redirect_uri')
        if q['resource']!=settings.mcp_resource_url: raise HTTPException(400,'Invalid resource')
        return f'''<!doctype html><html><head><title>Connect Magento</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:Arial;max-width:560px;margin:60px auto;padding:24px"><h2>Connect Magento</h2><p>Enter your Magento store URL and Integration Access Token.</p><form method="post" action="/oauth/authorize">{''.join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(q.get(k,""))}">' for k in ['client_id','redirect_uri','response_type','code_challenge','code_challenge_method','resource','scope','state'])}<label>Store URL</label><input required name="store_url" placeholder="https://shop.example.com" style="width:100%;padding:10px;margin:8px 0 16px"><label>Magento Integration Access Token</label><input required type="password" name="magento_token" style="width:100%;padding:10px;margin:8px 0 16px"><button type="submit" style="padding:10px 18px">Connect Magento</button></form><p style="font-size:13px;color:#666">The token is encrypted server-side and is never included in the OAuth access token.</p></body></html>'''

    @app.post('/oauth/authorize')
    async def authorize_submit(request: Request):
        form=await request.form(); data={k:str(v) for k,v in form.items()}
        for key in ('client_id','redirect_uri','code_challenge','resource','store_url','magento_token'):
            if not data.get(key): raise HTTPException(400,f'Missing {key}')
        if data.get('response_type')!='code' or data.get('code_challenge_method','S256')!='S256' or not _redirect_allowed(settings,data['redirect_uri']) or data['resource']!=settings.mcp_resource_url:
            raise HTTPException(400,'Invalid OAuth request')
        validation=await validate_magento_url(data['store_url'],data['magento_token'])
        if not validation['reachable']: raise HTTPException(400,f'Could not validate Magento connection: HTTP {validation["status_code"]}')
        # The CIMD client_id identifies ChatGPT; the connected account is represented by this subject.
        subject=data['client_id']
        db=oauth.session_factory()
        try:
            item=await connect(db,subject,data['store_url'],data['magento_token'])
            upsert_user(db,subject,'admin')
            tenant_id=item.tenant_id
        finally: db.close()
        scopes=data.get('scope','').split() or settings.oauth_scopes.split()
        code=secrets.token_urlsafe(32)
        oauth.put(code=code,client_id=data['client_id'],redirect_uri=data['redirect_uri'],code_challenge=data['code_challenge'],resource=data['resource'],tenant_id=tenant_id,subject=subject,role='admin',scopes=scopes,ttl=settings.oauth_code_ttl_seconds)
        params={'code':code,'iss':settings.oauth_issuer_url.rstrip('/')}
        if data.get('state'): params['state']=data['state']
        return RedirectResponse(f"{data['redirect_uri']}?{urlencode(params)}",303)

    @app.post('/oauth/token')
    async def token(request: Request):
        form=await request.form()
        if str(form.get('grant_type',''))!='authorization_code': return JSONResponse({'error':'unsupported_grant_type'},400)
        item=oauth.pop(str(form.get('code',''))); verifier=str(form.get('code_verifier','')); client_id=str(form.get('client_id',''))
        if not item or item['client_id']!=client_id or not _verify_pkce(verifier,item['code_challenge']) or item['resource']!=settings.mcp_resource_url:
            return JSONResponse({'error':'invalid_grant'},400)
        now = int(time.time())
        access = jwt.encode({'iss': settings.oauth_issuer_url.rstrip('/'), 'sub': item['subject'], 'aud': item['resource'], 'tenant_id': item['tenant_id'], 'role': item['role'], 'scope': ' '.join(item['scopes']), 'client_id': item['client_id'], 'iat': now, 'exp': now + settings.oauth_access_token_ttl_seconds}, _secret(settings), algorithm='HS256')
        return {'access_token': access, 'token_type': 'Bearer', 'expires_in': settings.oauth_access_token_ttl_seconds, 'scope': ' '.join(item['scopes'])}

    @app.get('/oauth/jwks.json')
    async def jwks(): return {'keys':[]}
    @app.get('/oauth/jwks')
    async def jwks_legacy(): return {'keys':[]}
