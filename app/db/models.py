from datetime import datetime
from sqlalchemy import String, Text, DateTime, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(64), default='admin')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class MagentoConnection(Base):
    __tablename__ = 'magento_connections'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_subject: Mapped[str] = mapped_column(String(255), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    store_url: Mapped[str] = mapped_column(String(1024))
    encrypted_access_token: Mapped[str] = mapped_column(Text)
    magento_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OAuthAuthorizationCode(Base):
    __tablename__ = 'oauth_authorization_codes'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(2048))
    redirect_uri: Mapped[str] = mapped_column(String(2048))
    code_challenge: Mapped[str] = mapped_column(String(512))
    resource: Mapped[str] = mapped_column(String(2048))
    tenant_id: Mapped[str] = mapped_column(String(128))
    subject: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(64), default='admin')
    scopes: Mapped[str] = mapped_column(Text, default='')
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class AuditEvent(Base):
    __tablename__ = 'audit_events'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
