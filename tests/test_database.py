import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, AsyncMock

from app.db.database import Base
from app.db.models import User, MagentoConnection, OAuthAuthorizationCode, AuditEvent
from app.services.connection_repository import tenant_id_for, upsert_user, get_connection
from app.services.magento_connection import connect
from app.services.crypto import decrypt

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()

def test_tenant_id_deterministic():
    t1 = tenant_id_for("https://store.example.com", "user_1")
    t2 = tenant_id_for("https://store.example.com/", "user_1")
    t3 = tenant_id_for("https://store.example.com", "user_2")
    assert t1 == t2
    assert t1.startswith("magento_")
    assert t1 != t3

def test_upsert_user(db_session):
    u1 = upsert_user(db_session, "user@test.com", "support_agent")
    assert u1.subject == "user@test.com"
    assert u1.role == "support_agent"

    # Update role
    u2 = upsert_user(db_session, "user@test.com", "admin")
    assert u2.id == u1.id
    assert u2.role == "admin"

@pytest.mark.anyio
async def test_connect_and_get_connection(db_session):
    validation_mock = {
        "reachable": True,
        "status_code": 200,
        "store_url": "https://store.example.com",
        "magento_version": "2.4.6",
    }
    with patch("app.services.magento_connection.validate_magento_url", new_callable=AsyncMock, return_value=validation_mock):
        conn = await connect(db_session, "admin_user", "https://store.example.com", "secret-token-123")
        assert conn.tenant_id is not None
        assert conn.owner_subject == "admin_user"
        assert conn.active is True
        assert decrypt(conn.encrypted_access_token) == "secret-token-123"

        # Lookup connection
        found = get_connection(db_session, conn.tenant_id, "admin_user")
        assert found is not None
        assert found.tenant_id == conn.tenant_id

        # Tenant isolation check: searching with another user should yield None
        unauthorized = get_connection(db_session, conn.tenant_id, "other_user")
        assert unauthorized is None
