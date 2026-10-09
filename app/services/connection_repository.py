import hashlib
from sqlalchemy import select
from ..db.models import MagentoConnection, User


def tenant_id_for(store_url: str, subject: str) -> str:
    normalized = store_url.rstrip('/').lower()
    digest = hashlib.sha256(f'{subject}:{normalized}'.encode()).hexdigest()[:24]
    return f'magento_{digest}'


def upsert_user(db, subject: str, role: str = 'admin') -> User:
    user = db.scalar(select(User).where(User.subject == subject))
    if user:
        user.role = role
        db.commit()
        db.refresh(user)
        return user
    user = User(subject=subject, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_connection(db, tenant_id: str, owner_subject: str | None = None) -> MagentoConnection | None:
    stmt = select(MagentoConnection).where(
        MagentoConnection.tenant_id == tenant_id,
        MagentoConnection.active.is_(True),
    )
    if owner_subject:
        stmt = stmt.where(MagentoConnection.owner_subject == owner_subject)
    return db.scalar(stmt)
