from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from ..config import get_settings

class Base(DeclarativeBase): pass
settings=get_settings()
DATABASE_URL=getattr(settings,'database_url','sqlite:///./magento_mcp.db')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL='postgresql+psycopg://'+DATABASE_URL[len('postgres://'):]
elif DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL='postgresql+psycopg://'+DATABASE_URL[len('postgresql://'):]
connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {}
engine=create_engine(DATABASE_URL,future=True,pool_pre_ping=True,connect_args=connect_args)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False)

def init_db():
    from .models import User, MagentoConnection, OAuthAuthorizationCode, AuditEvent
    Base.metadata.create_all(bind=engine)

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
