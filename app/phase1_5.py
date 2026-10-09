"""Combined Phase 1-5 bootstrap helpers."""
from .db.database import init_db

def initialize_phase1_5():
    init_db()
