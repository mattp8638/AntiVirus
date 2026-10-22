from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import RMM_DATABASE_URL

engine = create_engine(RMM_DATABASE_URL, connect_args={"check_same_thread": False} if RMM_DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)
