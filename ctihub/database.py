import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# Prioritize DATABASE_URL, then POSTGRES_URL_NON_POOLING (direct connection), then POSTGRES_URL
DATABASE_URL = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL_NON_POOLING")
    or os.environ.get("POSTGRES_URL")
)

if not DATABASE_URL:
    if os.environ.get("VERCEL"):
        DATABASE_URL = "sqlite:////tmp/ctihub.db"
    else:
        DATABASE_URL = "sqlite:///ctihub.db"

# Standardize postgres scheme and sanitize custom query parameters for psycopg2 compatibility
if DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://"):
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        
    try:
        parsed_url = urlparse(DATABASE_URL)
        if parsed_url.query:
            # Keep only standard libpq connection parameters
            allowed_params = {
                "sslmode", "sslcert", "sslkey", "sslrootcert", "sslcrl",
                "application_name", "fallback_application_name", "connect_timeout",
                "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count"
            }
            q_params = parse_qsl(parsed_url.query)
            filtered_params = [(k, v) for k, v in q_params if k.lower() in allowed_params]
            
            # Rebuild connection string with only safe parameters
            new_query = urlencode(filtered_params)
            DATABASE_URL = urlunparse(parsed_url._replace(query=new_query))
    except Exception as e:
        import sys
        print(f"Error sanitizing database URL: {e}", file=sys.stderr)



connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL, connect_args=connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    import ctihub.models
    Base.metadata.create_all(bind=engine)
