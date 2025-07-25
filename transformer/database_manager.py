from sqlalchemy import create_engine

from config.database_config import DATABASES

def get_connection(name):
    try:
        engine = create_engine(DATABASES[name])
        return engine.connect()
    except Exception as e:
        print(f"[X] Connection failed for {name}: {e}")
        return None
