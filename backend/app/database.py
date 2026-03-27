from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

DATABASE_URL = settings.database_url

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_runtime_schema() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:
        inspector = inspect(conn)

        if "incidents" in inspector.get_table_names():
            incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
            incident_alters = {
                "nist_phase": "ALTER TABLE incidents ADD COLUMN nist_phase VARCHAR DEFAULT 'Detection and Analysis'",
                "owner": "ALTER TABLE incidents ADD COLUMN owner VARCHAR",
                "disposition": "ALTER TABLE incidents ADD COLUMN disposition VARCHAR",
                "last_decision": "ALTER TABLE incidents ADD COLUMN last_decision VARCHAR",
                "response_summary": "ALTER TABLE incidents ADD COLUMN response_summary TEXT",
            }
            for name, statement in incident_alters.items():
                if name not in incident_columns:
                    conn.execute(text(statement))

        if "connectors" in inspector.get_table_names():
            connector_columns = {column["name"] for column in inspector.get_columns("connectors")}
            connector_alters = {
                "last_sync_status": "ALTER TABLE connectors ADD COLUMN last_sync_status VARCHAR",
                "last_sync_message": "ALTER TABLE connectors ADD COLUMN last_sync_message TEXT",
                "last_sync_at": "ALTER TABLE connectors ADD COLUMN last_sync_at DATETIME",
            }
            for name, statement in connector_alters.items():
                if name not in connector_columns:
                    conn.execute(text(statement))

        create_tables = {
            "incident_notes": """
                CREATE TABLE incident_notes (
                    id INTEGER PRIMARY KEY,
                    incident_id INTEGER NOT NULL,
                    author VARCHAR,
                    body TEXT NOT NULL,
                    created_at DATETIME,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                )
            """,
            "incident_tasks": """
                CREATE TABLE incident_tasks (
                    id INTEGER PRIMARY KEY,
                    incident_id INTEGER NOT NULL,
                    title VARCHAR NOT NULL,
                    owner VARCHAR,
                    status VARCHAR NOT NULL DEFAULT 'open',
                    created_at DATETIME,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                )
            """,
            "incident_evidence": """
                CREATE TABLE incident_evidence (
                    id INTEGER PRIMARY KEY,
                    incident_id INTEGER NOT NULL,
                    evidence_type VARCHAR NOT NULL,
                    source VARCHAR,
                    description TEXT NOT NULL,
                    created_at DATETIME,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                )
            """,
            "connector_jobs": """
                CREATE TABLE connector_jobs (
                    id INTEGER PRIMARY KEY,
                    connector_id INTEGER NOT NULL,
                    job_type VARCHAR NOT NULL DEFAULT 'sync',
                    status VARCHAR NOT NULL DEFAULT 'queued',
                    message TEXT,
                    started_at DATETIME,
                    finished_at DATETIME,
                    created_at DATETIME,
                    FOREIGN KEY(connector_id) REFERENCES connectors(id)
                )
            """,
            "news_sources": """
                CREATE TABLE news_sources (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR NOT NULL,
                    url VARCHAR NOT NULL,
                    trust_level VARCHAR NOT NULL DEFAULT 'community',
                    enabled BOOLEAN,
                    created_at DATETIME
                )
            """,
        }
        existing_tables = set(inspector.get_table_names())
        for table_name, statement in create_tables.items():
            if table_name not in existing_tables:
                conn.execute(text(statement))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
