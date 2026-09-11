from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from backend.core.config import settings

# Engine configuration with dialect-specific options
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.ECHO_SQL,
    pool_pre_ping=True,
)

# Enable foreign keys for SQLite
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    # Import all models to ensure they register on Base.metadata
    from backend.models import (
        Service,
        ServiceDependency,
        Incident,
        Event,
        EventRelationship,
        LogEntry,
        Metric,
        MetricSample,
        Trace,
        Span,
        Deployment,
        ConfigChange,
        Alert,
        Anomaly,
        Hypothesis,
        HypothesisEvidence,
        Evidence,
        Intervention,
        RecoveryEvent,
        Investigation,
        InvestigationStep,
        Report,
    )
    Base.metadata.create_all(bind=engine)

    # Auto-migrate missing columns for existing SQLite tables
    try:
        from sqlalchemy import text, inspect
        inspector = inspect(engine)
        with engine.connect() as conn:
            for table_name in inspector.get_table_names():
                table = Base.metadata.tables.get(table_name)
                if table is None:
                    continue
                existing_columns = {col["name"] for col in inspector.get_columns(table_name)}
                for column in table.columns:
                    if column.name not in existing_columns:
                        col_type = column.type.compile(engine.dialect)
                        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}"))
            conn.commit()
    except Exception:
        pass
