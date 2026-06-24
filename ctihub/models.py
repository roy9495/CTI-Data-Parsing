from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey
from datetime import datetime, timezone
from ctihub.database import Base

class StixObject(Base):
    __tablename__ = "stix_objects"

    id = Column(String, primary_key=True)  # STIX 2.1 ID (e.g., indicator--uuid)
    type = Column(String, nullable=False, index=True)  # indicator, malware, threat-actor, campaign, vulnerability, tool, identity
    name = Column(String, nullable=False, index=True)  # Name of entity or IOC value
    description = Column(Text, nullable=True)
    confidence = Column(Integer, default=70)
    stix_json = Column(Text, nullable=False)  # Raw STIX object JSON
    source = Column(String, nullable=True, index=True)  # Connector source (e.g., AbuseIPDB)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class StixRelationship(Base):
    __tablename__ = "stix_relationships"

    id = Column(String, primary_key=True)  # STIX 2.1 ID (relationship--uuid)
    relationship_type = Column(String, nullable=False, index=True)  # indicates, uses, targets, attributed-to
    source_ref = Column(String, nullable=False, index=True)  # Source STIX ID
    target_ref = Column(String, nullable=False, index=True)  # Target STIX ID
    description = Column(Text, nullable=True)
    stix_json = Column(Text, nullable=False)
    source = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Connector(Base):
    __tablename__ = "connectors"

    id = Column(String, primary_key=True)  # E.g., "abuseipdb"
    name = Column(String, nullable=False)
    type = Column(String, default="EXTERNAL_IMPORT")
    description = Column(Text, nullable=True)
    status = Column(String, default="IDLE")  # IDLE, RUNNING, ERROR
    last_run = Column(DateTime, nullable=True)
    record_count = Column(Integer, default=0)
    logs = Column(Text, nullable=True)
