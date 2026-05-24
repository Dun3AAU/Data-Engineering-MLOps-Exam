from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, relationship
import datetime

Base = declarative_base()

class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    published_date = Column(DateTime, index=True)
    last_modified_date = Column(DateTime, index=True)
    description = Column(Text)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    raw = Column(Text)

    cpe_matches = relationship("CPEMatch", back_populates="cve", cascade="all, delete-orphan")

class CPEMatch(Base):
    __tablename__ = "cpe_matches"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), index=True)
    cpe23Uri = Column(Text, index=True)
    versionStartIncluding = Column(String, nullable=True)
    versionEndIncluding = Column(String, nullable=True)
    raw = Column(Text)

    cve = relationship("CVE", back_populates="cpe_matches")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    cve_id = Column(Integer, nullable=False)
    cpe_uri = Column(Text)
    matched_asset = Column(Text)
    match_details = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Remediation tracking
    remediation_status = Column(String, nullable=True)  # "open", "patched", "mitigated", "accepted"
    patched_version = Column(String, nullable=True)     # version applied to fix vulnerability
    patched_at = Column(DateTime, nullable=True)        # when patch was applied
    remediation_notes = Column(Text, nullable=True)     # notes on fix, workaround, or justification
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
