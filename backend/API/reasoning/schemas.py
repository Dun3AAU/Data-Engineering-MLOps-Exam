"""Pydantic schemas for the reasoning layer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AssetContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    asset_id: str
    asset_type: str
    site: str | None = None
    role: str | None = None
    criticality: str | None = None
    internet_exposed: bool = False
    cpes: list[str] = Field(default_factory=list)


class CVEContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve_id: str
    description: str | None = None
    severity: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    published_date: datetime | None = None
    last_modified_date: datetime | None = None


class FindingContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_id: int
    cve_db_id: int
    asset: AssetContext
    cve: CVEContext
    cpe_uri: str | None = None
    match_confidence: float = 0.0
    match_reason: str | None = None
    version_vulnerable: bool = False
    match_details: dict[str, Any] = Field(default_factory=dict)
    remediation_status: str | None = None
    patched_version: str | None = None
    patched_at: datetime | None = None
    remediation_notes: str | None = None


class PentesterOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    summary: str
    attack_path: str
    attack_hypotheses: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    validation_checks: list[str] = Field(default_factory=list)
    likely_impact: str
    safety_notes: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class ExpertOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    assessment: str
    risk_level: str
    priority: str
    decision: str
    rationale: str
    remediation_plan: list[str] = Field(default_factory=list)
    compensating_controls: list[str] = Field(default_factory=list)
    follow_up_questions: list[str] = Field(default_factory=list)
    target_sla_days: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class ReasoningRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    input: FindingContext
    pentester: PentesterOutput
    expert: ExpertOutput
    provider: str
    model: str
    dry_run: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReasoningSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total_findings: int
    processed_findings: int
    dry_run: bool = False
    by_decision: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    by_risk_level: dict[str, int] = Field(default_factory=dict)
    by_criticality: dict[str, int] = Field(default_factory=dict)
    by_asset_type: dict[str, int] = Field(default_factory=dict)
    internet_exposed_count: int = 0
    top_assets: list[dict[str, Any]] = Field(default_factory=list)
    top_cves: list[dict[str, Any]] = Field(default_factory=list)


class ReasoningReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provider: str
    model: str
    dry_run: bool = False
    total_findings: int
    processed_findings: int
    summary: ReasoningSummary
    records: list[ReasoningRecord] = Field(default_factory=list)
