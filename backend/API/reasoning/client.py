"""Groq-backed reasoning engine with safe offline fallback."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, TypeVar

try:
    from groq import Groq
except ImportError:  # pragma: no cover - optional dependency fallback
    Groq = None  # type: ignore[assignment]

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency fallback
    def load_dotenv() -> None:  # type: ignore[no-redef]
        return None

from .prompts import build_expert_messages, build_pentester_messages
from .schemas import ExpertOutput, FindingContext, PentesterOutput, ReasoningRecord

load_dotenv()

T = TypeVar("T")


@dataclass(slots=True)
class ReasoningEngine:
    """Run the two-stage reasoning pipeline."""

    model: str = os.getenv("GROQ_REASONING_MODEL", "llama-3.3-70b-versatile")
    api_key: str | None = os.getenv("GROQ_API_KEY")
    fallback_mode: bool = False
    provider: str = field(init=False, default="groq")
    _client: Any | None = field(init=False, default=None, repr=False)
    _fallback_models: tuple[str, ...] = field(
        init=False,
        default=("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
        repr=False,
    )

    def __post_init__(self) -> None:
        client = None
        if self.api_key and not self.fallback_mode and Groq is not None:
            client = Groq(api_key=self.api_key)
        object.__setattr__(self, "_client", client)
        if not self.api_key or self.fallback_mode or Groq is None:
            object.__setattr__(self, "provider", "heuristic")

    def run_finding(self, context: FindingContext) -> ReasoningRecord:
        pentester = self._pentester(context)
        expert = self._expert(context, pentester)
        return ReasoningRecord(
            input=context,
            pentester=pentester,
            expert=expert,
            provider=self.provider,
            model=self.model,
            dry_run=self.provider != "groq",
        )

    def _pentester(self, context: FindingContext) -> PentesterOutput:
        if self._client is None:
            return self._fallback_pentester(context)
        payload = self._chat(build_pentester_messages(context))
        payload = self._normalize_pentester_payload(payload)
        return PentesterOutput.model_validate(payload)

    def _expert(self, context: FindingContext, pentester: PentesterOutput) -> ExpertOutput:
        if self._client is None:
            return self._fallback_expert(context, pentester)
        payload = self._chat(build_expert_messages(context, pentester))
        payload = self._normalize_expert_payload(payload)
        return ExpertOutput.model_validate(payload)

    def _chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("Groq client is unavailable; use heuristic fallback instead")
        last_error: Exception | None = None
        candidate_models = (self.model, *[model for model in self._fallback_models if model != self.model])

        for candidate in candidate_models:
            try:
                response = self._client.chat.completions.create(
                    model=candidate,
                    messages=messages,
                    temperature=0.2,
                )
                self.model = candidate
                content = response.choices[0].message.content or "{}"
                return self._extract_json(content)
            except Exception as exc:  # groq.BadRequestError is not stable across versions
                last_error = exc
                if "model_decommissioned" not in str(exc):
                    raise

        if last_error is not None:
            raise last_error
        raise RuntimeError("Groq request failed without a captured error")

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        stripped = text.strip()
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        start = stripped.find("{")
        end = stripped.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = stripped[start : end + 1]
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        raise ValueError("Model did not return valid JSON")

    @staticmethod
    def _normalize_pentester_payload(payload: dict[str, Any]) -> dict[str, Any]:
        source = payload.get("pentester") if isinstance(payload.get("pentester"), dict) else payload
        return {
            "summary": ReasoningEngine._coerce_text(source, ("summary", "overview", "analysis", "result"), default="Pentester analysis unavailable."),
            "attack_path": ReasoningEngine._coerce_text(source, ("attack_path", "path", "attack", "scenario"), default="High-level attack hypothesis."),
            "attack_hypotheses": ReasoningEngine._coerce_list(source, ("attack_hypotheses", "hypotheses", "hypothesis", "paths", "scenarios")),
            "preconditions": ReasoningEngine._coerce_list(source, ("preconditions", "conditions", "requirements", "assumptions")),
            "validation_checks": ReasoningEngine._coerce_list(source, ("validation_checks", "checks", "verification_steps", "tests")),
            "likely_impact": ReasoningEngine._coerce_text(source, ("likely_impact", "impact", "business_impact", "severity"), default="Potential defensive impact requires review."),
            "safety_notes": ReasoningEngine._coerce_list(source, ("safety_notes", "notes", "guardrails", "warnings")),
            "confidence": ReasoningEngine._coerce_float(source, ("confidence", "score", "certainty"), default=0.6),
        }

    @staticmethod
    def _normalize_expert_payload(payload: dict[str, Any]) -> dict[str, Any]:
        source = payload.get("expert") if isinstance(payload.get("expert"), dict) else payload
        return {
            "assessment": ReasoningEngine._coerce_text(source, ("assessment", "summary", "overview", "analysis"), default="Security assessment unavailable."),
            "risk_level": ReasoningEngine._coerce_text(source, ("risk_level", "risk", "severity"), default="medium").lower(),
            "priority": ReasoningEngine._coerce_text(source, ("priority", "prio"), default="P3").upper(),
            "decision": ReasoningEngine._coerce_text(source, ("decision", "action", "recommendation"), default="monitor").lower(),
            "rationale": ReasoningEngine._coerce_text(source, ("rationale", "reason", "justification"), default="Based on the supplied finding context."),
            "remediation_plan": ReasoningEngine._coerce_list(source, ("remediation_plan", "plan", "actions", "steps")),
            "compensating_controls": ReasoningEngine._coerce_list(source, ("compensating_controls", "controls", "mitigations", "safeguards")),
            "follow_up_questions": ReasoningEngine._coerce_list(source, ("follow_up_questions", "questions", "open_questions")),
            "target_sla_days": ReasoningEngine._coerce_int(source, ("target_sla_days", "sla_days", "deadline_days")),
            "confidence": ReasoningEngine._coerce_float(source, ("confidence", "score", "certainty"), default=0.6),
        }

    @staticmethod
    def _coerce_text(source: dict[str, Any], keys: tuple[str, ...], default: str = "") -> str:
        for key in keys:
            if key in source:
                value = source[key]
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, dict):
                    nested = ReasoningEngine._coerce_text(value, ("text", "summary", "title", "value", "content", "description", "impact", "rationale", "decision", "assessment"))
                    if nested:
                        return nested
                if isinstance(value, list):
                    joined = "; ".join(ReasoningEngine._flatten_item(item) for item in value if ReasoningEngine._flatten_item(item))
                    if joined:
                        return joined
        for value in source.values():
            if isinstance(value, dict):
                nested = ReasoningEngine._coerce_text(value, ("text", "summary", "title", "value", "content", "description", "impact", "rationale", "decision", "assessment"))
                if nested:
                    return nested
        return default

    @staticmethod
    def _coerce_list(source: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
        for key in keys:
            if key in source:
                value = source[key]
                if isinstance(value, list):
                    flattened = [ReasoningEngine._flatten_item(item) for item in value]
                    return [item for item in flattened if item]
                if isinstance(value, str) and value.strip():
                    return [value.strip()]
                if isinstance(value, dict):
                    nested = ReasoningEngine._flatten_dict_items(value)
                    if nested:
                        return nested
        nested = ReasoningEngine._flatten_dict_items(source)
        return nested

    @staticmethod
    def _coerce_float(source: dict[str, Any], keys: tuple[str, ...], default: float = 0.6) -> float:
        for key in keys:
            if key in source:
                value = source[key]
                try:
                    return float(value)
                except (TypeError, ValueError):
                    continue
        return default

    @staticmethod
    def _coerce_int(source: dict[str, Any], keys: tuple[str, ...]) -> int | None:
        for key in keys:
            if key in source:
                value = source[key]
                try:
                    return int(value)
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _flatten_item(item: Any) -> str:
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict):
            for key in ("text", "summary", "title", "value", "content", "description", "hypothesis", "check", "step", "action", "recommendation", "risk", "impact"):
                nested = item.get(key)
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
            for value in item.values():
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    @staticmethod
    def _flatten_dict_items(source: dict[str, Any]) -> list[str]:
        flattened: list[str] = []
        for value in source.values():
            if isinstance(value, list):
                for item in value:
                    text = ReasoningEngine._flatten_item(item)
                    if text:
                        flattened.append(text)
            elif isinstance(value, dict):
                text = ReasoningEngine._flatten_item(value)
                if text:
                    flattened.append(text)
        return flattened

    def _fallback_pentester(self, context: FindingContext) -> PentesterOutput:
        score = float(context.cve.cvss_v3_score or 0.0)
        if context.asset.internet_exposed:
            summary = "The asset is internet-exposed, so the most plausible abuse path is remote attack against the vulnerable service or software."
        elif (context.asset.criticality or "").lower() == "critical":
            summary = "The asset is business-critical, so the main concern is privilege escalation or lateral movement after initial compromise."
        else:
            summary = "The likely abuse scenario is targeted misuse of the vulnerable component within the local environment."

        impact = "Potential service disruption, unauthorized access, data exposure, or pivoting to adjacent systems."
        if score >= 9.0:
            impact = "Potential remote compromise, broad service disruption, and high-confidence impact to availability or confidentiality."
        elif score >= 7.0:
            impact = "Potential unauthorized access or service degradation with meaningful business impact."

        return PentesterOutput(
            summary=summary,
            attack_path="High-level attack hypothesis based on the exposed product, version, and CVE range.",
            attack_hypotheses=[
                "Verify whether the vulnerable version is reachable from trusted or untrusted networks.",
                "Check whether the affected service exposes administrative or remote interfaces.",
            ],
            preconditions=self._fallback_preconditions(context),
            validation_checks=self._fallback_validation_checks(context),
            likely_impact=impact,
            safety_notes=[
                "No exploit steps were generated.",
                "Use vendor advisories and internal validation only.",
            ],
            confidence=0.72 if context.match_confidence >= 0.7 else 0.58,
        )

    def _fallback_expert(self, context: FindingContext, pentester: PentesterOutput) -> ExpertOutput:
        score = float(context.cve.cvss_v3_score or 0.0)
        exposed = context.asset.internet_exposed
        criticality = (context.asset.criticality or "low").lower()

        if score >= 9.0 or (exposed and criticality == "critical"):
            decision = "remediate"
            priority = "P1"
            risk_level = "critical"
            sla_days = 7
        elif score >= 7.0 or exposed:
            decision = "mitigate"
            priority = "P2"
            risk_level = "high"
            sla_days = 14
        else:
            decision = "monitor"
            priority = "P3"
            risk_level = "medium"
            sla_days = 30

        remediation_plan = [
            "Confirm the asset and vulnerable version in the inventory.",
            "Apply the vendor patch or upgrade to a fixed release.",
            "If patching is delayed, reduce exposure and restrict access.",
            "Re-run matching after remediation to confirm the finding clears.",
        ]
        if exposed:
            remediation_plan.insert(2, "Remove or narrow internet exposure until the patch is applied.")

        controls = [
            "Segmentation",
            "Access restriction",
            "Temporary service hardening",
        ]

        return ExpertOutput(
            assessment="The finding should be treated as a defensive remediation item with business context applied.",
            risk_level=risk_level,
            priority=priority,
            decision=decision,
            rationale=pentester.likely_impact,
            remediation_plan=remediation_plan,
            compensating_controls=controls,
            follow_up_questions=[
                "Is the asset internet-exposed or reachable from user VLANs?",
                "Is there a fixed vendor version available?",
                "Can the service be isolated or disabled temporarily?",
            ],
            target_sla_days=sla_days,
            confidence=0.7 if score >= 7.0 else 0.62,
        )

    @staticmethod
    def _fallback_preconditions(context: FindingContext) -> list[str]:
        preconditions = [
            "The vulnerable product and version must still be installed.",
            "The affected service must be reachable or usable in its current configuration.",
        ]
        if context.asset.internet_exposed:
            preconditions.append("The asset must remain exposed to external or semi-trusted networks.")
        return preconditions

    @staticmethod
    def _fallback_validation_checks(context: FindingContext) -> list[str]:
        checks = [
            "Confirm the installed version against the vulnerable range.",
            "Review whether the asset is externally reachable.",
            "Check vendor advisories for the fixed release.",
        ]
        if context.match_confidence < 0.6:
            checks.append("Revalidate the vendor/product mapping because the match confidence is moderate.")
        return checks
