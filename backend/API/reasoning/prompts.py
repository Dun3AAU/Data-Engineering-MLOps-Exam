"""Prompt builders for the reasoning layer."""

from __future__ import annotations

import json

from .schemas import FindingContext, PentesterOutput


PENTESTER_SYSTEM_PROMPT = """You are a defensive security analyst acting as a pentester in a two-stage reasoning pipeline.
Your task is to produce high-level attack hypotheses, validation checks, and likely impact.
Do not provide exploit code, payloads, step-by-step exploitation instructions, weaponization, or persistence techniques.
Focus on safe, non-operational analysis that helps prioritize defensive work."""

EXPERT_SYSTEM_PROMPT = """You are a senior security expert reviewing the pentester analysis plus the original CVE and infrastructure context.
Your task is to recommend a practical remediation and prioritization plan.
Do not add exploit instructions. Keep the result concise, actionable, and suitable for a risk register or executive report."""


def build_pentester_messages(context: FindingContext) -> list[dict[str, str]]:
    payload = json.dumps(context.model_dump(mode="json"), indent=2)
    user_prompt = f"""Analyze the following CVE-to-asset match and return a JSON object that matches the pentester schema.

Requirements:
- Provide only high-level attack hypotheses.
- Include validation checks that a defender could use to confirm exposure.
- Explain the likely impact in business terms.
- Do not provide exploit code, payloads, command lines, or weaponized steps.
- Return valid JSON only.

Context:
{payload}"""
    return [
        {"role": "system", "content": PENTESTER_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def build_expert_messages(context: FindingContext, pentester: PentesterOutput) -> list[dict[str, str]]:
    payload = {
        "finding": context.model_dump(mode="json"),
        "pentester": pentester.model_dump(mode="json"),
    }
    user_prompt = f"""Review the following security finding and the pentester analysis.
Return a JSON object that matches the expert schema.

Requirements:
- Recommend a remediation plan with concrete but safe actions.
- Include compensating controls if patching is not immediate.
- Provide a decision such as remediate, mitigate, accept, or monitor.
- Prioritize for operational use, not exploitation.
- Return valid JSON only.

Context:
{json.dumps(payload, indent=2)}"""
    return [
        {"role": "system", "content": EXPERT_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
