"""Fusion, policy + risk, and the decision recommendation.

Fusion uses the rule measured in ablation step 6 (Qwen3 4B: 95.2% recall, hard-flag FPR 11.1%):
  STRONG signals flag on their own: L0 honeytoken, L1 CRITICAL/HIGH rule, L3 Org DNA, L5 verified quote.
  WEAK signals: L1 MEDIUM rule (email / phone / private IP), L2 identifier, L4 cue.
  One weak layer alone → REVIEW (layers disagree). Two or more weak layers → SENSITIVE. None → SAFE.
Confidence (how sure) and severity (how bad) are kept separate.
"""
from __future__ import annotations

from . import config
from .models import Finding

LAYER_WEIGHT = {"L0": 1.0, "L1": 0.95, "L2": 0.6, "L3": 0.9, "L4": 0.5, "L5": 0.85}


def with_hierarchy(labels: list[str]) -> list[str]:
    out = list(dict.fromkeys(labels))
    for lab in list(out):
        for extra in config.HIERARCHY.get(lab, []):
            if extra not in out:
                out.append(extra)
    return out


def is_strong(f: Finding) -> bool:
    if not f.flags:
        return False
    if f.layer in ("L0", "L3", "L5"):
        return True
    return f.layer == "L1" and f.severity in ("CRITICAL", "HIGH")


BULK_IDENTIFIERS = 3  # this many personal identifiers in one prompt is bulk personal data, not a contact line


def fuse(findings: list[Finding]) -> dict:
    for f in findings:
        f.labels = with_hierarchy(f.labels)
    flagging = [f for f in findings if f.flags]
    strong = [f for f in flagging if is_strong(f)]
    identifiers = {f.text.lower() for f in flagging if f.entity_type in ("EMAIL", "PHONE", "NATIONAL_ID", "ADDRESS", "CUSTOMER_ID") and f.text}
    bulk = len(identifiers) >= BULK_IDENTIFIERS
    if bulk:
        strong = strong + [f for f in flagging if f.entity_type in ("EMAIL", "PHONE") and f not in strong]
    weak_layers = sorted({f.layer for f in flagging if not is_strong(f)})
    if strong:
        verdict = "SENSITIVE"
    elif len(weak_layers) >= 2:
        verdict = "SENSITIVE"
    elif len(weak_layers) == 1:
        verdict = "REVIEW"
    else:
        verdict = "SAFE"
    p_clear = 1.0
    for f in flagging:
        p_clear *= 1 - LAYER_WEIGHT.get(f.layer, 0.5) * max(0.0, min(1.0, f.confidence))
    categories = sorted({lab for f in flagging for lab in f.labels}, key=config.CATEGORIES.index)
    return {
        "verdict": verdict,
        "fused_confidence": round(1 - p_clear, 3),
        "strong_layers": sorted({f.layer for f in strong}),
        "weak_layers": weak_layers,
        "categories": categories,
        "bulk_personal_data": bulk,
        "rule": "strong signal flags alone; one weak layer → REVIEW; two weak layers → flag; ≥3 personal identifiers → flag",
    }


def assess_risk(findings: list[Finding], fusion: dict, destination: str = "free_tier_ai") -> dict:
    flagging = [f for f in findings if f.flags]
    honeytoken = next((f for f in flagging if f.entity_type == "HONEYTOKEN"), None)
    if honeytoken:
        level = "CRITICAL"
    elif fusion["verdict"] == "SAFE":
        level = "SAFE"
    elif fusion["verdict"] == "REVIEW":
        level = "REVIEW"
    else:
        level = "LOW"
        for f in flagging:
            sev = f.severity if f.layer in ("L0", "L1") else config.CATEGORY_SEVERITY.get(f.category, "MEDIUM")
            if not is_strong(f):
                sev = "MEDIUM"
            if fusion.get("bulk_personal_data") and f.entity_type in ("EMAIL", "PHONE"):
                sev = "HIGH"
            if config.LEVEL_RANK.get(sev, 0) > config.LEVEL_RANK[level]:
                level = sev
    bonus = None
    types = {f.entity_type for f in findings}
    if level in ("LOW", "MEDIUM", "REVIEW") and "PERSON" in types and ({"MONEY", "NATIONAL_ID", "MEDICAL"} & types):
        level, bonus = "HIGH", "Combination bonus: a named person together with salary, ID or health data"
    base = {"SAFE": 3, "LOW": 22, "MEDIUM": 45, "HIGH": 68, "CRITICAL": 90, "REVIEW": 50}[level]
    mult = config.DESTINATION_MULTIPLIER.get(destination, 1.3)
    score = base if level in ("SAFE", "CRITICAL") else min(99, round(base * (0.85 + 0.15 * mult) + 2 * len(fusion["categories"])))
    if level == "CRITICAL":
        score = 100 if honeytoken else 95
    return {"level": level, "score": score, "confidence": fusion["fused_confidence"], "destination": destination,
            "destination_multiplier": mult, "combination_bonus": bonus, "honeytoken": bool(honeytoken),
            "honeytoken_source": honeytoken.detail if honeytoken else None}


def recommend(risk: dict, findings: list[Finding], task: str) -> dict:
    level = risk["level"]
    if risk["honeytoken"]:
        return {"default": "BLOCK", "allowed": ["BLOCK"], "why": "Honeytoken match: a security incident. The request is blocked and cannot be overridden."}
    allowed = ["SEND_SANITISED", "ANSWER_LOCALLY", "EDIT", "BLOCK"]
    if level not in ("CRITICAL",):
        allowed.insert(3, "OVERRIDE")
    if level == "SAFE":
        return {"default": "SEND_SANITISED", "allowed": ["SEND_SANITISED", "ANSWER_LOCALLY", "EDIT"], "why": "Nothing sensitive found by any layer: sent unchanged."}
    if level == "REVIEW":
        return {"default": "SEND_SANITISED", "allowed": ["SEND_SANITISED", "EDIT", "OVERRIDE", "ANSWER_LOCALLY"],
                "why": "Layers disagree. Send the sanitised version, edit it, or override with a written justification."}
    org_dna = any(f.layer == "L3" and f.entity_type == "ORG_DOCUMENT" for f in findings)
    business = any(f.layer == "L5" and f.category == "CONFIDENTIAL_BUSINESS" for f in findings)
    if level == "HIGH" and (org_dna or business) and task in ("summarise", "question", "draft_rewrite"):
        return {"default": "ANSWER_LOCALLY", "allowed": allowed,
                "why": "Confidential business content: on-device Qwen can answer this without anything leaving the device."}
    if level == "CRITICAL":
        return {"default": "SEND_SANITISED", "allowed": allowed,
                "why": "Secrets are replaced by inert placeholders and are never restored into the prompt."}
    return {"default": "SEND_SANITISED", "allowed": allowed, "why": "Send the minimised, masked and verified version."}
