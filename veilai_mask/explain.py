"""Exposure Explainer: built from templates filled with findings, never free LLM text."""
from __future__ import annotations

from . import config
from .models import Finding


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _evidence(f: Finding) -> str:
    if f.entity_type in ("SECRET", "HONEYTOKEN", "CARD", "BANK_ACCOUNT", "NATIONAL_ID"):
        v = f.text
        return (v[:3] + "•" * min(10, max(3, len(v) - 5)) + v[-2:]) if len(v) > 6 else "••••"
    s = f.text or f.detail
    return f'"{s[:90]}{"…" if len(s) > 90 else ""}"'


def explain(findings: list[Finding], text: str, recommendation: dict) -> list[dict]:
    flagging = [f for f in findings if f.flags]
    by_cat: dict[str, list[Finding]] = {}
    for f in flagging:
        by_cat.setdefault(f.category, []).append(f)
    out = []
    for cat in sorted(by_cat, key=config.CATEGORIES.index):
        fs = sorted(by_cat[cat], key=lambda f: (-config.LEVEL_RANK.get(f.severity, 0), -f.confidence))
        top = fs[0]
        lines = sorted({_line_of(text, f.start) for f in fs if f.start >= 0})
        kinds = sorted({(f.detail if f.layer in ("L1", "L0") else f.entity_type.replace("_", " ").lower()) for f in fs})
        out.append({
            "category": cat,
            "severity": top.severity,
            "found": f"{len(fs)} finding{'s' if len(fs) != 1 else ''}: " + ", ".join(kinds[:4]),
            "where": ("line " + ", ".join(map(str, lines[:6]))) if lines else "whole document",
            "evidence": _evidence(top),
            "layers": sorted({f.layer for f in fs}),
            "why_it_matters": config.WHY.get(cat, ""),
            "regulation": config.REGULATION.get(cat, ""),
            "recommended": recommendation["why"],
        })
    return out
