"""L4 context signals: cue rules from the design doc §11.2 (weak signals).

A cue alone never decides: fusion sends a single weak signal to REVIEW.
Also extracts money amounts that sit next to finance words, as MONEY entities for minimisation.
"""
from __future__ import annotations

import re

from .models import Finding

MONEY = r"(?:₹|rs\.?|inr|\$|€|£|usd)\s?\d[\d,.]*(?:\s?(?:crore|cr|lakh|lakhs|lpa|million|billion|mn|bn|k)\b)?|\d[\d,.]*\s?(?:crore|cr|lakh|lakhs|lpa|million|billion|mn|bn)\b"
FIN_WORDS = r"revenue|margin|salary|salaries|compensation|ctc|forecast|valuation|profit|ebitda|earnings|budget|bonus|payroll|deal|contract|price|pricing|worth|increment"

_MONEY_RE = re.compile(MONEY, re.I)
_FIN_RE = re.compile(rf"\b(?:{FIN_WORDS})\b", re.I)

CUES = [
    ("board-approved", "CONFIDENTIAL_BUSINESS", re.compile(r"\bboard\s+(?:has\s+)?approved\b", re.I)),
    ("do-not-distribute", "CONFIDENTIAL_BUSINESS", re.compile(r"\bdo\s+not\s+(?:distribute|share|forward|discuss)\b|\bnot\s+for\s+distribution\b|\bkeep\s+(?:this|it)\s+(?:between\s+us|quiet|confidential|internal|within\s+(?:the\s+)?(?:team|group|us|leadership))\b", re.I)),
    ("confidential-marking", "CONFIDENTIAL_BUSINESS", re.compile(r"\b(?:strictly\s+)?confidential\b|\binternal\s+only\b|\bleadership\s+only\b|\bprivileged\b", re.I)),
    ("deal-language", "CONFIDENTIAL_BUSINESS", re.compile(r"\b(?:acquisition|acquire|merger|term\s+sheet|due\s+diligence|layoffs?|restructuring)\b", re.I)),
    ("unreleased", "INTELLECTUAL_PROPERTY", re.compile(r"\bunreleased\b|\bunannounced\b|\bnot\s+yet\s+public\b", re.I)),
    ("proprietary", "INTELLECTUAL_PROPERTY", re.compile(r"\bproprietary\b|\btrade\s+secret\b|\bpatent[-\s]pending\b", re.I)),
]


def money_near_finance(text: str, window: int = 60) -> list[tuple[int, int, str]]:
    """Money amounts within `window` characters of a finance word (same sentence)."""
    out = []
    for m in _MONEY_RE.finditer(text):
        lo, hi = max(0, m.start() - window), min(len(text), m.end() + window)
        if _FIN_RE.search(text[lo:hi]):
            out.append((m.start(), m.end(), m.group().strip()))
    return out


def scan_cues(text: str, offset: int = 0) -> list[Finding]:
    found: list[Finding] = []
    for cue_id, cat, rx in CUES:
        m = rx.search(text)
        if m:
            found.append(Finding("L4", cat, [cat], "CUE", "MEDIUM", 0.55, "weak", m.group(), offset + m.start(), offset + m.end(), cue_id))
    for s, e, v in money_near_finance(text):
        found.append(Finding("L4", "FINANCIAL", ["FINANCIAL"], "MONEY", "MEDIUM", 0.6, "weak", v, offset + s, offset + e, "money-near-finance"))
    return found
