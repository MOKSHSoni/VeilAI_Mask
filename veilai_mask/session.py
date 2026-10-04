"""Session mosaic risk: harmless pieces that add up across messages (design doc §11.5).

Facets tracked per session (in memory only): counterparty (an organisation name), amount (money),
timeline (a date, quarter or deadline). Three facets across two or more messages escalate to HIGH.
"""
from __future__ import annotations

import re
import threading
import time

from .models import Finding

_TIMELINE = re.compile(
    r"\b(?:\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}"
    r"|q[1-4]\b|by (?:monday|tuesday|wednesday|thursday|friday|end of (?:the )?(?:week|month|quarter))|next (?:week|month|quarter))", re.I)
_LABEL = {"counterparty": "the client", "amount": "the deal size", "timeline": "the closing date"}
_TTL_S = 4 * 3600

_sessions: dict[str, dict] = {}
_lock = threading.Lock()


def _facets(findings: list[Finding], text: str) -> set[str]:
    f = set()
    if any(x.entity_type in ("ORG", "CLIENT") for x in findings):
        f.add("counterparty")
    if any(x.entity_type == "MONEY" for x in findings):
        f.add("amount")
    if _TIMELINE.search(text):
        f.add("timeline")
    return f


def update(session_id: str | None, findings: list[Finding], text: str) -> dict | None:
    if not session_id:
        return None
    now = time.time()
    with _lock:
        for k in [k for k, v in _sessions.items() if now - v["at"] > _TTL_S]:
            del _sessions[k]
        s = _sessions.setdefault(session_id, {"facets": {}, "messages": 0, "at": now})
        s["messages"] += 1
        s["at"] = now
        for fct in _facets(findings, text):
            s["facets"].setdefault(fct, s["messages"])
        facets = dict(s["facets"])
        messages = s["messages"]
    mosaic = len(facets) >= 3 and messages >= 2 and len(set(facets.values())) >= 2
    shared = [_LABEL[k] for k in ("counterparty", "amount", "timeline") if k in facets]
    return {
        "session_id": session_id, "messages": messages, "facets": sorted(facets), "mosaic": mosaic,
        "warning": f"Across this session you've shared {', '.join(shared[:-1])} and {shared[-1]}." if mosaic else None,
    }
