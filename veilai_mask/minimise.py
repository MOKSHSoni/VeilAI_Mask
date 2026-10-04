"""Data Minimisation Engine: send only what the task needs (design doc §11.7).

The necessity matrix (config.NECESSITY) decides per entity class and task, not the LLM:
  KEEP → left as is · PSEUDONYMISE → ⟦ROLE_n⟧ (restored in the reply) · DROP → placeholder, value never
  needed · GENERALISE → coarser value (₹4.37 Cr → about ₹4 Cr).
Tables: for data-analysis tasks only the columns the instruction refers to are kept.
"""
from __future__ import annotations

import re

from . import config
from .masking import MaskTarget, generalise_money, parse_csv, table_to_csv
from .models import Finding

_ID_COLS = re.compile(r"(id|phone|mobile|pin|zip|code|number|account|aadhaar|pan|email|name)", re.I)
_SYNONYMS = {"spend": ["spend", "spending", "amount", "total", "purchase", "value"], "revenue": ["revenue", "sales", "amount"],
             "salary": ["salary", "ctc", "pay", "compensation"], "price": ["price", "cost", "amount"], "age": ["age"],
             "city": ["city", "location", "region"], "date": ["date", "month", "year"], "quantity": ["qty", "quantity", "units"]}


def _stem(w: str) -> str:
    return re.sub(r"[^a-z0-9]", "", w.lower())[:5]


def _wanted_columns(instruction: str, header: list[str], rows: list[list[str]]) -> tuple[list[int], str]:
    words = {_stem(w) for w in re.findall(r"[A-Za-z]{3,}", instruction)}
    for key, syns in _SYNONYMS.items():
        if any(_stem(s) in words for s in syns):
            words |= {_stem(s) for s in syns}
    keep = [i for i, h in enumerate(header) if any(_stem(part) in words for part in re.split(r"[_\s-]+", h) if len(part) >= 3)]
    if keep:
        return keep, "columns named in the instruction"
    numeric = [i for i, h in enumerate(header)
               if not _ID_COLS.search(h) and all(re.fullmatch(r"-?[\d,.]+", r[i].strip() or "0") for r in rows)]
    return numeric, "no column named in the instruction: kept numeric, non-identifying columns"


def minimise_table(instruction: str, content: str, task: str) -> dict | None:
    parsed = parse_csv(content)
    if not parsed or task != "analyse_data":
        return None
    header, rows = parsed
    keep, why = _wanted_columns(instruction, header, rows)
    if not keep:
        return None
    kept_header = [header[i] for i in keep]
    kept_rows = [[r[i] for i in keep] for r in rows]
    dropped_cols = [h for i, h in enumerate(header) if i not in keep]
    dropped_values = [r[i] for r in rows for i in range(len(header)) if i not in keep and r[i].strip()]
    return {
        "content": table_to_csv(kept_header, kept_rows),
        "kept_columns": kept_header,
        "dropped_columns": dropped_cols,
        "dropped_values": dropped_values,
        "rows": len(rows),
        "reason": why,
        "items": [{"item": h, "action": "KEPT" if h in kept_header else "DROPPED",
                   "reason": "needed for the calculation" if h in kept_header else "not needed for this task"} for h in header],
    }


def plan(findings: list[Finding], task: str) -> tuple[list[MaskTarget], list[dict]]:
    """Turn findings into mask targets using the necessity matrix. Returns (targets, report items)."""
    row = config.NECESSITY.get(task, config.NECESSITY["question"])
    targets: dict[str, MaskTarget] = {}
    report: dict[tuple[str, str], dict] = {}
    for f in findings:
        if not f.text or f.entity_type in ("CUE", "ORG_DOCUMENT"):
            continue
        cls = "strategy_text" if f.entity_type == "STRATEGY" else config.ENTITY_CLASS.get(f.entity_type)
        if cls is None:
            continue
        action = row[cls]
        if cls == "secrets":
            action = "DROP"  # never sent, whatever the task
        key = (cls, action)
        rep = report.setdefault(key, {"class": cls, "action": action, "count": 0, "examples": []})
        rep["count"] += 1
        if len(rep["examples"]) < 3 and f.text not in rep["examples"]:
            rep["examples"].append(f.text if cls != "secrets" else f.text[:4] + "…")
        if action == "KEEP":
            continue
        if f.text in targets:
            continue
        if action == "GENERALISE" and f.entity_type == "MONEY":
            targets[f.text] = MaskTarget(f.text, f.entity_type, f.category, generalise_to=generalise_money(f.text))
        else:
            targets[f.text] = MaskTarget(f.text, f.entity_type, f.category)
    labels = {"KEEP": "KEPT", "PSEUDONYMISE": "PSEUDONYMISED", "DROP": "DROPPED", "GENERALISE": "GENERALISED"}
    reasons = {
        "names": "the task needs roles, not identities", "contacts": "contact details are not needed for this task",
        "figures": "exact figures are not needed; the scale is kept", "secrets": "secrets are never sent, whatever the task",
        "internal_hosts": "the host's role is kept, its name stays local", "strategy_text": "the task is about this content",
    }
    def reason(cls: str, action: str) -> str:
        if action == "KEEP":
            return "needed for the task"
        if cls == "figures":
            return {"PSEUDONYMISE": "the exact figure stays on this device and is restored in the reply",
                    "GENERALISE": "the exact figure is not needed; the scale is kept",
                    "DROP": "figures are not needed for this task"}[action]
        return reasons[cls]

    items = [{"item": r["class"].replace("_", " "), "action": labels[r["action"]], "count": r["count"], "examples": r["examples"],
              "reason": reason(r["class"], r["action"])} for r in report.values()]
    return list(targets.values()), items
