"""Shared data types."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    layer: str              # L0 … L5
    category: str           # primary category
    labels: list[str]
    entity_type: str        # PERSON, EMAIL, SECRET, MONEY, STRATEGY, …
    severity: str           # SAFE … CRITICAL (impact)
    confidence: float       # 0–1 (how sure)
    strength: str           # "strong" flags alone; "weak" only with a second weak layer (else REVIEW)
    text: str = ""          # exact span in the normalised text ("" for document-level findings)
    start: int = -1
    end: int = -1
    detail: str = ""        # rule label, cue id, model reason, matched document …
    flags: bool = True      # False = recorded (e.g. a person's name) but does not raise risk on its own

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LayerReport:
    layer: str
    name: str
    status: str             # CLEAR | FLAGGED | SKIPPED | UNAVAILABLE
    ms: float
    findings: int = 0
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Chunk:
    index: int
    start: int
    text: str
    l5: str = "pending"     # ran | skipped:<reason> | off
    meta: dict = field(default_factory=dict)
