"""Rehydration: restore placeholders in the external AI's reply using the local vault.

Tolerant to case, spacing and bracket changes (⟦emp_01⟧, ⟦ EMP 01 ⟧, [[EMP_01]]).
Secrets are never restored unless explicitly requested for a local-only view.
"""
from __future__ import annotations

import re

from .masking import VaultEntry

_TOKEN = re.compile(r"⟦\s*([A-Za-z][A-Za-z0-9_ ]{0,40}?)\s*⟧|\[\[\s*([A-Za-z][A-Za-z0-9_ ]{0,40}?)\s*\]\]")


def _canon(inner: str) -> str:
    return re.sub(r"[\s_]+", "_", inner.strip().upper())


def rehydrate(reply: str, vault: list[VaultEntry], restore_secrets: bool = False) -> dict:
    by_key = {_canon(e.placeholder[1:-1]): e for e in vault}
    parts, segments, unresolved = [], [], []
    restored = secrets_kept = 0
    cursor = 0
    for m in _TOKEN.finditer(reply):
        if m.start() > cursor:
            segments.append({"kind": "text", "text": reply[cursor:m.start()]})
            parts.append(reply[cursor:m.start()])
        raw = m.group()
        e = by_key.get(_canon(m.group(1) or m.group(2) or ""))
        if e is None:
            segments.append({"kind": "unresolved", "raw": raw})
            unresolved.append(raw)
            parts.append(raw)
        elif e.secret and not restore_secrets:
            segments.append({"kind": "secret", "placeholder": e.placeholder, "raw": raw})
            secrets_kept += 1
            parts.append(e.placeholder)
        else:
            segments.append({"kind": "restored", "placeholder": e.placeholder, "raw": raw, "value": e.original})
            restored += 1
            parts.append(e.original)
        cursor = m.end()
    if cursor < len(reply):
        segments.append({"kind": "text", "text": reply[cursor:]})
        parts.append(reply[cursor:])
    return {"text": "".join(parts), "segments": segments, "restored": restored, "secrets_kept": secrets_kept, "unresolved": unresolved}
