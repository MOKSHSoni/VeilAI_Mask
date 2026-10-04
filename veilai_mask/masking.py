"""Context-preserving masking (deterministic; the LLM never rewrites text). Ported from masking.ts.

* Role-preserving placeholders: Rahul Mehta → ⟦EMP_01⟧, Acme Corp → ⟦CLIENT_A⟧, keys → ⟦SECRET_1⟧.
* The same original always maps to the same placeholder (relationships survive).
* Longest span wins on overlap; placeholders numbered per prefix by first appearance.
* GENERALISE targets are replaced by a coarser value (₹4.37 Cr → about ₹4 Cr) and are not restorable.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

OPEN, CLOSE = "⟦", "⟧"
SECRET_TYPES = {"SECRET", "HONEYTOKEN", "CARD", "BANK_ACCOUNT"}

_PREFIX = {
    "PERSON": ("EMP", "pad2"), "CUSTOMER": ("CUSTOMER", "pad2"), "CLIENT": ("CLIENT", "letter"), "ORG": ("ORG", "letter"),
    "PROJECT": ("PROJECT", "pad2"), "SECRET": ("SECRET", "plain"), "HONEYTOKEN": ("SECRET", "plain"), "CARD": ("CARD", "plain"),
    "BANK_ACCOUNT": ("ACCOUNT", "plain"), "INTERNAL_HOST": ("INTERNAL_HOST", "plain"), "MONEY": ("AMOUNT", "plain"),
    "EMAIL": ("EMAIL", "plain"), "PHONE": ("PHONE", "plain"), "NATIONAL_ID": ("ID", "plain"), "ADDRESS": ("ADDRESS", "plain"),
    "CUSTOMER_ID": ("CUSTOMER_ID", "plain"), "STRATEGY": ("DETAIL", "plain"),
}


@dataclass
class MaskTarget:
    original: str
    entity_type: str
    category: str = ""
    aliases: list[str] = field(default_factory=list)
    generalise_to: str | None = None   # GENERALISE: replace with this text instead of a placeholder


@dataclass
class VaultEntry:
    placeholder: str
    original: str
    aliases: list[str]
    entity_type: str
    category: str
    secret: bool


@dataclass
class MaskResult:
    text: str
    vault: list[VaultEntry]
    replacements: list[dict]      # {start, end, matched, replacement, kind}


def _prefix(entity_type: str) -> tuple[str, str]:
    return _PREFIX.get(entity_type, (re.sub(r"[^A-Z]+", "_", entity_type.upper()).strip("_") or "ITEM", "plain"))


def _index(n: int, numbering: str) -> str:
    if numbering == "pad2":
        return f"{n:02d}"
    if numbering == "letter":
        s = ""
        while n > 0:
            n, r = divmod(n - 1, 26)
            s = chr(65 + r) + s
        return s
    return str(n)


def _word(ch: str | None) -> bool:
    return bool(ch) and (ch.isalnum() or ch == "_")


def find_occurrences(text: str, term: str, case_insensitive: bool = False) -> list[int]:
    """Occurrences of `term` not glued to other word characters."""
    if not term:
        return []
    hay, needle = (text.lower(), term.lower()) if case_insensitive else (text, term)
    out, i = [], hay.find(needle)
    while i != -1:
        before = text[i - 1] if i > 0 else None
        after = text[i + len(term)] if i + len(term) < len(text) else None
        ok_start = not _word(term[0]) or not _word(before)
        ok_end = not _word(term[-1]) or not _word(after)
        if ok_start and ok_end:
            out.append(i)
        i = hay.find(needle, i + 1)
    return out


def mask(content: str, targets: list[MaskTarget]) -> MaskResult:
    by_original: dict[str, MaskTarget] = {}
    for t in targets:
        if not t.original.strip():
            continue
        if t.original in by_original:
            for a in t.aliases:
                if a not in by_original[t.original].aliases:
                    by_original[t.original].aliases.append(a)
        else:
            by_original[t.original] = MaskTarget(t.original, t.entity_type, t.category, list(t.aliases), t.generalise_to)

    terms = []
    for t in by_original.values():
        terms.append((t.original, t.original))
        terms += [(a, t.original) for a in t.aliases if a and a != t.original]
    terms.sort(key=lambda x: -len(x[0]))

    claimed: list[tuple[int, int, str, str]] = []
    for term, original in terms:
        for s in find_occurrences(content, term):
            e = s + len(term)
            if any(s < c[1] and c[0] < e for c in claimed):
                continue
            claimed.append((s, e, term, original))
    claimed.sort()

    counters: dict[str, int] = {}
    vault: dict[str, VaultEntry] = {}
    for _, _, _, original in claimed:
        t = by_original[original]
        if original in vault or t.generalise_to is not None:
            continue
        prefix, numbering = _prefix(t.entity_type)
        counters[prefix] = counters.get(prefix, 0) + 1
        vault[original] = VaultEntry(f"{OPEN}{prefix}_{_index(counters[prefix], numbering)}{CLOSE}", original, t.aliases,
                                     t.entity_type, t.category, t.entity_type in SECRET_TYPES)

    out, cursor, reps = [], 0, []
    for s, e, matched, original in claimed:
        t = by_original[original]
        rep = t.generalise_to if t.generalise_to is not None else vault[original].placeholder
        if t.generalise_to is not None and rep.startswith("about ") and re.search(
                r"\b(?:near|around|about|approximately|roughly|nearly|almost|over|under)\s*$", content[max(0, s - 16):s], re.I):
            rep = rep[len("about "):]
        out.append(content[cursor:s] + rep)
        reps.append({"start": s, "end": e, "matched": matched, "replacement": rep,
                     "kind": "generalised" if t.generalise_to is not None else "placeholder"})
        cursor = e
    out.append(content[cursor:])
    return MaskResult("".join(out), list(vault.values()), reps)


# ---------------------------------------------------------------- generalisation

_MONEY_NUM = re.compile(r"(\d[\d,]*(?:\.\d+)?)")


def generalise_money(text: str) -> str:
    """₹4.37 Cr → about ₹4 Cr; $412,500 → about $400,000 (one significant figure)."""
    m = _MONEY_NUM.search(text)
    if not m:
        return "an amount"
    try:
        v = float(m.group(1).replace(",", ""))
    except ValueError:
        return "an amount"
    if v <= 0:
        return "an amount"
    mag = 10 ** math.floor(math.log10(v))
    rounded = round(v / mag) * mag
    s = f"{rounded:,.0f}" if rounded >= 1 else f"{rounded:g}"
    return "about " + text[:m.start()] + s + text[m.end():]


# ---------------------------------------------------------------- tables (CSV)

def parse_csv(text: str) -> tuple[list[str], list[list[str]]] | None:
    """Very small CSV detector: a header row plus at least 2 rows with the same column count."""
    import csv
    import io

    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if len(lines) < 3 or "," not in lines[0]:
        return None
    rows = list(csv.reader(io.StringIO("\n".join(lines))))
    n = len(rows[0])
    if n < 2 or any(len(r) != n for r in rows[1:]):
        return None
    return rows[0], rows[1:]


def table_to_csv(header: list[str], rows: list[list[str]]) -> str:
    import csv
    import io

    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().strip()
