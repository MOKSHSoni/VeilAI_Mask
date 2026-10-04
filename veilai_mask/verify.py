"""Fast local verification (deterministic; no second LLM pass). Ported from verification.ts.

Checks: (1) no vault value or dropped value in the output, (2) no variant (first name, surname,
possessive, initials, spacing, short forms), (3) L0+L1 re-scan of the normalised output is clean,
(4) placeholders well-formed and in the vault, (5) one original ↔ one placeholder.
On failure: add the leak to the vault under the right placeholder, re-mask, re-verify once.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .masking import CLOSE, OPEN, MaskResult, MaskTarget, VaultEntry, find_occurrences, mask
from .rules import normalise, scan_rules

_PERSON = {"PERSON", "EMPLOYEE", "CUSTOMER"}
_ORG = {"CLIENT", "ORG"}
_ORG_SUFFIX = re.compile(r"^(corp|corporation|ltd|limited|inc|pvt|llp|llc|co|traders|group|holdings)\.?$", re.I)
_PH_ANY = re.compile(f"{OPEN}[^{OPEN}{CLOSE}]*{CLOSE}")
_PH_STRICT = re.compile(f"^{OPEN}[A-Z]+(?:_[A-Z]+)*_(?:\\d+|[A-Z]+){CLOSE}$")


@dataclass
class Leak:
    found: str
    alias: str
    placeholder: str
    original: str
    kind: str


@dataclass
class VerifyResult:
    passed: bool
    checks: list[dict]
    leaks: list[Leak] = field(default_factory=list)
    pattern_leaks: list = field(default_factory=list)


def variants_of(original: str, entity_type: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def push(v: str, kind: str):
        if v and v != original and len(v) >= 3 and all(v.lower() != o[0].lower() for o in out):
            out.append((v, kind))

    words = original.split()
    if entity_type in _PERSON and len(words) >= 2:
        push(words[0], "first name")
        push(words[-1], "surname")
        push(f"{words[0][0]}. {words[-1]}", "initials")
    if entity_type in _ORG and len(words) >= 2:
        core = [w for w in words if not _ORG_SUFFIX.match(w)]
        if core and len(core) < len(words):
            push(" ".join(core), "short form")
    if entity_type == "PROJECT" and len(words) >= 2 and words[0].lower() == "project":
        push(" ".join(words[1:]), "short form")
    if entity_type == "EMAIL" and "@" in original:
        push(original.split("@")[0], "email local part")
    if entity_type == "INTERNAL_HOST" and "." in original and len(original.split(".")[0]) >= 4:
        push(original.split(".")[0], "short form")
    if len(words) >= 2:
        push("-".join(words), "spacing variant")
        push("".join(words), "spacing variant")
        push("_".join(words), "spacing variant")
    if "-" in original:
        push(original.replace("-", " "), "spacing variant")
        push(original.replace("-", ""), "spacing variant")
    return out


def verify(text: str, vault: list[VaultEntry], dropped: list[str] | None = None) -> VerifyResult:
    leaks: list[Leak] = []
    seen: set[str] = set()

    def add(l: Leak):
        k = f"{l.placeholder}|{l.found.lower()}"
        if k not in seen:
            seen.add(k)
            leaks.append(l)

    for e in vault:
        for term, kind in [(e.original, "original")] + [(a, "alias") for a in e.aliases]:
            for i in find_occurrences(text, term, True):
                f = text[i:i + len(term)]
                add(Leak(f, f, e.placeholder, e.original, kind))
    for d in dropped or []:
        for i in find_occurrences(text, d, True):
            add(Leak(text[i:i + len(d)], d, "", d, "dropped"))
    n_vault = len(leaks)

    claimed: list[tuple[int, int]] = []
    for e in vault:
        if e.secret:
            continue
        known = {s.lower() for s in [e.original, *e.aliases]}
        for value, kind in sorted(variants_of(e.original, e.entity_type), key=lambda x: -len(x[0])):
            if value.lower() in known:
                continue
            for i in find_occurrences(text, value, True):
                end = i + len(value)
                if any(i < t and s < end for s, t in claimed):
                    continue
                claimed.append((i, end))
                base = text[i:end]
                poss = text[end:end + 2] if text[end:end + 2] in ("'s", "’s") else ""
                add(Leak(base + poss, base, e.placeholder, e.original, "possessive" if poss else kind))
    variant_leaks = leaks[n_vault:]

    pattern_leaks = scan_rules(normalise(text).text)

    phs = {e.placeholder for e in vault}
    found = _PH_ANY.findall(text)
    bad = [p for p in found if not _PH_STRICT.match(p) or p not in phs]
    balanced = text.count(OPEN) == text.count(CLOSE) == len(found)

    owners: dict[str, str] = {}
    consistent = len(phs) == len(vault)
    for e in vault:
        for form in [e.original, *e.aliases]:
            if owners.get(form, e.placeholder) != e.placeholder:
                consistent = False
            owners[form] = e.placeholder

    checks = [
        {"id": "vault", "label": "No vault value in output", "passed": n_vault == 0,
         "detail": f"{len(vault)} vault values" + (f" + {len(dropped)} dropped values" if dropped else "") + " absent" if n_vault == 0
         else "Found " + ", ".join(f'"{l.found}"' for l in leaks[:n_vault])},
        {"id": "variants", "label": "No variant of a vault value", "passed": not variant_leaks,
         "detail": "First name, surname, possessive, spacing and short-form variants absent" if not variant_leaks
         else ", ".join(f'"{l.found}" ({l.kind} of {l.placeholder})' for l in variant_leaks)},
        {"id": "patterns", "label": "No known sensitive patterns remain", "passed": not pattern_leaks,
         "detail": "L0 + L1 re-scan of the normalised output: clean" if not pattern_leaks
         else ", ".join(f'{p.label}: "{p.value}"' for p in pattern_leaks)},
        {"id": "placeholders", "label": "Placeholders well-formed and in vault", "passed": not bad and balanced,
         "detail": f"{len(found)} placeholders resolved" if not bad and balanced else "Unresolved: " + (", ".join(bad) or "unbalanced brackets")},
        {"id": "consistency", "label": "Mappings consistent (1 original → 1 placeholder)", "passed": consistent,
         "detail": f"{len(vault)} one-to-one mappings" if consistent else "A value maps to more than one placeholder"},
    ]
    return VerifyResult(all(c["passed"] for c in checks), checks, leaks, pattern_leaks)


@dataclass
class VerificationOutcome:
    status: str                      # PASS | REPAIRED | REVIEW
    attempts: list[tuple[MaskResult, VerifyResult]]
    repairs: list[dict]
    final: MaskResult
    targets: list[MaskTarget]


def mask_and_verify(content: str, targets: list[MaskTarget], dropped: list[str] | None = None) -> VerificationOutcome:
    first = mask(content, targets)
    r1 = verify(first.text, first.vault, dropped)
    if r1.passed:
        return VerificationOutcome("PASS", [(first, r1)], [], first, targets)

    repaired = [MaskTarget(t.original, t.entity_type, t.category, list(t.aliases), t.generalise_to) for t in targets]
    repairs: list[dict] = []
    for leak in r1.leaks:
        if leak.kind == "dropped":
            repaired.append(MaskTarget(leak.original, "DROPPED"))
            repairs.append({"found": leak.found, "note": "Dropped value reappeared; masked"})
            continue
        t = next((x for x in repaired if x.original == leak.original), None)
        if t and leak.alias not in t.aliases and leak.alias != t.original:
            t.aliases.append(leak.alias)
            repairs.append({"found": leak.found, "note": f'Added "{leak.alias}" to the vault as {leak.kind} of {leak.placeholder}'})
    for p in r1.pattern_leaks:
        if p.value in content and not any(t.original == p.value for t in repaired):
            repaired.append(MaskTarget(p.value, p.entity_type, p.category))
            repairs.append({"found": p.value, "note": f"{p.label} masked on re-scan"})

    second = mask(content, repaired)
    r2 = verify(second.text, second.vault, dropped)
    return VerificationOutcome("REPAIRED" if r2.passed else "REVIEW", [(first, r1), (second, r2)], repairs, second, repaired)
