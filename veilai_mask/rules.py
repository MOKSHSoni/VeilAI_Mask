"""L0 honeytokens + L1 deterministic rules + the evasion normaliser.

Ported from the VeilAI prototype (rules.ts), including the one-letter-word fix for spaced-out
secrets. Honeytokens use HMAC-SHA256 with an organisation secret (design doc §11.1): endpoints
store only HMACs, never the tokens.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets as _secrets
import unicodedata
from dataclasses import dataclass, field

from . import config


@dataclass
class RuleMatch:
    rule: str
    label: str
    value: str
    start: int
    end: int
    entity_type: str
    category: str
    labels: list[str]
    severity: str
    honeytoken_id: str | None = None
    planted_in: str | None = None


# ---------------------------------------------------------------- checksums

_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def verhoeff_valid(num: str) -> bool:
    d = _digits(num)
    if not d:
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> int:
    c = 0
    for i, ch in enumerate(reversed(_digits(num))):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return _INV[c]


def luhn_valid(num: str) -> bool:
    d = _digits(num)
    if not 13 <= len(d) <= 19:
        return False
    total, double = 0, False
    for ch in reversed(d):
        n = int(ch)
        if double:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        double = not double
    return total % 10 == 0


# ---------------------------------------------------------------- honeytokens (L0)

_SECRET_FILE = config.DATA_DIR / "org_secret.key"
_REGISTRY_FILE = config.DATA_DIR / "honeytokens.json"


def _org_secret() -> bytes:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not _SECRET_FILE.exists():
        _SECRET_FILE.write_text(_secrets.token_hex(32), encoding="utf-8")
    return bytes.fromhex(_SECRET_FILE.read_text(encoding="utf-8").strip())


def token_hmac(token: str) -> str:
    return hmac.new(_org_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def load_registry() -> list[dict]:
    if not _REGISTRY_FILE.exists():
        return []
    return json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))


def register_honeytoken(token: str, token_id: str, planted_in: str) -> dict:
    """Store only the HMAC of a planted token, plus where it was planted."""
    reg = [r for r in load_registry() if r["id"] != token_id]
    rec = {"id": token_id, "hmac": token_hmac(token), "planted_in": planted_in}
    reg.append(rec)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    _REGISTRY_FILE.write_text(json.dumps(reg, indent=2), encoding="utf-8")
    return rec


def generate_honeytoken(prefix: str = "HT") -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    n = len(load_registry()) + 1
    return f"{prefix}-{n:04d}-" + "".join(_secrets.choice(alphabet) for _ in range(12))


_CANDIDATE = re.compile(r"""[^\s"'`,;=:()\[\]{}<>]{8,}""")


def _registry_index() -> dict[str, dict]:
    return {r["hmac"]: r for r in load_registry()}


def is_honeytoken(s: str, index: dict[str, dict] | None = None) -> dict | None:
    idx = _registry_index() if index is None else index
    return idx.get(token_hmac(s)) if idx else None


def _detect_honeytokens(text: str) -> list[RuleMatch]:
    idx = _registry_index()
    if not idx:
        return []
    out = []
    for m in _CANDIDATE.finditer(text):
        rec = idx.get(token_hmac(m.group()))
        if rec:
            out.append(RuleMatch("HONEYTOKEN", f"Honeytoken {rec['id']}", m.group(), m.start(), m.end(), "HONEYTOKEN",
                                 "CREDENTIALS", ["CREDENTIALS", "SECURITY"], "CRITICAL", rec["id"], rec["planted_in"]))
    return out


# ---------------------------------------------------------------- L1 rules

@dataclass
class _Rule:
    rule: str
    label: str
    pattern: re.Pattern
    entity_type: str
    category: str
    labels: list[str]
    severity: str
    group: int = 0
    validate: object = None


def _not_placeholder(v: str) -> bool:
    return "⟦" not in v and "⟧" not in v


_KEY_WORDS = r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key)"

RULES: list[_Rule] = [
    _Rule("AWS_ACCESS_KEY", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "SECRET", "CREDENTIALS", ["CREDENTIALS", "SECURITY"], "CRITICAL"),
    _Rule("API_KEY", "API key", re.compile(r"\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
          "SECRET", "CREDENTIALS", ["CREDENTIALS", "SECURITY"], "CRITICAL"),
    _Rule("PRIVATE_KEY", "Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "SECRET", "CREDENTIALS", ["CREDENTIALS", "SECURITY"], "CRITICAL"),
    _Rule("PASSWORD", "Password / secret assignment",
          re.compile(_KEY_WORDS + r"""[\w-]*["']?\s*[:=]\s*(["'])([^"'\s]{4,})\1""", re.I), "SECRET", "CREDENTIALS",
          ["CREDENTIALS", "SECURITY"], "CRITICAL", group=2, validate=_not_placeholder),
    _Rule("PASSWORD", "Password / secret assignment",
          re.compile(_KEY_WORDS + r"""[\w-]*\s*:[ \t]*([^\s"'⟦]{6,})""", re.I), "SECRET", "CREDENTIALS",
          ["CREDENTIALS", "SECURITY"], "CRITICAL", group=1, validate=_not_placeholder),
    _Rule("CONNECTION_STRING", "Connection string with credentials",
          re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s@/]+)@", re.I), "SECRET", "CREDENTIALS",
          ["CREDENTIALS", "SECURITY"], "CRITICAL", group=1),
    _Rule("EMAIL", "Email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "EMAIL", "PERSONAL_INFORMATION", ["PERSONAL_INFORMATION"], "MEDIUM"),
    _Rule("CARD", "Payment card (Luhn)", re.compile(r"(?<!\d)(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)"), "CARD", "FINANCIAL",
          ["FINANCIAL", "PERSONAL_INFORMATION"], "CRITICAL", validate=luhn_valid),
    _Rule("AADHAAR", "Aadhaar-like number (Verhoeff)", re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"), "NATIONAL_ID",
          "PERSONAL_INFORMATION", ["PERSONAL_INFORMATION"], "HIGH", validate=verhoeff_valid),
    _Rule("INDIAN_PHONE", "Indian mobile number", re.compile(r"(?<![\w+])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?![ -]?\d)"), "PHONE",
          "PERSONAL_INFORMATION", ["PERSONAL_INFORMATION"], "MEDIUM"),
    _Rule("PAN", "PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "NATIONAL_ID", "PERSONAL_INFORMATION", ["PERSONAL_INFORMATION", "FINANCIAL"], "HIGH"),
    _Rule("INTERNAL_HOST", "Internal hostname", re.compile(r"\b(?:[a-z0-9-]+\.)+(?:internal|corp|intranet|lan)\b", re.I), "INTERNAL_HOST",
          "SECURITY", ["SECURITY"], "HIGH"),
    _Rule("PRIVATE_IP", "Private IP address", re.compile(r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"),
          "INTERNAL_HOST", "SECURITY", ["SECURITY"], "MEDIUM"),
]


def scan_rules(text: str) -> list[RuleMatch]:
    """L0 + L1 over already-normalised text. Honeytokens win overlaps; otherwise earliest, then longest."""
    found = _detect_honeytokens(text)
    for r in RULES:
        for m in r.pattern.finditer(text):
            value = m.group(r.group)
            if value is None or (r.validate and not r.validate(value)):
                continue
            start = m.start(r.group)
            found.append(RuleMatch(r.rule, r.label, value, start, start + len(value), r.entity_type, r.category, list(r.labels), r.severity))
    # Honeytokens first; then earliest; at the same spot the more severe rule wins (a password inside a
    # connection string must not be reported as an email), then the longest.
    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    found.sort(key=lambda m: (0 if m.rule == "HONEYTOKEN" else 1, sev.get(m.severity, 4), m.start, -(m.end - m.start)))
    kept: list[RuleMatch] = []
    for m in found:
        if any(m.start < k.end and k.start < m.end for k in kept):
            continue
        kept.append(m)
    return sorted(kept, key=lambda m: m.start)


# ---------------------------------------------------------------- normaliser

@dataclass
class NormaliseResult:
    text: str
    notes: list[dict] = field(default_factory=list)


_ZERO_WIDTH = re.compile("[" + chr(0x200B) + "-" + chr(0x200D) + chr(0x2060) + chr(0xFEFF) + "]")
_HOMOGLYPHS = {chr(c): r for c, r in [
    (0x0430, "a"), (0x0435, "e"), (0x043E, "o"), (0x0440, "p"), (0x0441, "c"), (0x0445, "x"), (0x0456, "i"), (0x0458, "j"),
    (0x0501, "d"), (0x0455, "s"), (0x0410, "A"), (0x0412, "B"), (0x0415, "E"), (0x041A, "K"), (0x041C, "M"), (0x041D, "H"),
    (0x041E, "O"), (0x0420, "P"), (0x0421, "C"), (0x0422, "T"), (0x0425, "X"),
]}
_CYRILLIC = re.compile("[" + chr(0x0400) + "-" + chr(0x052F) + "]")
_SPACED_RUN = re.compile(r"(?<!\S)(?:[A-Za-z0-9_+/-] ){7,}[A-Za-z0-9_+/=-](?!\S)")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_ONE_LETTER_WORD = re.compile(r"^[aAI]$")


def _matches_whole(s: str) -> bool:
    return any(m.start == 0 and m.end == len(s) for m in scan_rules(s))


def _collapse_spaced_run(run: str) -> str:
    """Join "s k _ l i v e …". A neighbouring one-letter word ("a", "I") looks like part of the run, so
    pick the reading that is a registered honeytoken or matches a rule exactly; keep both if still ambiguous."""
    chars = run.split(" ")
    joined = "".join(chars)
    lead = len(chars) > 8 and bool(_ONE_LETTER_WORD.match(chars[0]))
    trail = len(chars) > 8 and bool(_ONE_LETTER_WORD.match(chars[-1]))
    if not lead and not trail:
        return joined
    pre = f"{chars[0]} " if lead else ""
    post = f" {chars[-1]}" if trail else ""
    split = []
    if lead and trail:
        split.append((joined[1:-1], f"{pre}{joined[1:-1]}{post}"))
    if lead:
        split.append((joined[1:], f"{pre}{joined[1:]}"))
    if trail:
        split.append((joined[:-1], f"{joined[:-1]}{post}"))
    candidates = [(joined, joined)] + split
    idx = _registry_index()
    for core, text in candidates:
        if is_honeytoken(core, idx):
            return text
    for core, text in split:
        if _matches_whole(core):
            return text
    if _matches_whole(joined):
        return joined
    return f"{joined} {split[0][1]}"


def _decode_b64(s: str) -> str | None:
    if len(s) % 4:
        return None
    try:
        out = base64.b64decode(s, validate=True).decode("ascii")
    except Exception:
        return None
    if len(out) < 6 or not all(32 <= ord(c) < 127 for c in out):
        return None
    return out if sum(c.isalnum() for c in out) / len(out) >= 0.6 else None


def normalise(text: str) -> NormaliseResult:
    """Defeats simple evasion: zero-width characters, homoglyphs, spaced-out characters, base64."""
    notes: list[dict] = []
    t = unicodedata.normalize("NFKC", text)
    if _ZERO_WIDTH.search(t):
        notes.append({"before": "zero-width characters", "after": "(removed)", "method": "Strip zero-width characters"})
        t = _ZERO_WIDTH.sub("", t)

    def fold(m: re.Match) -> str:
        ch = m.group()
        if ch in _HOMOGLYPHS:
            notes.append({"before": ch, "after": _HOMOGLYPHS[ch], "method": "Fold homoglyph"})
            return _HOMOGLYPHS[ch]
        return ch

    t = _CYRILLIC.sub(fold, t)

    def collapse(m: re.Match) -> str:
        after = _collapse_spaced_run(m.group())
        notes.append({"before": m.group(), "after": after, "method": "Collapse spaced-out characters"})
        return after

    t = _SPACED_RUN.sub(collapse, t)

    def b64(m: re.Match) -> str:
        cand = m.group()
        if not re.search(r"[0-9+/=]", cand) and not re.search(r"[a-z][A-Z]|[A-Z][a-z].*[A-Z]", cand):
            return cand
        dec = _decode_b64(cand)
        if not dec:
            return cand
        notes.append({"before": cand, "after": dec, "method": "Decode base64"})
        return dec

    t = _B64.sub(b64, t)
    return NormaliseResult(t, notes)
