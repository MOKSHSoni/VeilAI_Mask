"""L3 Org DNA: the organisation's own confidential documents and terms.

* MinHash fingerprints of registered documents (data/org_dna/*.txt). Only fingerprints are kept in
  memory; a match reports which document matched and the containment score.
* Codename dictionary (data/codenames.json): exact term hits, e.g. internal project names.
* Allowlist (data/allowlist.json): terms an analyst approved as public; never flagged.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import config
from .models import Finding

try:
    from datasketch import MinHash, MinHashLSHEnsemble
except ImportError:  # pragma: no cover
    MinHash = MinHashLSHEnsemble = None

ORG_DIR = config.DATA_DIR / "org_dna"
CODENAMES_FILE = config.DATA_DIR / "codenames.json"
ALLOWLIST_FILE = config.DATA_DIR / "allowlist.json"


def _shingles(text: str) -> set[str]:
    words = re.sub(r"[^\w\s]", " ", text.lower()).split()
    k = config.ORG_DNA_SHINGLE
    return {" ".join(words[i:i + k]) for i in range(max(1, len(words) - k + 1))}


def _minhash(sh: set[str]):
    m = MinHash(num_perm=config.ORG_DNA_PERM)
    for s in sh:
        m.update(s.encode("utf8"))
    return m


def _read_json(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


class OrgDNA:
    def __init__(self):
        self.reload()

    def reload(self) -> None:
        ORG_DIR.mkdir(parents=True, exist_ok=True)
        self.docs: dict[str, set[str]] = {p.stem: _shingles(p.read_text(encoding="utf-8")) for p in sorted(ORG_DIR.glob("*.txt"))}
        self.codenames: list[str] = _read_json(CODENAMES_FILE, [])
        self.allowlist: list[str] = _read_json(ALLOWLIST_FILE, [])
        self.index = None
        if MinHash and self.docs:
            self.index = MinHashLSHEnsemble(threshold=config.ORG_DNA_THRESHOLD, num_perm=config.ORG_DNA_PERM, num_part=4)
            self.index.index([(k, _minhash(v), len(v)) for k, v in self.docs.items()])

    # ---- management
    def register_document(self, name: str, text: str) -> None:
        safe = re.sub(r"[^\w.-]+", "_", name).strip("_") or "document"
        (ORG_DIR / f"{safe}.txt").write_text(text, encoding="utf-8")
        self.reload()

    def add_codename(self, term: str) -> None:
        if term not in self.codenames:
            self.codenames.append(term)
            CODENAMES_FILE.write_text(json.dumps(self.codenames, indent=2), encoding="utf-8")

    def add_to_allowlist(self, term: str) -> None:
        if term.lower() not in (t.lower() for t in self.allowlist):
            self.allowlist.append(term)
            ALLOWLIST_FILE.write_text(json.dumps(self.allowlist, indent=2), encoding="utf-8")

    def is_allowlisted(self, text: str) -> bool:
        return text.strip().lower() in (t.lower() for t in self.allowlist)

    # ---- detection
    def scan(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        if self.index is not None:
            sh = _shingles(text)
            for doc_id in self.index.query(_minhash(sh), len(sh)):
                containment = len(sh & self.docs[doc_id]) / max(1, len(sh))
                if containment >= config.ORG_DNA_THRESHOLD:
                    found.append(Finding("L3", "CONFIDENTIAL_BUSINESS", ["CONFIDENTIAL_BUSINESS"], "ORG_DOCUMENT", "HIGH",
                                         round(min(1.0, 0.5 + containment / 2), 2), "strong",
                                         detail=f"{round(containment * 100)}% fingerprint match with registered document '{doc_id}'"))
        for term in self.codenames:
            if self.is_allowlisted(term):
                continue
            for m in re.finditer(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.I):
                found.append(Finding("L3", "INTELLECTUAL_PROPERTY", ["INTELLECTUAL_PROPERTY", "CONFIDENTIAL_BUSINESS"], "PROJECT",
                                     "MEDIUM", 0.75, "strong", m.group(), m.start(), m.end(), "codename dictionary hit"))
        return found
