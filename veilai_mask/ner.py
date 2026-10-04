"""L2 entity NER: Presidio (pattern + spaCy recognisers) + GLiNER (zero-shot labels).

Personal identifiers (address, customer id, bank account, date of birth, medical condition, plus
Presidio's ID / card recognisers) are weak signals. Names of people, organisations and projects are
recorded as masking targets but never raise risk on their own: names appear in plenty of safe text.
Loaded lazily; if the packages are missing the layer reports UNAVAILABLE and the engine keeps working.
"""
from __future__ import annotations

import logging
import threading

from . import config
from .models import Finding

log = logging.getLogger(__name__)

_PRESIDIO_FLAG = {
    "CREDIT_CARD": ("FINANCIAL", "CARD"), "IBAN_CODE": ("FINANCIAL", "BANK_ACCOUNT"), "US_BANK_NUMBER": ("FINANCIAL", "BANK_ACCOUNT"),
    "US_SSN": ("PERSONAL_INFORMATION", "NATIONAL_ID"), "US_PASSPORT": ("PERSONAL_INFORMATION", "NATIONAL_ID"),
    "IN_PAN": ("PERSONAL_INFORMATION", "NATIONAL_ID"), "IN_AADHAAR": ("PERSONAL_INFORMATION", "NATIONAL_ID"),
    "IN_PASSPORT": ("PERSONAL_INFORMATION", "NATIONAL_ID"), "IN_VOTER": ("PERSONAL_INFORMATION", "NATIONAL_ID"),
}
_GLINER_FLAG = {
    "address": ("PERSONAL_INFORMATION", "ADDRESS"), "customer id": ("CUSTOMER_INFORMATION", "CUSTOMER_ID"),
    "bank account number": ("FINANCIAL", "BANK_ACCOUNT"), "date of birth": ("PERSONAL_INFORMATION", "NATIONAL_ID"),
    "medical condition": ("PERSONAL_INFORMATION", "MEDICAL"),
}
_GLINER_RECORD = {"person": ("PERSONAL_INFORMATION", "PERSON"), "organisation": ("CONFIDENTIAL_BUSINESS", "ORG"),
                  "project codename": ("INTELLECTUAL_PROPERTY", "PROJECT")}


# Department / generic words GLiNER sometimes tags as organisations; never masking targets.
_NOT_ORG = {"hr", "it", "finance", "legal", "sales", "marketing", "operations", "engineering", "board", "team", "management",
            "leadership", "admin", "security", "support", "procurement", "payroll", "ops", "devops", "qa", "r&d", "company"}


def _load_gliner_offline_first(GLiNER):
    """Load GLiNER from the local cache without touching the network. Only if the model has never been
    downloaded (first setup) is the Hugging Face hub contacted, once, to fetch the weights."""
    import os

    prev = os.environ.get("HF_HUB_OFFLINE")
    os.environ["HF_HUB_OFFLINE"] = "1"
    try:
        return GLiNER.from_pretrained(config.GLINER_MODEL, local_files_only=True)
    except Exception:
        log.warning("GLiNER model not cached yet: downloading it once")
        os.environ.pop("HF_HUB_OFFLINE", None)
        return GLiNER.from_pretrained(config.GLINER_MODEL)
    finally:
        if prev is None:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")  # stay offline for the rest of the process
        else:
            os.environ["HF_HUB_OFFLINE"] = prev


class NER:
    def __init__(self):
        self._lock = threading.Lock()
        self._ready = False
        self.available = config.L2_ENABLED
        self.error = "" if config.L2_ENABLED else "disabled (VEILAI_L2=0)"

    def load(self) -> bool:
        if self._ready or not self.available:
            return self._ready
        with self._lock:
            if self._ready:
                return True
            try:
                from gliner import GLiNER
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider

                nlp = NlpEngineProvider(nlp_configuration={
                    "nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]}).create_engine()
                self.presidio = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
                self.gliner = _load_gliner_offline_first(GLiNER)
                self._ready = True
            except Exception as e:  # missing packages or model download blocked
                self.available = False
                self.error = f"{type(e).__name__}: {e}"
                log.warning("L2 NER unavailable: %s", self.error)
        return self._ready

    def scan(self, text: str, offset: int = 0) -> list[Finding]:
        if not self.load():
            return []
        out: list[Finding] = []
        for r in self.presidio.analyze(text=text, language="en"):
            if r.score < config.NER_THRESHOLD or r.entity_type not in _PRESIDIO_FLAG:
                continue
            cat, et = _PRESIDIO_FLAG[r.entity_type]
            out.append(Finding("L2", cat, [cat], et, "HIGH", round(r.score, 2), "weak", text[r.start:r.end],
                               offset + r.start, offset + r.end, f"Presidio {r.entity_type}"))
        labels = list(_GLINER_FLAG) + list(_GLINER_RECORD)
        for e in self.gliner.predict_entities(text, labels, threshold=config.NER_THRESHOLD):
            if e["label"] == "organisation":
                name = e["text"].strip()
                # A real organisation name is a proper noun or acronym, not a description ("a mid-size firm").
                if name.lower() in _NOT_ORG or len(name) < 3 or not any(w[:1].isupper() for w in name.split()):
                    continue
            if e["label"] in _GLINER_FLAG:
                cat, et = _GLINER_FLAG[e["label"]]
                flags = True
            else:
                cat, et = _GLINER_RECORD[e["label"]]
                flags = False
            out.append(Finding("L2", cat, [cat], et, "MEDIUM", round(float(e["score"]), 2), "weak", e["text"],
                               offset + e["start"], offset + e["end"], f"GLiNER {e['label']}", flags=flags))
        return out
