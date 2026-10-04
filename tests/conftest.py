"""Unit tests run fully offline: L2 off, L5 off (or a fake model), and a temporary data folder."""
import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="veilai_mask_test_")
os.environ["VEILAI_DATA"] = _TMP
os.environ["VEILAI_L2"] = "0"
os.environ["VEILAI_L5"] = "off"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from veilai_mask.models import Finding  # noqa: E402

NAMES = ["Rahul Mehta", "Priya Nair"]


class FakeNER:
    """Stands in for Presidio + GLiNER offline: recognises a few known person names."""
    available, error, _ready = True, "", True

    def load(self):
        return True

    def scan(self, text, offset=0):
        out = []
        for n in NAMES:
            i = text.find(n)
            if i >= 0:
                out.append(Finding("L2", "PERSONAL_INFORMATION", ["PERSONAL_INFORMATION"], "PERSON", "MEDIUM", 0.9, "weak",
                                   n, offset + i, offset + i + len(n), "fake NER person", flags=False))
        return out


@pytest.fixture(autouse=True)
def fake_ner(monkeypatch):
    from veilai_mask import pipeline
    monkeypatch.setattr(pipeline, "NER", FakeNER)
    from veilai_mask import api
    monkeypatch.setattr(api.engine, "ner", FakeNER())
