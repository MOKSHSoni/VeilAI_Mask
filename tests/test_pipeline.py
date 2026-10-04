"""End-to-end pipeline with deterministic layers; L5 replaced by a fake model where needed."""
import pytest

from veilai_mask.llm import LLM
from veilai_mask.pipeline import VeilAIMask
from veilai_mask.rules import register_honeytoken

CSV = ("name,email,phone,city,total_spend\nAarav Sharma,aarav@example.com,9876543210,Pune,12400\n"
       "Diya Patel,diya@example.com,9123456780,Ahmedabad,8650\nKabir Rao,kabir@example.com,9988776655,Bengaluru,15320")


@pytest.fixture
def eng():
    register_honeytoken("HT-0042-7QX9VL3MZK81", "HT-0042", "finance-reports repository config")
    return VeilAIMask()


def test_secrets_masked_critical_no_override(eng):
    r = eng.scan("Why does this connection fail?", 'AWS_ACCESS_KEY_ID = "AKIAQ7X3VEILDEMO4K2P"\nDB_PASSWORD = "Tr0ub4dor&Falcon!"\nhost="pg-billing-01.corp.internal"')
    assert r["risk"]["level"] == "CRITICAL"
    assert "AKIA" not in r["outbound"] and "Tr0ub4dor" not in r["outbound"] and "corp.internal" not in r["outbound"]
    assert "⟦SECRET_1⟧" in r["outbound"] and "⟦INTERNAL_HOST_1⟧" in r["outbound"]
    assert "OVERRIDE" not in r["recommendation"]["allowed"]
    assert r["verification"]["status"] == "PASS"


def test_honeytoken_blocked(eng):
    r = eng.scan("Tidy this config", "access_token: HT-0042-7QX9VL3MZK81")
    assert r["blocked"] and r["outbound"] is None and r["recommendation"]["allowed"] == ["BLOCK"]
    assert "finance-reports" in r["risk"]["honeytoken_source"]


def test_safe_sent_unchanged(eng):
    r = eng.scan("Explain the difference between TCP and UDP.")
    assert r["risk"]["level"] == "SAFE" and r["outbound"] == "Explain the difference between TCP and UDP." and r["vault"] == []


def test_table_minimised(eng):
    r = eng.scan("Calculate the average customer spending.", CSV)
    assert r["table"]["kept_columns"] == ["total_spend"]
    assert r["outbound"].endswith("total_spend\n12400\n8650\n15320")
    for leak in ("Aarav", "aarav@example.com", "9876543210", "Pune"):
        assert leak not in r["outbound"]
    assert r["risk"]["level"] == "HIGH" and r["fusion"]["bulk_personal_data"]


def test_evasion(eng):
    spaced = " ".join("sk_live_" "4eC39HqLyjWDarjtT1zdp7dc")
    r = eng.scan("Why is this key rejected?", f"PAYMENTS_KEY = {spaced}\ndb_pass_b64: VmVpbERlbW8hUGFzc3cwcmQ=")
    assert len(r["normalisation"]) == 2 and r["risk"]["level"] == "CRITICAL"
    assert "PAYMENTS_KEY = ⟦SECRET_1⟧" in r["outbound"] and "db_pass_b64: ⟦SECRET_2⟧" in r["outbound"]


def test_fusion_rule_weak_signals(eng):
    one_weak = eng.scan("Who do I contact?", "Write to press@example.com for media questions.")
    assert one_weak["fusion"]["verdict"] == "REVIEW" and one_weak["risk"]["level"] == "REVIEW"
    two_weak = eng.scan("Reply to this", "This is strictly confidential. Contact priya@example.com.")
    assert two_weak["fusion"]["verdict"] == "SENSITIVE"


def test_orgdna_and_allowlist(eng):
    doc = ("Minutes of the board meeting held on 14 August. The board reviewed the proposal to acquire Brightline Logistics "
           "and authorised management to enter exclusive negotiations for a period of sixty days. The indicative valuation "
           "range discussed was between 380 and 420 crore, subject to due diligence on the cold chain business.")
    eng.orgdna.register_document("board_minutes", doc)
    r = eng.scan("Summarise this", "The board reviewed the proposal to acquire Brightline Logistics and authorised management "
                                   "to enter exclusive negotiations for a period of sixty days.")
    assert any(f["layer"] == "L3" and f["entity_type"] == "ORG_DOCUMENT" for f in r["findings"])
    assert r["recommendation"]["default"] == "ANSWER_LOCALLY" or r["risk"]["level"] in ("HIGH", "CRITICAL")
    eng.orgdna.add_codename("Project Atlas")
    assert eng.scan("Summarise", "Today we launch Project Atlas.")["risk"]["level"] != "SAFE"
    eng.orgdna.add_to_allowlist("Project Atlas")
    assert eng.scan("Summarise", "Today we launch Project Atlas.")["risk"]["level"] == "SAFE"


def test_mosaic_session(eng):
    sid = "test-session"
    eng.scan("Draft a follow-up", "Follow up with Northwind Traders about the renewal.", session_id=sid)
    eng.scan("Is this big?", "The renewal is worth about ₹12 Cr.", session_id=sid)
    r = eng.scan("Plan the timeline", "We expect to sign by 15 November.", session_id=sid)
    # Without L2 the counterparty facet is not detected, so the mosaic needs the amount + timeline + an org entity.
    assert r["session"]["messages"] == 3 and "timeline" in r["session"]["facets"] and "amount" in r["session"]["facets"]


def test_l5_verified_quote_and_hallucination_guard(eng, monkeypatch):
    calls = []

    def fake_ask(self, category, chunk):
        calls.append(category)
        if category == "CONFIDENTIAL_BUSINESS":
            return {"sensitive": True, "evidence": "approved talks to buy a rival", "confidence": 0.9, "cached": False, "seconds": 0}
        return {"sensitive": False, "evidence": "", "confidence": 0.8, "cached": False, "seconds": 0}

    monkeypatch.setattr(LLM, "ask", fake_ask)
    monkeypatch.setattr(LLM, "health", lambda self: {"model_installed": True})
    r = eng.scan("Summarise", "Leadership approved talks to buy a rival next quarter.", l5_mode="always")
    assert calls == ["FINANCIAL", "CONFIDENTIAL_BUSINESS", "INTELLECTUAL_PROPERTY"]
    l5 = [f for f in r["findings"] if f["layer"] == "L5"]
    assert l5 and l5[0]["strong"] and r["fusion"]["verdict"] == "SENSITIVE"


def test_gating_skips_critical_chunks(eng, monkeypatch):
    monkeypatch.setattr(LLM, "health", lambda self: {"model_installed": True})
    monkeypatch.setattr(LLM, "ask", lambda self, c, ch: pytest.fail("L5 must not run on a CRITICAL chunk"))
    r = eng.scan("Fix", 'API_KEY = "sk_live_' '4eC39HqLyjWDarjtT1zdp7dc" in our deployment notes for the team', l5_mode="gated")
    assert r["chunks"][0]["l5"].startswith("skipped: chunk already CRITICAL")


def test_rehydrate_and_answer_flow(eng):
    r = eng.scan("Help me write this HR email.", "Draft an email telling Rahul Mehta his salary goes to ₹18.5 LPA. Mention that Rahul's review was the reason.")
    assert r["verification"]["status"] == "REPAIRED"
    assert "Rahul" not in r["outbound"] and "18.5" not in r["outbound"]
    back = eng.rehydrate(r["scan_id"], "Dear ⟦EMP_01⟧, your salary is now ⟦AMOUNT_1⟧.")
    assert back["text"] == "Dear Rahul Mehta, your salary is now ₹18.5 LPA."
    with pytest.raises(KeyError):
        eng.rehydrate("nope", "x")
