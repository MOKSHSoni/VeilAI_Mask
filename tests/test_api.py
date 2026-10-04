from fastapi.testclient import TestClient

from veilai_mask.api import app

client = TestClient(app)


def test_health_and_index():
    assert client.get("/").status_code == 200
    h = client.get("/api/health").json()
    assert {"llm", "l2", "org_dna", "honeytokens"} <= set(h)


def test_scan_rehydrate_roundtrip():
    r = client.post("/api/scan", json={"instruction": "Help me write this HR email.",
                                        "content": "Tell Rahul Mehta his salary goes to ₹18.5 LPA."}).json()
    assert "Rahul" not in r["outbound"]
    back = client.post("/api/rehydrate", json={"scan_id": r["scan_id"], "reply": "Hello ⟦EMP_01⟧ (⟦AMOUNT_1⟧)"}).json()
    assert back["text"] == "Hello Rahul Mehta (₹18.5 LPA)"


def test_errors():
    assert client.post("/api/scan", json={"instruction": "", "content": ""}).status_code == 400
    assert client.post("/api/rehydrate", json={"scan_id": "missing", "reply": "x"}).status_code == 404


def test_honeytoken_endpoint():
    out = client.post("/api/honeytokens", json={"planted_in": "crm export"}).json()
    r = client.post("/api/scan", json={"instruction": "check", "content": f"token {out['token']}"}).json()
    assert r["blocked"] and "crm export" in r["risk"]["honeytoken_source"]
