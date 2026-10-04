import json

from veilai_mask import config
from veilai_mask.rules import (luhn_valid, normalise, register_honeytoken, scan_rules, verhoeff_check_digit, verhoeff_valid)

SPACE = " "


def rules_in(t):
    return [m.rule for m in scan_rules(t)]


def values(t, rule):
    return [m.value for m in scan_rules(t) if m.rule == rule]


def spaced(s):
    return SPACE.join(s)


def test_checksums():
    assert verhoeff_valid("2363") and verhoeff_check_digit("236") == 3
    base = "23456789012"
    assert verhoeff_valid(base + str(verhoeff_check_digit(base)))
    assert not verhoeff_valid(base + str((verhoeff_check_digit(base) + 1) % 10))
    assert luhn_valid("4111 1111 1111 1111") and luhn_valid("5555-5555-5555-4444")
    assert not luhn_valid("4111 1111 1111 1112") and not luhn_valid("1234")


def test_secrets():
    assert values('key = "AKIAQ7X3VEILDEMO4K2P"', "AWS_ACCESS_KEY") == ["AKIAQ7X3VEILDEMO4K2P"]
    assert values("X=sk_live_" "4eC39HqLyjWDarjtT1zdp7dc", "API_KEY") == ["sk_live_" "4eC39HqLyjWDarjtT1zdp7dc"]
    assert values('DB_PASSWORD = "Tr0ub4dor&Falcon!"', "PASSWORD") == ["Tr0ub4dor&Falcon!"]
    assert values("db_pass: VeilDemo!Passw0rd", "PASSWORD") == ["VeilDemo!Passw0rd"]
    assert values("postgresql://svc:Harbor5706@db.example.test:5432/x", "CONNECTION_STRING") == ["Harbor5706"]
    assert rules_in("password=DB_PASSWORD,") == []
    assert rules_in('DB_PASSWORD = "⟦SECRET_2⟧"') == []
    assert rules_in("AKIA123 and sk_live_short") == []


def test_personal_ids():
    base = "23456789012"
    aad = base + str(verhoeff_check_digit(base))
    assert values(f"Aadhaar {aad[:4]} {aad[4:8]} {aad[8:]}", "AADHAAR") == [f"{aad[:4]} {aad[4:8]} {aad[8:]}"]
    assert "AADHAAR" not in rules_in("Ref 123456789012")
    assert values("PAN: ABCDE1234F", "PAN") == ["ABCDE1234F"]
    assert values("Call +91 98765 43210", "INDIAN_PHONE") == ["+91 98765 43210"]
    assert "INDIAN_PHONE" not in rules_in("Order 1234567890")
    assert values("Card 4111 1111 1111 1111 exp", "CARD") == ["4111 1111 1111 1111"]
    assert "AADHAAR" not in rules_in("Card 4111 1111 1111 1111")
    assert values("write to priya.k@example.co.in", "EMAIL") == ["priya.k@example.co.in"]


def test_hosts():
    assert values('host="pg-billing-01.corp.internal"', "INTERNAL_HOST") == ["pg-billing-01.corp.internal"]
    assert values("ssh 10.24.3.17", "PRIVATE_IP") == ["10.24.3.17"]
    assert rules_in("see example.com or 8.8.8.8") == []


def test_honeytoken_hmac_registry_stores_no_token():
    rec = register_honeytoken("HT-0042-7QX9VL3MZK81", "HT-0042", "finance-reports repository config")
    raw = (config.DATA_DIR / "honeytokens.json").read_text(encoding="utf-8")
    assert "HT-0042-7QX9VL3MZK81" not in raw and rec["hmac"] in raw
    m = scan_rules("access_token: HT-0042-7QX9VL3MZK81")
    assert [(x.rule, x.honeytoken_id, x.planted_in) for x in m] == [("HONEYTOKEN", "HT-0042", "finance-reports repository config")]
    assert "HONEYTOKEN" not in rules_in("ticket HT-0042-XXXXXXXXXXXX")
    assert any(r["id"] == "HT-0042" for r in json.loads(raw))


def test_normaliser_evasion():
    key = "sk_live_" "4eC39HqLyjWDarjtT1zdp7dc"
    n = normalise(f"KEY = {spaced(key)}\ndb_pass_b64: VmVpbERlbW8hUGFzc3cwcmQ=")
    assert key in n.text and "VeilDemo!Passw0rd" in n.text
    zw = normalise("AKIA" + chr(0x200B) + "Q7X3VEILDEMO4K2P " + chr(0x0440) + "ass")
    assert zw.text == "AKIAQ7X3VEILDEMO4K2P pass"
    prose = "The board has approved negotiations with Acme Corp in Q4."
    assert normalise(prose).text == prose and normalise(prose).notes == []


def test_normaliser_one_letter_words():
    key = "sk_live_" "4eC39HqLyjWDarjtT1zdp7dc"
    for t in (f"Here is a {spaced(key)} for staging.", f"Key {spaced(key)} a new one", f"So a {spaced(key)} I guess"):
        assert values(normalise(t).text, "API_KEY") == [key], t
    assert values(normalise(f"key {spaced('AKIAQ7X3VEILDEMO4K2P')} rotated").text, "AWS_ACCESS_KEY") == ["AKIAQ7X3VEILDEMO4K2P"]
