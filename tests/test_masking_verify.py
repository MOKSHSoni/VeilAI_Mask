from veilai_mask.masking import MaskTarget, generalise_money, mask, parse_csv
from veilai_mask.rehydrate import rehydrate
from veilai_mask.verify import mask_and_verify, verify


def test_relationships_and_numbering():
    r = mask("Rahul reports to Priya. Rahul manages ABC Corporation. Priya approved the transaction.",
             [MaskTarget("Rahul", "PERSON"), MaskTarget("Priya", "PERSON"), MaskTarget("ABC Corporation", "CLIENT")])
    assert r.text == "⟦EMP_01⟧ reports to ⟦EMP_02⟧. ⟦EMP_01⟧ manages ⟦CLIENT_A⟧. ⟦EMP_02⟧ approved the transaction."


def test_overlap_longest_wins_and_word_boundaries():
    r = mask("ABC Corporation signed. ABC later renewed. Ravi and Ravindra.",
             [MaskTarget("ABC", "CLIENT"), MaskTarget("ABC Corporation", "CLIENT"), MaskTarget("Ravi", "PERSON")])
    assert r.text == "⟦CLIENT_A⟧ signed. ⟦CLIENT_B⟧ later renewed. ⟦EMP_01⟧ and Ravindra."


def test_generalise():
    assert generalise_money("₹4.37 Cr") == "about ₹4 Cr"
    assert generalise_money("$412,500") == "about $400,000"
    r = mask("worth about ₹12.4 Cr and near ₹420 Cr", [MaskTarget("₹12.4 Cr", "MONEY", generalise_to=generalise_money("₹12.4 Cr")),
                                                         MaskTarget("₹420 Cr", "MONEY", generalise_to=generalise_money("₹420 Cr"))])
    assert r.text == "worth about ₹10 Cr and near ₹400 Cr"
    assert r.vault == []  # generalised values are not restorable


def test_verify_detects_variants_and_repairs():
    m = mask("Rahul Mehta", [MaskTarget("Rahul Mehta", "PERSON")])
    kinds = lambda t: [l.kind for l in verify(t, m.vault).leaks]  # noqa: E731
    assert kinds("Ask Rahul today") == ["first name"]
    assert kinds("Rahul's review") == ["possessive"]
    assert kinds("user Rahul-Mehta") == ["spacing variant"]
    out = mask_and_verify("Draft an email telling Rahul Mehta his salary. Mention that Rahul's review was the reason.",
                          [MaskTarget("Rahul Mehta", "PERSON")])
    assert out.status == "REPAIRED"
    assert out.final.text == "Draft an email telling ⟦EMP_01⟧ his salary. Mention that ⟦EMP_01⟧'s review was the reason."


def test_verify_patterns_and_dropped():
    assert not verify("key AKIAQ7X3VEILDEMO4K2P", []).passed
    assert not verify("total 120 for Pune", [], dropped=["Pune"]).passed
    out = mask_and_verify('key = "AKIAQ7X3VEILDEMO4K2P"', [])
    assert out.status == "REPAIRED" and out.final.text == 'key = "⟦SECRET_1⟧"'


def test_rehydrate():
    v = mask("Rahul Mehta at Acme Corp, key AKIAQ7X3VEILDEMO4K2P",
             [MaskTarget("Rahul Mehta", "PERSON"), MaskTarget("Acme Corp", "CLIENT"), MaskTarget("AKIAQ7X3VEILDEMO4K2P", "SECRET")]).vault
    r = rehydrate("Hi ⟦ emp_01 ⟧ of [[CLIENT_A]], rotate ⟦SECRET_1⟧ and ⟦EMP_09⟧", v)
    assert r["text"] == "Hi Rahul Mehta of Acme Corp, rotate ⟦SECRET_1⟧ and ⟦EMP_09⟧"
    assert (r["restored"], r["secrets_kept"], r["unresolved"]) == (2, 1, ["⟦EMP_09⟧"])


def test_parse_csv():
    assert parse_csv("a,b\n1,2\n3,4") == (["a", "b"], [["1", "2"], ["3", "4"]])
    assert parse_csv("just a sentence, with a comma") is None
