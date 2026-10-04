"""End-to-end benchmark of the complete VeilAI_Mask system (all six layers + fusion), not one layer.

  .venv/Scripts/python.exe eval/run_benchmark.py            # run (resumable) and score
  .venv/Scripts/python.exe eval/run_benchmark.py --score    # score existing results only

Uses the 192-document benchmark and the long-document test from ../privacy-benchmark (read only).
Each document is scanned as pasted content with no instruction, exactly as a user would paste it.
Scoring matches the original benchmark: recall = sensitive documents caught / 147, FPR = safe documents
flagged / 45. "Protected" counts SENSITIVE or REVIEW (never released unreviewed); "hard flag" counts SENSITIVE only.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
BENCH = ROOT.parent / "privacy-benchmark" / "dataset"
OUT = ROOT / "eval" / "results.jsonl"
SUMMARY = ROOT / "eval" / "summary.json"


def keep_awake(on: bool) -> None:
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | (0x00000001 if on else 0))


def load_docs():
    ds = json.loads((BENCH / "dataset.json").read_text(encoding="utf-8"))["documents"]
    hard = set(json.loads((BENCH / "hard_cases.json").read_text(encoding="utf-8"))["document_ids"])
    size = json.loads((BENCH / "size_tests.json").read_text(encoding="utf-8"))["documents"]
    docs = [{"id": d["document_id"], "text": d["text"], "sensitive": d["expected_sensitive"], "hard": d["document_id"] in hard,
             "group": d["group"], "kind": "benchmark"} for d in ds]
    docs += [{"id": d["document_id"], "text": (BENCH / d["text_file"]).read_text(encoding="utf-8"), "sensitive": True, "hard": False,
              "group": "SIZE_TEST", "kind": "long", "needle": d["needle"], "pages": d["pages"]} for d in size]
    return docs


def run(limit: int | None = None) -> None:
    from veilai_mask.pipeline import VeilAIMask

    done = set()
    if OUT.exists():
        done = {json.loads(l)["id"] for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()}
    docs = [d for d in load_docs() if d["id"] not in done]
    if limit:
        docs = docs[:limit]
    print(f"{len(docs)} documents to scan ({len(done)} already done)", flush=True)
    if not docs:
        return
    eng = VeilAIMask()
    eng.ner.load()
    keep_awake(True)
    t_start = time.perf_counter()
    try:
        with OUT.open("a", encoding="utf-8") as f:
            for n, d in enumerate(docs, 1):
                r = eng.scan("", d["text"])
                rec = {
                    "id": d["id"], "kind": d["kind"], "sensitive": d["sensitive"], "hard": d["hard"], "group": d["group"],
                    "verdict": r["fusion"]["verdict"], "level": r["risk"]["level"], "seconds": r["total_ms"] / 1000,
                    "layers": {l["layer"]: l["status"] for l in r["layers"]},
                    "strong_layers": r["fusion"]["strong_layers"], "weak_layers": r["fusion"]["weak_layers"],
                    "l5_errors": [l["note"] for l in r["layers"] if l["layer"] == "L5" and "error" in l["note"]],
                }
                if d["kind"] == "long":
                    needle = d["needle"].lower()
                    rec["pages"] = d["pages"]
                    rec["needle_caught"] = any(fd["flags"] and fd["text"] and fd["text"].lower() in needle for fd in r["findings"])
                f.write(json.dumps(rec) + "\n")
                f.flush()
                if n % 10 == 0 or n == len(docs):
                    el = time.perf_counter() - t_start
                    print(f"  {n}/{len(docs)}  {el / 60:5.1f} min  ~{el / n * (len(docs) - n) / 60:5.1f} min left", flush=True)
    finally:
        keep_awake(False)


def pct(a: int, b: int) -> float | None:
    return round(100 * a / b, 1) if b else None


def score() -> dict:
    rows = [json.loads(l) for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()]
    bench = [r for r in rows if r["kind"] == "benchmark"]
    sens = [r for r in bench if r["sensitive"]]
    safe = [r for r in bench if not r["sensitive"]]
    hard = [r for r in sens if r["hard"]]
    caught = lambda r: r["verdict"] in ("SENSITIVE", "REVIEW")  # noqa: E731
    flag = lambda r: r["verdict"] == "SENSITIVE"  # noqa: E731
    tp, fp = sum(flag(r) for r in sens), sum(flag(r) for r in safe)
    out = {
        "documents": len(bench), "sensitive": len(sens), "safe": len(safe),
        "recall_protected": pct(sum(caught(r) for r in sens), len(sens)),
        "recall_hard_flag": pct(tp, len(sens)),
        "fnr": pct(sum(not caught(r) for r in sens), len(sens)),
        "precision_hard_flag": pct(tp, tp + fp),
        "fpr_hard_flag": pct(fp, len(safe)),
        "safe_sent_to_review": pct(sum(r["verdict"] == "REVIEW" for r in safe), len(safe)),
        "review_rate_all": pct(sum(r["verdict"] == "REVIEW" for r in bench), len(bench)),
        "hard_case_recall_protected": pct(sum(caught(r) for r in hard), len(hard)),
        "missed": [r["id"] for r in sens if not caught(r)],
        "false_flags": [r["id"] for r in safe if flag(r)],
        "by_group": {g: pct(sum(caught(r) for r in sens if r["group"] == g), sum(r["group"] == g for r in sens))
                     for g in sorted({r["group"] for r in sens})},
        "seconds_per_doc_avg": round(sum(r["seconds"] for r in bench) / max(1, len(bench)), 2),
        "seconds_per_doc_max": round(max((r["seconds"] for r in bench), default=0), 2),
        "l5_error_docs": sum(bool(r["l5_errors"]) for r in rows),
        "long_documents": [{"pages": r["pages"], "verdict": r["verdict"], "needle_caught": r["needle_caught"], "seconds": round(r["seconds"], 1)}
                           for r in sorted((r for r in rows if r["kind"] == "long"), key=lambda r: r["pages"])],
    }
    SUMMARY.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--limit", type=int, help="scan at most N remaining documents this run")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not args.score:
        run(args.limit)
    s = score()
    print(json.dumps({k: v for k, v in s.items() if k not in ("missed", "false_flags")}, indent=2))
