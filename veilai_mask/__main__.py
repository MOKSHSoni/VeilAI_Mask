"""Command line.

  python -m veilai_mask serve [--port 8765]
  python -m veilai_mask scan "instruction" [--file content.txt] [--l5 gated|always|off] [--json]
  python -m veilai_mask honeytoken new --planted-in "finance-reports repo config"
  python -m veilai_mask honeytoken add TOKEN --id HT-0042 --planted-in "..."
  python -m veilai_mask orgdna add path/to/confidential.txt
  python -m veilai_mask orgdna codename "Project Kestrel"
  python -m veilai_mask allow "Project Atlas"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _print_scan(r: dict) -> None:
    risk, rec = r["risk"], r["recommendation"]
    print(f"\nRisk {risk['level']}  score {risk['score']}  confidence {risk['confidence']}  →  {rec['default']}")
    print(f"  {rec['why']}")
    print(f"  task: {r['task']['label']} · {r['total_ms'] / 1000:.2f} s on this device")
    print("\nLayers")
    for l in r["layers"]:
        print(f"  {l['layer']} {l['name']:<20} {l['status']:<11} {l['findings']:>3}  {l['ms']:>9} ms  {l['note']}")
    flagged = [f for f in r["findings"] if f["flags"]]
    if flagged:
        print("\nFindings")
        for f in flagged:
            text = f["text"] if f["entity_type"] not in ("SECRET", "HONEYTOKEN", "CARD") else f["text"][:4] + "…"
            print(f"  [{f['layer']}] {f['category']:<22} {f['entity_type']:<14} {'strong' if f['strong'] else 'weak':<6} {text!r}  {f['detail']}")
    if r.get("session") and r["session"].get("warning"):
        print(f"\nMosaic: {r['session']['warning']}")
    if r["blocked"]:
        print("\nBLOCKED: nothing is sent.")
        return
    if r["verification"]:
        print(f"\nVerification: {r['verification']['status']}")
        for rep in r["verification"]["repairs"]:
            print(f"  repair: {rep['note']}")
    print("\nOutbound (all the external AI would receive):\n" + "-" * 60 + f"\n{r['outbound']}\n" + "-" * 60)
    if r["vault"]:
        print("Vault (stays on this device):")
        for v in r["vault"]:
            print(f"  {v['placeholder']:<18} {'(secret: never restored)' if v['secret'] else v['original']}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="veilai_mask", description="VeilAI_Mask: local AI privacy firewall")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the local API + web page on 127.0.0.1")
    s.add_argument("--port", type=int, default=8765)

    sc = sub.add_parser("scan", help="scan an instruction and optional content")
    sc.add_argument("instruction")
    sc.add_argument("--file", help="file with the pasted content")
    sc.add_argument("--l5", choices=["gated", "always", "off"])
    sc.add_argument("--destination", default="free_tier_ai")
    sc.add_argument("--json", action="store_true")

    ht = sub.add_parser("honeytoken")
    hts = ht.add_subparsers(dest="action", required=True)
    n = hts.add_parser("new")
    n.add_argument("--planted-in", required=True)
    a = hts.add_parser("add")
    a.add_argument("token")
    a.add_argument("--id", required=True)
    a.add_argument("--planted-in", required=True)

    od = sub.add_parser("orgdna")
    ods = od.add_subparsers(dest="action", required=True)
    oa = ods.add_parser("add")
    oa.add_argument("path")
    oc = ods.add_parser("codename")
    oc.add_argument("term")

    al = sub.add_parser("allow", help="add an analyst-approved public term to the allowlist")
    al.add_argument("term")

    args = p.parse_args(argv)

    if args.cmd == "serve":
        import uvicorn
        print(f"VeilAI_Mask on http://127.0.0.1:{args.port}  (local only)")
        uvicorn.run("veilai_mask.api:app", host="127.0.0.1", port=args.port, log_level="warning")
        return 0
    if args.cmd == "scan":
        from .pipeline import VeilAIMask
        content = Path(args.file).read_text(encoding="utf-8") if args.file else ""
        r = VeilAIMask().scan(args.instruction, content, args.destination, None, args.l5)
        print(json.dumps(r, indent=2, ensure_ascii=False) if args.json else "", end="")
        if not args.json:
            _print_scan(r)
        return 0
    if args.cmd == "honeytoken":
        from .rules import generate_honeytoken, register_honeytoken
        if args.action == "new":
            token = generate_honeytoken()
            rec = register_honeytoken(token, token[:7], args.planted_in)
            print(f"Honeytoken {rec['id']}: {token}\nPlant it in: {rec['planted_in']}\nOnly its HMAC is stored; save the token now.")
        else:
            rec = register_honeytoken(args.token, args.id, args.planted_in)
            print(f"Registered {rec['id']} (HMAC only), planted in {rec['planted_in']}")
        return 0
    if args.cmd == "orgdna":
        from .orgdna import OrgDNA
        o = OrgDNA()
        if args.action == "add":
            path = Path(args.path)
            o.register_document(path.stem, path.read_text(encoding="utf-8"))
            print(f"Registered '{path.stem}'. {len(o.docs)} documents fingerprinted.")
        else:
            o.add_codename(args.term)
            print(f"Codenames: {o.codenames}")
        return 0
    if args.cmd == "allow":
        from .orgdna import OrgDNA
        o = OrgDNA()
        o.add_to_allowlist(args.term)
        print(f"Allowlist: {o.allowlist}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
