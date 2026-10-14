# VeilAI_Mask

The **real, working** version of the VeilAI prototype: a local AI privacy firewall that runs every layer for real on your own machine. Nothing is simulated. It detects sensitive information, minimises it to what the task needs, masks the rest with role-preserving placeholders, verifies the result, and restores the AI's reply on your device.

**What "model" means here.** `veilai_mask` is a custom **Ollama model** created from Qwen3 4B Instruct (`./Modelfile`): the same weights packaged with VeilAI_Mask's instructions and deterministic settings. No new weights were trained; that would need a GPU and labelled training data. The protection comes from the whole engine: six detection layers, fusion, minimisation, masking and verification, with Qwen as one layer among them.

This is the [VeilAI prototype](https://github.com/MOKSHSoni/VeilAI) ([live demo](https://veil-ai-blush.vercel.app/), simulated results). VeilAI_Mask ports its deterministic code (rules, masking, verification, rehydration) to Python and replaces every simulated part with real models.

---

## Quick start (Windows)

Needs **Python 3.11+** and **Ollama** (running).

```powershell
cd VeilAI_Mask
powershell -ExecutionPolicy Bypass -File setup.ps1   # once: venv, packages, Qwen3 4B, creates veilai_mask
powershell -ExecutionPolicy Bypass -File start.ps1   # opens http://127.0.0.1:8765
```

On the page: type an instruction, paste content (or click a sample), and click **Scan on device**. Then:

- copy the **outbound** text (all the external AI would receive),
- or click **Answer locally with Qwen** (nothing leaves the device),
- and paste the external AI's reply into **Restore** to get the real names and values back.

Try the model on its own: `ollama run veilai_mask "The board approved the Acme acquisition at 420 crore"`.

## Command line

```powershell
$py = ".\.venv\Scripts\python.exe"
& $py -m veilai_mask scan "Why does this connection fail?" --file notes.txt     # full report in the terminal
& $py -m veilai_mask scan "Summarise this" --file memo.txt --json               # machine-readable
& $py -m veilai_mask honeytoken new --planted-in "finance-reports repo config"  # create + register a tripwire
& $py -m veilai_mask orgdna add path\to\confidential_board_pack.txt             # fingerprint a confidential document
& $py -m veilai_mask orgdna codename "Project Kestrel"                          # internal codename
& $py -m veilai_mask allow "Project Atlas"                                      # analyst-approved public term
& $py -m pytest -q                                                              # 29 tests, fully offline
```

`--l5 gated|always|off` controls the Qwen layer (`off` = rules + NER + Org DNA only, in milliseconds).

## Local API (127.0.0.1 only)

| Method | Path | Body |
|---|---|---|
| POST | `/api/scan` | `{instruction, content, destination?, session_id?, l5_mode?}` |
| POST | `/api/rehydrate` | `{scan_id, reply}` |
| POST | `/api/answer-local` | `{scan_id}` |
| POST | `/api/orgdna/document` | `{name, text}` |
| POST | `/api/orgdna/codename` | `{term}` |
| POST | `/api/allowlist` | `{term}` |
| POST | `/api/honeytokens` | `{id?, planted_in}`; the token is returned once, only its HMAC is stored |
| GET | `/api/health` | model, NER, Org DNA and honeytoken status |

Interactive docs: http://127.0.0.1:8765/api/docs

---

## How it works

```text
Capture → Normalise → Task analysis → Detection (L0–L5) → Fusion → Policy + risk → Explain
→ Minimise → Mask → Verify (+ repair) → Decide → [external AI] → Rehydrate on this device
```

| Layer | What runs | File |
|---|---|---|
| Normalise | Zero-width characters, Cyrillic look-alikes, spaced-out keys (with the "a"/"I" fix), base64 | `rules.py` |
| **L0** Honeytokens | HMAC-SHA256 with an organisation secret; only HMACs are stored; a hit names where the token was planted | `rules.py` |
| **L1** Rules | AWS/Stripe/GitHub/Google/Slack keys, password and token assignments, connection strings, private keys, cards (Luhn), Aadhaar (Verhoeff), PAN, Indian mobiles, emails, internal hosts, private IPs | `rules.py` |
| **L2** Entity NER | Presidio + GLiNER (`gliner_small-v2.1`): addresses, IDs, customer IDs, bank accounts, health data; person, organisation and project names as masking targets | `ner.py` |
| **L3** Org DNA | MinHash fingerprints of registered confidential documents (5-word shingles, containment ≥ 0.4), codename dictionary, analyst allowlist | `orgdna.py` |
| **L4** Context signals | Cue rules (board approved, do not distribute, confidential, acquisition, unreleased, proprietary…) and money near finance words | `cues.py` |
| **L5** Local Qwen | `veilai_mask` via Ollama: one yes/no question per category (financial, business, IP) per ~1-page chunk, with a verbatim evidence quote that must exist in the text; cached by chunk hash; gated (skipped when a chunk is already CRITICAL) | `llm.py` |
| Fusion | Strong signals (L0, L1 CRITICAL/HIGH, L3, L5) flag alone; one weak layer → REVIEW; two weak layers → flag; ≥3 personal identifiers → flag. Label hierarchy; noisy-OR confidence | `fusion.py` |
| Policy + risk | Level, score, confidence kept separate; destination multiplier; name + salary/ID combination bonus; session mosaic risk | `fusion.py`, `session.py` |
| Minimisation | Necessity matrix per task (summarise, analyse data, debug, draft, translate, question); tables keep only the columns the instruction needs | `minimise.py`, `task.py` |
| Masking | Role-preserving placeholders (`⟦EMP_01⟧`, `⟦ORG_A⟧`, `⟦SECRET_1⟧`, `⟦AMOUNT_1⟧`); relationship-preserving; generalisation (₹4.37 Cr → about ₹4 Cr) | `masking.py` |
| Verification | Vault leaks, variants (first name, possessive, spacing…), rule re-scan, placeholder validity, mapping consistency; one auto-repair, otherwise REVIEW | `verify.py` |
| Rehydration | Restores the reply on the device; tolerant to `⟦ emp_01 ⟧` / `[[EMP_01]]`; secrets are never restored | `rehydrate.py` |
| Explainer | Template-filled (never free LLM text): found, where, evidence, why it matters, regulation | `explain.py` |
| Local Answer Mode | The same local model answers the request; nothing leaves the device | `llm.py` |

Policy, thresholds and the necessity matrix are in `veilai_mask/config.py`.

## Privacy guarantees

- **No external service is ever contacted while running.** Ollama is on `127.0.0.1`; the API binds to `127.0.0.1`; GLiNER loads from the local cache with the Hugging Face hub forced offline (verified by loading it with all network traffic blocked). The only downloads happen during `setup.ps1`.
- **Vaults live in memory only** (2-hour expiry), never on disk.
- **The `data/` folder** holds only: the organisation secret for honeytoken HMACs, the honeytoken HMAC registry, registered Org DNA documents (you add them), codenames, the allowlist, and the L5 answer cache (`data/cache/l5_cache.jsonl`, keyed by a hash of the chunk; it contains the model's short evidence quotes). Delete the cache any time.

## Benchmark (complete system)

The whole engine, end to end, on the same 192-document benchmark and scoring as the original LLM-only test (`eval/run_benchmark.py`, results in `eval/summary.json`; the benchmark documents themselves are not included in this repository). Each document is scanned as pasted content; Intel Core Ultra 5 125H, 16 GB RAM, CPU only.

| | Qwen3 4B alone (original benchmark) | **VeilAI_Mask (complete system)** |
|---|---:|---:|
| Sensitive documents caught (flagged or REVIEW) | 45.6% | **93.2%** (137 / 147) |
| Hard cases caught | 24.3% | **91.9%** |
| Safe documents hard-flagged (FPR) | 6.7% | **2.2%** (1 / 45) |
| Precision of hard flags | 95.7% | **99.2%** |
| Documents sent to REVIEW | n/a | 12.0% (20% of safe docs; target < 10%) |
| Average time per short document | 8.0 s | 12.3 s |

By group (sensitive documents caught): business 100%, customer 100%, financial 100%, IP 100%, mixed 95%, security 84%, personal 75%.

**Long documents** (one hidden sensitive sentence): caught at **1, 5, 10 and 15 pages** (the LLM alone caught only the 1-page one). This is slow on CPU: 5 min for 5 pages, 9 min for 15 pages, because L5 asks 3 questions per page.

**What it misses (10 documents).** Almost all are **personal or security matters written in plain prose**, with no pattern to match and outside the three categories L5 is asked about (financial, business, IP): a performance review, medical leave, a harassment report, a background check, an unpatched VPN vulnerability, a logging blind spot, an incident description. One is a list of US-format phone numbers (L1's phone rule is India-specific). The fix is to ask L5 about PERSONAL_INFORMATION and SECURITY too, at the cost of more time per page. I haven't applied it, so these results aren't tuned to this test set.

**The one false flag** is a code quickstart with `API_KEY="<your-key>"`: a template placeholder that the password rule treats as a secret.

The earlier ablation (each layer added separately, not included in this repository) measured 95.2% recall and 11.1% hard-flag FPR with the same fusion rule. This complete system trades a little recall for far fewer false alarms, mainly because L2 now ignores department names and descriptions, and the bulk-identifier rule is in place.

## Limitations

- **Names need L2.** Without Presidio + GLiNER (`VEILAI_L2=0` or packages missing), person and organisation names are not detected or masked. The web page shows L2's status.
- **Speed.** Rules, NER and Org DNA take well under a second; the Qwen layer takes about 3 × 3–5 s per page on CPU. Use `--l5 off` for instant rules-only scans, or `VEILAI_MODEL=qwen3:1.7b` for faster but less precise L5.
- **Contextual personal and security information** (health, performance reviews, unpatched vulnerabilities) is missed when it contains no pattern, because L5 is asked only about financial, business and IP content. This causes most of the 10 benchmark misses.
- **Phone numbers:** L1 recognises Indian mobile numbers only; other formats depend on Presidio.
- **Category labels from L5 are not reliable** (the model tends to say yes to every category once text is sensitive). The sensitive-vs-safe decision is reliable; the per-category label is indicative.
- **Paraphrases of registered documents** are not caught by Org DNA (MinHash catches copies and light edits); L5 covers some of them.
- **PDF / Word** input is not parsed; paste text or use `.txt`.
- **The L4 embedding classifier** from the design doc is not implemented; L4 is cue rules only.
- Measured on one synthetic dataset; validate on your own data before relying on it.
