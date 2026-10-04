"""VeilAI_Mask pipeline: Understand → detect → assess → minimise → mask → verify → decide.

Every step runs for real; the timings reported are measured on this device.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import asdict

from . import config, session
from .cues import scan_cues
from .explain import explain
from .fusion import assess_risk, fuse, is_strong, recommend
from .llm import LLM
from .masking import VaultEntry
from .minimise import minimise_table, plan
from .models import Chunk, Finding, LayerReport
from .ner import NER
from .orgdna import OrgDNA
from .rehydrate import rehydrate
from .rules import normalise, scan_rules
from .task import analyse_task
from .verify import mask_and_verify

LAYER_NAMES = {"L0": "Honeytokens", "L1": "Deterministic rules", "L2": "Entity NER", "L3": "Org DNA", "L4": "Context signals", "L5": "Local Qwen"}
_VAULT_TTL_S = 2 * 3600


def chunk_text(text: str, size: int = config.CHUNK_CHARS) -> list[Chunk]:
    """~1-page chunks on paragraph / sentence boundaries, with offsets into `text`."""
    if len(text) <= size:
        return [Chunk(0, 0, text)]
    chunks, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = max(text.rfind("\n\n", start, end), text.rfind(". ", start, end), text.rfind("\n", start, end))
            if cut > start + size // 2:
                end = cut + 1
        chunks.append(Chunk(len(chunks), start, text[start:end]))
        start = end
    return chunks


def _sub_spans(text: str, size: int = 1200) -> list[tuple[int, str]]:
    """Smaller windows for GLiNER (its context is ~384 tokens)."""
    out, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            cut = max(text.rfind(" ", start, end), start + size // 2)
            end = cut
        out.append((start, text[start:end]))
        start = end
    return out


class VeilAIMask:
    def __init__(self, model: str | None = None):
        self.llm = LLM(model)
        self.ner = NER()
        self.orgdna = OrgDNA()
        self._vaults: dict[str, dict] = {}
        self._lock = threading.Lock()

    def warm_up(self) -> None:
        """Load NER models in the background so the first scan is not slow."""
        threading.Thread(target=self.ner.load, daemon=True).start()

    # ------------------------------------------------------------------ scan
    def scan(self, instruction: str, content: str = "", destination: str = "free_tier_ai", session_id: str | None = None,
             l5_mode: str | None = None) -> dict:
        t_all = time.perf_counter()
        steps: list[dict] = []

        def step(name: str, t0: float, **extra):
            steps.append({"step": name, "ms": round((time.perf_counter() - t0) * 1000, 2), **extra})

        # 1 Capture + 2 Normalise
        t0 = time.perf_counter()
        n_instr, n_content = normalise(instruction or ""), normalise(content or "")
        notes = n_instr.notes + n_content.notes
        sep = "\n\n" if n_content.text else ""
        text = n_instr.text + sep + n_content.text
        content_offset = len(n_instr.text) + len(sep)
        step("Capture + Normalise", t0, notes=len(notes))

        # 3 Task analysis
        t0 = time.perf_counter()
        task = analyse_task(instruction or "", content or "")
        step("Task Analysis", t0, task=task["label"])

        # 4 Detection ensemble
        chunks = chunk_text(text)
        layers: dict[str, LayerReport] = {}
        findings: list[Finding] = []

        t_detect = time.perf_counter()
        t0 = time.perf_counter()
        rule_hits = scan_rules(text)
        for m in rule_hits:
            layer = "L0" if m.rule == "HONEYTOKEN" else "L1"
            detail = f"{m.label} · planted in {m.planted_in}" if m.honeytoken_id else m.label
            findings.append(Finding(layer, m.category, m.labels, m.entity_type, m.severity, 1.0 if layer == "L0" else 0.97,
                                    "strong", m.value, m.start, m.end, detail))
        ms = (time.perf_counter() - t0) * 1000
        for lid in ("L0", "L1"):
            n = sum(f.layer == lid for f in findings)
            layers[lid] = LayerReport(lid, LAYER_NAMES[lid], "FLAGGED" if n else "CLEAR", round(ms, 2), n,
                                      "registered honeytoken hashes (HMAC)" if lid == "L0" else "regex, Luhn, Verhoeff, entropy-free patterns")

        t0 = time.perf_counter()
        l2: list[Finding] = []
        if self.ner.load():
            for off, sub in _sub_spans(text):
                l2 += self.ner.scan(sub, off)
            flag = sum(f.flags for f in l2)
            layers["L2"] = LayerReport("L2", LAYER_NAMES["L2"], "FLAGGED" if flag else "CLEAR", round((time.perf_counter() - t0) * 1000, 1),
                                       len(l2), f"{flag} identifier(s); {len(l2) - flag} name(s) recorded as masking targets")
        else:
            layers["L2"] = LayerReport("L2", LAYER_NAMES["L2"], "UNAVAILABLE", 0, 0, self.ner.error)
        findings += l2

        t0 = time.perf_counter()
        l3 = self.orgdna.scan(text)
        findings += l3
        layers["L3"] = LayerReport("L3", LAYER_NAMES["L3"], "FLAGGED" if l3 else "CLEAR", round((time.perf_counter() - t0) * 1000, 2), len(l3),
                                   f"{len(self.orgdna.docs)} registered documents, {len(self.orgdna.codenames)} codenames")

        t0 = time.perf_counter()
        l4 = []
        for c in chunks:
            l4 += scan_cues(c.text, c.start)
        findings += l4
        layers["L4"] = LayerReport("L4", LAYER_NAMES["L4"], "FLAGGED" if l4 else "CLEAR", round((time.perf_counter() - t0) * 1000, 2), len(l4),
                                   ", ".join(sorted({f.detail for f in l4})) or "no context cues")

        # Gating router + L5
        mode = (l5_mode or config.L5_MODE).lower()
        t0 = time.perf_counter()
        l5: list[Finding] = []
        llm_stats = {"calls": 0, "cached": 0, "seconds": 0.0, "errors": []}
        health = self.llm.health() if mode != "off" else {}
        for c in chunks:
            critical = any(f.layer in ("L0", "L1") and f.severity == "CRITICAL" and c.start <= f.start < c.start + len(c.text) for f in findings)
            words = len(re.findall(r"[A-Za-z]{3,}", c.text))
            if mode == "off":
                c.l5 = "off"
            elif not health.get("model_installed"):
                c.l5 = "skipped: model not available"
            elif mode == "gated" and critical:
                c.l5 = "skipped: chunk already CRITICAL from L0/L1"
            elif mode == "gated" and words < 4:
                c.l5 = "skipped: too little text"
            else:
                fs, st = self.llm.scan_chunk(c.text, c.start, config.L5_CATEGORIES)
                l5 += fs
                for k in ("calls", "cached", "seconds"):
                    llm_stats[k] += st[k]
                llm_stats["errors"] += st["errors"]
                c.l5 = "ran"
        findings += l5
        ran = sum(c.l5 == "ran" for c in chunks)
        layers["L5"] = LayerReport(
            "L5", LAYER_NAMES["L5"],
            "FLAGGED" if l5 else ("CLEAR" if ran else ("UNAVAILABLE" if mode != "off" and not health.get("model_installed") else "SKIPPED")),
            round((time.perf_counter() - t0) * 1000, 1), len(l5),
            f"{self.llm.model}: ran on {ran}/{len(chunks)} chunk(s), {llm_stats['calls']} calls ({llm_stats['cached']} cached)"
            + (f"; {len(llm_stats['errors'])} errors" if llm_stats["errors"] else "")
            + ("" if ran else f"; {chunks[0].l5}"))
        step("Detection Ensemble", t_detect, chunks=len(chunks), l5_ms=round((time.perf_counter() - t0) * 1000, 1))

        # Analyst allowlist: approved public terms are never flagged (CRITICAL cannot be allowlisted).
        findings = [f for f in findings if not (f.text and f.severity != "CRITICAL" and self.orgdna.is_allowlisted(f.text))]

        # 5 Fusion + 6 Policy + risk (+ session mosaic)
        t0 = time.perf_counter()
        fusion = fuse(findings)
        risk = assess_risk(findings, fusion, destination)
        sess = session.update(session_id, findings, text)
        if sess and sess["mosaic"] and risk["level"] in ("SAFE", "LOW", "MEDIUM", "REVIEW"):
            risk.update(level="HIGH", score=max(risk["score"], 72), mosaic=sess["warning"])
            fusion["verdict"] = "SENSITIVE"
        rec = recommend(risk, findings, task["task"])
        step("Fusion + Policy + Risk", t0, level=risk["level"])

        # 7 Exposure explanation
        t0 = time.perf_counter()
        explanation = explain(findings, text, rec)
        step("Exposure Explanation", t0)

        # 8 Minimisation + 9 Masking + 10 Verification
        t0 = time.perf_counter()
        table = None
        outbound_text, vault, verification, min_items = text, [], None, []
        if risk["honeytoken"]:
            outbound_text = None
        elif fusion["verdict"] != "SAFE":
            table = minimise_table(instruction or "", n_content.text, task["task"]) if n_content.text else None
            base = n_instr.text + sep + (table["content"] if table else n_content.text)
            targets, min_items = plan(findings, task["task"])
            step("Data Minimisation", t0, items=len(min_items))
            t0 = time.perf_counter()
            outcome = mask_and_verify(base, targets, table["dropped_values"] if table else None)
            outbound_text = outcome.final.text
            vault = outcome.final.vault
            verification = {
                "status": outcome.status,
                "attempts": [{"passed": r.passed, "checks": r.checks, "text": m.text} for m, r in outcome.attempts],
                "repairs": outcome.repairs,
                "generalised": [r for r in outcome.final.replacements if r["kind"] == "generalised"],
            }
            step("Masking + Verification", t0, status=outcome.status)
        if fusion["verdict"] == "SAFE":
            step("Minimisation / Masking", t0, note="nothing to transform: sent unchanged")

        scan_id = secrets.token_hex(8)
        with self._lock:
            now = time.time()
            for k in [k for k, v in self._vaults.items() if now - v["at"] > _VAULT_TTL_S]:
                del self._vaults[k]
            self._vaults[scan_id] = {"vault": vault, "instruction": instruction, "content": content, "at": now}

        return {
            "scan_id": scan_id,
            "total_ms": round((time.perf_counter() - t_all) * 1000, 1),
            "steps": steps,
            "normalisation": notes,
            "task": task,
            "chunks": [{"index": c.index, "chars": len(c.text), "l5": c.l5} for c in chunks],
            "layers": [layers[k].to_dict() for k in ("L0", "L1", "L2", "L3", "L4", "L5")],
            "findings": [{**f.to_dict(), "strong": is_strong(f)} for f in findings],
            "fusion": fusion,
            "risk": risk,
            "recommendation": rec,
            "explanation": explanation,
            "minimisation": min_items,
            "table": {k: v for k, v in table.items() if k != "dropped_values"} if table else None,
            "verification": verification,
            "outbound": outbound_text,
            "blocked": risk["honeytoken"],
            "vault": [asdict(v) for v in vault],
            "session": sess,
            "model": self.llm.model,
        }

    # ------------------------------------------------------------------ actions
    def _get(self, scan_id: str) -> dict:
        with self._lock:
            v = self._vaults.get(scan_id)
        if v is None:
            raise KeyError("Unknown or expired scan id")
        return v

    def rehydrate(self, scan_id: str, reply: str, restore_secrets: bool = False) -> dict:
        v = self._get(scan_id)
        return rehydrate(reply, v["vault"], restore_secrets)

    def answer_locally(self, scan_id: str) -> dict:
        v = self._get(scan_id)
        return self.llm.answer_locally(v["instruction"] or "", v["content"] or "")

    def vault_of(self, scan_id: str) -> list[VaultEntry]:
        return self._get(scan_id)["vault"]
