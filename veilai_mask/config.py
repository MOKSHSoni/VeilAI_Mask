"""VeilAI_Mask configuration: policy-as-code, models, thresholds. Edit here, not in the engine."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("VEILAI_DATA", ROOT / "data"))

# ---------------------------------------------------------------- models (local only)
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("VEILAI_MODEL", "veilai_mask")          # created from ./Modelfile
FAST_MODEL = os.environ.get("VEILAI_FAST_MODEL", "qwen3:1.7b")  # optional tier for 8 GB machines
LLM_OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 4096, "num_predict": 120}
LOCAL_ANSWER_OPTIONS = {"temperature": 0.2, "seed": 42, "num_ctx": 4096, "num_predict": 600}
KEEP_ALIVE = "30m"
LLM_TIMEOUT_S = 600

# L5 mode: "gated" (default, gating router decides per chunk), "always", or "off".
L5_MODE = os.environ.get("VEILAI_L5", "gated")
L5_CATEGORIES = ["FINANCIAL", "CONFIDENTIAL_BUSINESS", "INTELLECTUAL_PROPERTY"]

# L2 entity NER (Presidio + GLiNER). Disabled automatically if the packages are missing.
L2_ENABLED = os.environ.get("VEILAI_L2", "1") == "1"
GLINER_MODEL = "urchade/gliner_small-v2.1"
NER_THRESHOLD = 0.5

# L3 Org DNA (MinHash containment)
ORG_DNA_SHINGLE = 5
ORG_DNA_PERM = 128
ORG_DNA_THRESHOLD = 0.4

CHUNK_CHARS = 3000  # ~1 page

# ---------------------------------------------------------------- categories and policy
CATEGORIES = [
    "CREDENTIALS", "SECURITY", "PERSONAL_INFORMATION", "CUSTOMER_INFORMATION",
    "FINANCIAL", "CONFIDENTIAL_BUSINESS", "INTELLECTUAL_PROPERTY",
]
LEVELS = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# Label hierarchy (fusion): a finding with the key label also carries the value labels.
HIERARCHY = {"CREDENTIALS": ["SECURITY"], "CUSTOMER_INFORMATION": ["PERSONAL_INFORMATION"]}

CATEGORY_SEVERITY = {
    "CREDENTIALS": "CRITICAL",
    "SECURITY": "HIGH",
    "PERSONAL_INFORMATION": "MEDIUM",
    "CUSTOMER_INFORMATION": "HIGH",
    "FINANCIAL": "HIGH",
    "CONFIDENTIAL_BUSINESS": "HIGH",
    "INTELLECTUAL_PROPERTY": "HIGH",
}

DESTINATION_MULTIPLIER = {"enterprise_ai": 0.8, "free_tier_ai": 1.3, "unknown_ai": 1.5}

# Data Minimisation Engine: necessity matrix (design doc §11.7). The matrix decides, not the LLM.
#   classes: names, contacts, figures, secrets, internal_hosts, strategy_text
NECESSITY = {
    "summarise":      {"names": "PSEUDONYMISE", "contacts": "DROP", "figures": "PSEUDONYMISE", "secrets": "DROP", "internal_hosts": "DROP", "strategy_text": "KEEP"},
    "analyse_data":   {"names": "DROP", "contacts": "DROP", "figures": "KEEP", "secrets": "DROP", "internal_hosts": "DROP", "strategy_text": "DROP"},
    "debug_code":     {"names": "DROP", "contacts": "DROP", "figures": "KEEP", "secrets": "DROP", "internal_hosts": "PSEUDONYMISE", "strategy_text": "DROP"},
    "draft_rewrite":  {"names": "PSEUDONYMISE", "contacts": "DROP", "figures": "PSEUDONYMISE", "secrets": "DROP", "internal_hosts": "DROP", "strategy_text": "KEEP"},
    "translate":      {"names": "PSEUDONYMISE", "contacts": "PSEUDONYMISE", "figures": "KEEP", "secrets": "DROP", "internal_hosts": "PSEUDONYMISE", "strategy_text": "KEEP"},
    "question":       {"names": "PSEUDONYMISE", "contacts": "DROP", "figures": "GENERALISE", "secrets": "DROP", "internal_hosts": "PSEUDONYMISE", "strategy_text": "KEEP"},
}

# Which minimisation class each entity type belongs to.
ENTITY_CLASS = {
    "PERSON": "names", "CUSTOMER": "names", "ORG": "names", "CLIENT": "names", "PROJECT": "names",
    "EMAIL": "contacts", "PHONE": "contacts", "ADDRESS": "contacts", "NATIONAL_ID": "contacts", "CUSTOMER_ID": "contacts",
    "MONEY": "figures", "CARD": "secrets", "BANK_ACCOUNT": "secrets",
    "SECRET": "secrets", "HONEYTOKEN": "secrets",
    "INTERNAL_HOST": "internal_hosts",
}

# Exposure Explainer templates (filled from findings; no free LLM text).
WHY = {
    "CREDENTIALS": "Anyone holding this credential can access the system directly. Secrets pasted into AI tools cannot be recalled.",
    "SECURITY": "Internal infrastructure details help an attacker map and target internal systems.",
    "PERSONAL_INFORMATION": "Personal data sent to an external processor without a lawful purpose creates a privacy breach.",
    "CUSTOMER_INFORMATION": "Customer data shared outside approved processors breaks customer trust and contract terms.",
    "FINANCIAL": "Non-public financial figures can move deal terms or share price if leaked.",
    "CONFIDENTIAL_BUSINESS": "Unannounced business matters could harm negotiations or strategy if leaked.",
    "INTELLECTUAL_PROPERTY": "Proprietary methods and unreleased work are the company's competitive advantage.",
}
REGULATION = {
    "CREDENTIALS": "ISO 27001 A.5.17 (authentication information) · Secrets Handling Policy",
    "SECURITY": "ISO 27001 A.8.20 (network security) · Information Security Policy",
    "PERSONAL_INFORMATION": "DPDP Act 2023 §4, §8 · GDPR Art. 5(1)(c)",
    "CUSTOMER_INFORMATION": "DPDP Act 2023 §8 · customer contracts / NDA",
    "FINANCIAL": "SEBI (PIT) Regulations 2015 (unpublished price-sensitive information)",
    "CONFIDENTIAL_BUSINESS": "NDA obligations · Information Classification Policy (Confidential)",
    "INTELLECTUAL_PROPERTY": "Trade-secret protection · Information Classification Policy (Restricted)",
}
