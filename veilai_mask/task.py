"""Task analyser: what is the user asking the AI to do? Deterministic keyword rules (fast, explainable).
The task picks the necessity-matrix row used by the Data Minimisation Engine."""
from __future__ import annotations

import re

from .masking import parse_csv

TASKS = [
    ("debug_code", "Debugging", r"\b(debug|error|exception|stack ?trace|traceback|bug|crash(es|ing)?|fix (this|the|my)|why (does|is|do) .{0,40}(fail|crash|error|reject|break|not work))"),
    ("analyse_data", "Data Analysis", r"\b(average|mean|median|sum|total|calculate|compute|analy[sz]e|statistics|trend|chart|plot|count|percentage|distribution)\b"),
    ("translate", "Translation", r"\btranslate\b|\binto (hindi|french|german|spanish|tamil|telugu|marathi|bengali|english)\b"),
    ("summarise", "Summarisation", r"\b(summari[sz]e|summary|tl;?dr|key points|bullet points|outline|recap|slides?|brief)\b"),
    ("draft_rewrite", "Drafting / Rewriting", r"\b(draft|write|rewrite|reword|rephrase|compose|polish|email|reply|letter|message)\b"),
]


def analyse_task(instruction: str, content: str = "") -> dict:
    text = instruction.lower()
    for key, label, pattern in TASKS:
        if re.search(pattern, text):
            return {"task": key, "label": label, "reason": "keyword match in the instruction"}
    if content and parse_csv(content):
        return {"task": "analyse_data", "label": "Data Analysis", "reason": "content is a table"}
    if content and re.search(r"(def |class |import |function |=>|;\s*$|\{\s*$)", content, re.M):
        return {"task": "debug_code", "label": "Debugging", "reason": "content looks like code"}
    return {"task": "question", "label": "Question / General", "reason": "no specific task detected"}
