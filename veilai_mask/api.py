"""Local HTTP API + web page. Binds to 127.0.0.1 only: nothing on the network can reach it.

  POST /api/scan            {instruction, content, destination?, session_id?, l5_mode?}
  POST /api/rehydrate       {scan_id, reply}
  POST /api/answer-local    {scan_id}
  POST /api/orgdna/document {name, text}      register a confidential document (fingerprint)
  POST /api/orgdna/codename {term}
  POST /api/allowlist       {term}            analyst-approved public term
  POST /api/honeytokens     {id?, planted_in} generate + register a honeytoken (token shown once)
  GET  /api/health
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import config
from .pipeline import VeilAIMask
from .rules import generate_honeytoken, load_registry, register_honeytoken

WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"

engine = VeilAIMask()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    engine.warm_up()  # load NER models in the background
    yield


app = FastAPI(title="VeilAI_Mask", version="1.0", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)


class ScanIn(BaseModel):
    instruction: str = Field("", max_length=20_000)
    content: str = Field("", max_length=1_000_000)
    destination: str = "free_tier_ai"
    session_id: str | None = None
    l5_mode: str | None = None


class RehydrateIn(BaseModel):
    scan_id: str
    reply: str = Field(..., max_length=200_000)


class ScanRef(BaseModel):
    scan_id: str


class DocIn(BaseModel):
    name: str
    text: str = Field(..., max_length=2_000_000)


class TermIn(BaseModel):
    term: str = Field(..., min_length=2, max_length=200)


class HoneytokenIn(BaseModel):
    id: str | None = None
    planted_in: str = Field(..., min_length=2, max_length=300)


@app.get("/")
def index():
    return FileResponse(WEB)


@app.get("/favicon.svg")
def favicon():
    from fastapi.responses import Response
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#15161b"/>'
           '<path d="M8.5 9.5 16 24l7.5-14.5" fill="none" stroke="#3b54ff" stroke-width="3.2" stroke-linejoin="round"/></svg>')
    return Response(svg, media_type="image/svg+xml")


@app.get("/api/health")
def health():
    return {
        "llm": engine.llm.health(),
        "l2": {"available": engine.ner.available, "loaded": engine.ner._ready, "error": engine.ner.error},
        "org_dna": {"documents": len(engine.orgdna.docs), "codenames": len(engine.orgdna.codenames), "allowlist": engine.orgdna.allowlist},
        "honeytokens": len(load_registry()),
        "l5_mode": config.L5_MODE,
    }


@app.post("/api/scan")
def scan(body: ScanIn):
    if not body.instruction.strip() and not body.content.strip():
        raise HTTPException(400, "Provide an instruction or content")
    return engine.scan(body.instruction, body.content, body.destination, body.session_id, body.l5_mode)


@app.post("/api/rehydrate")
def rehydrate(body: RehydrateIn):
    try:
        return engine.rehydrate(body.scan_id, body.reply)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@app.post("/api/answer-local")
def answer_local(body: ScanRef):
    try:
        return engine.answer_locally(body.scan_id)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@app.post("/api/orgdna/document")
def add_document(body: DocIn):
    engine.orgdna.register_document(body.name, body.text)
    return {"documents": len(engine.orgdna.docs)}


@app.post("/api/orgdna/codename")
def add_codename(body: TermIn):
    engine.orgdna.add_codename(body.term)
    return {"codenames": engine.orgdna.codenames}


@app.post("/api/allowlist")
def add_allowlist(body: TermIn):
    engine.orgdna.add_to_allowlist(body.term)
    return {"allowlist": engine.orgdna.allowlist}


@app.post("/api/honeytokens")
def new_honeytoken(body: HoneytokenIn):
    token = generate_honeytoken()
    rec = register_honeytoken(token, body.id or token[:7], body.planted_in)
    return {"token": token, "id": rec["id"], "planted_in": rec["planted_in"],
            "note": "Plant this token now. Only its HMAC is stored; it is not shown again."}
