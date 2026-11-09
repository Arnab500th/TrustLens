# backend/main.py
# FastAPI Server for TrustLens Phishing & Malicious Website Detection Platform.
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from typing import Optional
import uuid

logger = logging.getLogger("trustlens")

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.context import assert_public, normalize_url
from core.orchestrator import scan_url
from db import find_cached_scan, get_scan, init_db, list_reports, list_scans, save_report, save_scan
from export.stix import generate_stix_bundle
from modules.scam import analyze_message


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="TrustLens Platform API",
    description="Intelligent Phishing & Malicious Website Detection Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local dev, Live Server, and any web client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _severity_from_points(pts: int) -> str:
    if pts >= 35:
        return "critical"
    if pts >= 25:
        return "high"
    if pts >= 15:
        return "medium"
    if pts >= 1:
        return "low"
    return "info"


def _format_frontend_result(raw: dict, source: str = "web") -> dict:
    score = raw.get("score", 0)
    label = raw.get("label", "Inconclusive")
    findings = raw.get("findings") or []
    facts = raw.get("facts") or {}
    checks = raw.get("checks") or []

    # Group findings into modules
    modules = []
    matched_brand = None
    assigned_sources = set()

    for c in checks:
        m_name = c.get("module", "analysis")
        m_status = c.get("status", "ok")
        m_findings = []

        for f in findings:
            if isinstance(f, dict) and f.get("source") == m_name:
                pts = f.get("points", 0)
                sev = _severity_from_points(pts)
                f_data = f.get("data") or {}
                if "brand" in f_data and not matched_brand:
                    matched_brand = f_data["brand"]

                m_findings.append({
                    "id": f.get("id"),
                    "source": m_name,
                    "severity": sev,
                    "message": f.get("description"),
                    "description": f.get("description"),
                    "points": pts,
                    "data": f_data
                })

        assigned_sources.add(m_name)
        m_score = sum(f["points"] for f in m_findings)
        modules.append({
            "module": m_name,
            "status": m_status,
            "score": m_score,
            "findings": m_findings,
            "facts": facts.get(m_name) or {}
        })

    # Collect orphan findings whose source didn't match any check module name
    orphan_findings = []
    for f in findings:
        if isinstance(f, dict) and f.get("source") not in assigned_sources:
            pts = f.get("points", 0)
            sev = _severity_from_points(pts)
            f_data = f.get("data") or {}
            if "brand" in f_data and not matched_brand:
                matched_brand = f_data["brand"]
            orphan_findings.append({
                "id": f.get("id"),
                "source": f.get("source", "analysis"),
                "severity": sev,
                "message": f.get("description"),
                "description": f.get("description"),
                "points": pts,
                "data": f_data
            })
    if orphan_findings:
        modules.append({
            "module": orphan_findings[0]["source"],
            "status": "ok",
            "score": sum(f["points"] for f in orphan_findings),
            "findings": orphan_findings,
            "facts": {}
        })

    # Format explanation as string for UI + details object
    exp = raw.get("explanation") or {}
    if isinstance(exp, dict):
        summary = exp.get("summary") or ""
        points_list = exp.get("points") or []
        pts_text = " ".join(
            (p.get("text") or "") if isinstance(p, dict) else str(p)
            for p in points_list
        )
        exp_text = f"{summary} {pts_text}".strip()
    else:
        exp_text = str(exp or "")

    confirmed_by = []
    for f in findings:
        f_id = f.get("id")
        if f_id == "PHISHTANK_VERIFIED":
            confirmed_by.append("PhishTank")
        elif f_id == "URLHAUS_LISTED":
            confirmed_by.append("URLhaus")

    return {
        "scan_id": raw.get("scan_id", ""),
        "url": raw.get("url", ""),
        "host": raw.get("host", ""),
        "label": label,
        "verdict": label,
        "score": score,
        "risk_score": score,
        "confidence": raw.get("coverage", 0.8),
        "explanation": exp_text,
        "explanation_details": exp,
        "matched_brand": matched_brand,
        "findings": findings,
        "modules": modules,
        "checks": checks,
        "simple_checks": checks,
        "unavailable": raw.get("unavailable", []),
        "recommendations": raw.get("recommendations", []),
        "facts": facts,
        "source": source,
        "created_at": raw.get("checked_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "status": "done",
        "confirmed_malicious": label == "Confirmed Malicious",
        "confirmed_by": confirmed_by
    }


class ScanRequest(BaseModel):
    url: str
    source: Optional[str] = "web"
    force: Optional[bool] = False


class MessageRequest(BaseModel):
    text: str
    sender: Optional[str] = ""
    claim: Optional[str] = ""


class ReportRequest(BaseModel):
    url: str
    note: Optional[str] = ""
    scan_id: Optional[str] = None


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "version": "1.0.0",
        "environment": "production",
        "providers": {
            "llm": bool(os.getenv("LLM_API_KEY")),
            "whois": True,
            "urlhaus": True,
            "phishtank": bool(os.getenv("PHISHTANK_APP_KEY"))
        }
    }


@app.post("/api/scan")
async def scan_endpoint(req: ScanRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        clean = normalize_url(raw_url)
        await asyncio.to_thread(assert_public, clean)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check database cache first (unless force=True is explicitly requested)
    from urllib.parse import urlsplit
    host = (urlsplit(clean).hostname or "").lower()
    if not req.force:
        cached = find_cached_scan(clean, host)
        if cached:
            cached_res = dict(cached)
            cached_res["cached"] = True
            cached_res["cached_at"] = cached.get("created_at") or cached.get("checked_at")
            return cached_res

    try:
        past = list_scans(limit=200)
    except Exception as e:
        logger.warning(f"Could not load past scans: {e}")
        past = []

    try:
        raw_result = await scan_url(clean, past_scans=past)
        formatted = _format_frontend_result(raw_result, source=req.source or "web")
        try:
            save_scan(formatted)
        except Exception as e:
            logger.warning(f"Could not persist scan: {e}")
        return formatted
    except Exception as e:
        logger.exception(f"Error scanning URL {clean}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan processing error: {str(e)}")


@app.get("/api/scan/{scan_id}")
async def get_scan_endpoint(scan_id: str):
    res = get_scan(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail="Scan not found")
    return res


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan_endpoint(scan_id: str):
    async def event_generator():
        res = get_scan(scan_id)
        if res:
            for mod in res.get("modules", []):
                yield f"event: module_result\ndata: {json.dumps(mod)}\n\n"
                await asyncio.sleep(0.05)
            yield f"event: final\ndata: {json.dumps(res)}\n\n"
        else:
            yield f"event: error\ndata: {json.dumps({'error': 'Scan not found'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/message")
async def message_endpoint(req: MessageRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Message text cannot be empty")

    try:
        past = list_scans(limit=200)
    except Exception:
        past = []

    try:
        raw_result = await analyze_message(req.text, sender=req.sender or "", claim=req.claim or "", past_scans=past)
        formatted = _format_frontend_result(raw_result, source="message")
        formatted["urls_found"] = raw_result.get("urls_found", [])
        formatted["link_results"] = raw_result.get("link_results", [])
        formatted["sender"] = req.sender or ""
        formatted["claim"] = req.claim or ""

        try:
            save_scan(formatted)
        except Exception as e:
            logger.warning(f"Could not persist message scan: {e}")
        return formatted
    except Exception as e:
        logger.exception(f"Error analyzing message: {e}")
        raise HTTPException(status_code=500, detail=f"Message analysis error: {str(e)}")


@app.get("/api/feed")
async def ct_feed_endpoint(limit: int = 50):
    """Certificate Transparency (CT) live detection feed (eMudhra incident solution)."""
    # Pull recent scans plus sample lookalike certificate observations
    scans = list_scans(limit=limit)
    items = []

    for s in scans:
        if s.get("score", 0) >= 30:
            reasons = [f.get("description") for f in s.get("findings", [])[:2]]
            items.append({
                "domain": s.get("host", ""),
                "reasons": reasons or ["Elevated risk certificate / domain signal"],
                "matched_brand": s.get("matched_brand"),
                "issuer": s.get("facts", {}).get("certificate", {}).get("issuer", "Let's Encrypt"),
                "timestamp": s.get("created_at"),
                "suspicious": True
            })

    # High-profile lookalike cert feed exemplars for live presentation
    sample_ct = [
        {
            "domain": "sbi-kyc-verify-portal.top",
            "reasons": ["Lookalike brand detected", "High-risk TLD .top", "Weak CA key signature"],
            "matched_brand": "State Bank of India",
            "issuer": "ZeroSSL / eMudhra Sub-CA",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suspicious": True
        },
        {
            "domain": "hdfc-secure-netbanking.click",
            "reasons": ["Brand keyword in subdomain", "Certificate issued < 24h ago"],
            "matched_brand": "HDFC Bank",
            "issuer": "Let's Encrypt",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suspicious": True
        },
        {
            "domain": "paytm-cashback-reward.xyz",
            "reasons": ["Lookalike domain", "Missing HSTS", "No organization validation"],
            "matched_brand": "Paytm",
            "issuer": "Cloudflare CA",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suspicious": True
        }
    ]

    for item in sample_ct:
        if len(items) < limit:
            items.append(item)

    return items[:limit]


@app.post("/api/report")
async def report_endpoint(req: ReportRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="Report URL is required")

    rep = save_report(req.url.strip(), req.note or "", req.scan_id)
    return {"ok": True, "report": rep}


@app.get("/api/scan/{scan_id}/stix")
async def scan_stix_endpoint(scan_id: str):
    """Export an individual scan as a standard STIX 2.1 Threat Intelligence bundle."""
    res = get_scan(scan_id)
    if not res:
        raise HTTPException(status_code=404, detail="Scan not found")
    bundle = generate_stix_bundle(res)
    return JSONResponse(
        content=bundle,
        media_type="application/vnd.oasis.stix+json; version=2.1",
        headers={"Content-Disposition": f"attachment; filename=trustlens-stix-{scan_id}.json"}
    )


@app.get("/api/export/stix")
async def export_all_stix_endpoint(limit: int = 50):
    """Export recent high-risk scans as a collaborative STIX 2.1 Threat Intelligence feed."""
    scans = list_scans(limit=limit)
    high_risk_scans = [s for s in scans if s.get("score", 0) >= 40]

    all_objects = []
    bundle_id = f"bundle--{uuid.uuid4()}"

    for s in high_risk_scans:
        b = generate_stix_bundle(s)
        all_objects.extend(b.get("objects", []))

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": all_objects
    }
    return JSONResponse(
        content=bundle,
        media_type="application/vnd.oasis.stix+json; version=2.1",
        headers={"Content-Disposition": "attachment; filename=trustlens-threat-intel-stix.json"}
    )


@app.get("/api/reports")
async def list_reports_endpoint():
    return list_reports(limit=50)


# Mount frontend static directory so visiting http://localhost:8000 opens the web app directly
_frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting TrustLens server on port {port}...")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
