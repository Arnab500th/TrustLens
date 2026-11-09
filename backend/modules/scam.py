# backend/modules/scam.py
# Reads a pasted message, finds scam signs, pulls out links, scans each link.
# Combines AI LLM message classification with deterministic regex heuristics.
import asyncio
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from core.models import Finding, ModuleResult
from core.scoring import recommendations_for, score_scan

MAX_TEXT = 5000
MAX_LINKS = 3

# (id, regex, points, description)
RULES = [
    ("URGENT_LANGUAGE",
     r"\b(act now|immediately|urgent(ly)?|within \d+ ?(hours?|hrs?|minutes?|mins?)|last chance|expires? (today|soon)|final (notice|warning))\b",
     10, "The message pressures you to act right now."),
    ("THREAT_LANGUAGE",
     r"\b(account (will be |has been |is )?(suspended|blocked|closed|locked|deactivated)|legal action|arrest(ed)?|penalty|permanently (blocked|closed)|sim (will be )?blocked)\b",
     15, "The message threatens account closure or legal action."),
    ("MONEY_REQUEST",
     r"\b(gift ?cards?|bitcoin|crypto(currency)?|wire transfer|send money|western union|processing fee|pay a fee|registration fee)\b",
     20, "The message asks for gift cards, crypto or a money transfer."),
    ("ASKS_SENSITIVE_INFO",
     r"\b(share|send|enter|provide|give|tell|reply with|confirm|submit)\b\W+(?:\w+\W+){0,4}?(otp|one[- ]time password|password|pin|cvv|card number|seed phrase|recovery phrase)\b",
     25, "The message asks for an OTP, password, PIN or card number."),
    ("PRIZE_OR_REFUND_BAIT",
     r"\b(you (have )?won|you('ve| have) been selected|lottery|refund|cash ?back|claim your|prize|lucky draw)\b",
     15, "The message promises a prize, refund or cashback."),
    ("IMPERSONATION_CLAIM",
     r"\b(this is (the )?(sbi|hdfc|icici|axis bank|paytm|income tax|customs|rbi|amazon)|support team|customer care|income tax department|bank officer)\b",
     10, "The message claims to come from a bank, office or company."),
    ("KYC_BAIT",
     r"(\bkyc\b|verify your (account|identity|details)|update your (details|kyc|account|pan|aadhaar))",
     15, "The message asks you to update or verify your details."),
    ("SENDER_PERSONAL_NUMBER",
     r"$^",
     25, "Message sent from an ordinary personal mobile number instead of an official registered sender header."),
    ("SENDER_NAME_MISMATCH",
     r"$^",
     20, "Sender header name does not match the claimed organization."),
]
COMPILED = [(i, re.compile(rx, re.I), pts, desc) for i, rx, pts, desc in RULES]
NEGATION_AWARE = {"ASKS_SENSITIVE_INFO"}            # "never share your OTP" is a warning, not a request
_NEG = re.compile(r"(\bnot\b|n't\b|\bnever\b|\bno one\b)\W+(?:\w+\W+){0,2}$", re.I)

URL_RE = re.compile(r"https?://[^\s<>\"']+|\bwww\.[^\s<>\"']+|"
                    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|in|co|io|xyz|top|info|online|site|link|ly|me|app)/[^\s<>\"']*",
                    re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)|(?<![\d.])\+?\d{1,3}[\s-]\d{3,5}[\s-]\d{4,6}(?![\d.])")

# Load trained Indian SMS scam model (TF-IDF + LogisticRegression)
_MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scam_india_model.joblib")
_SCAM_ML_MODEL = None
try:
    import joblib
    if os.path.exists(_MODEL_PATH):
        _SCAM_ML_MODEL = joblib.load(_MODEL_PATH)
except Exception:
    _SCAM_ML_MODEL = None


def classify_message_ml(text: str) -> tuple[list[Finding], dict]:
    """Runs zero-latency local ML inference using trained Indian SMS dataset model."""
    global _SCAM_ML_MODEL
    if _SCAM_ML_MODEL is None or not (text or "").strip():
        return [], {}
    try:
        prob = float(_SCAM_ML_MODEL.predict_proba([text[:2000]])[0][1])
        facts = {
            "ml_model": "scam-ham-india",
            "ml_scam_probability": round(prob, 3),
            "ml_label": "scam" if prob >= 0.65 else "ham"
        }
        findings = []
        if prob >= 0.65:
            findings.append(Finding(
                id="IMPERSONATION_CLAIM",
                source="scam",
                description=f"Trained Indian SMS ML model flagged message as high-confidence scam ({int(prob * 100)}% scam probability)",
                points=25 if prob >= 0.85 else 20,
                data=facts
            ))
        return findings, facts
    except Exception:
        return [], {}


def extract_indicators(text: str) -> dict:
    text = (text or "")[:MAX_TEXT]
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    urls = []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;:!?)]}>'\"")
        if "@" in u.split("/")[0] and not u.lower().startswith("http"):
            continue                                   # part of an email address
        if not u.lower().startswith("http"):
            u = "http://" + u
        if u not in urls:
            urls.append(u)
    phones = list(dict.fromkeys(p.strip() for p in PHONE_RE.findall(text)))
    return {"urls": urls, "emails": emails, "phones": phones}


def scan_text(text: str) -> list:
    """One finding per matching rule (each id once)."""
    text = (text or "")[:MAX_TEXT]
    findings = []
    for fid, rx, pts, desc in COMPILED:
        hit = False
        for m in rx.finditer(text):
            before = text[max(0, m.start() - 25):m.start()]
            if fid in NEGATION_AWARE and _NEG.search(before):
                continue
            hit = True
            break
        if hit:
            findings.append(Finding(id=fid, source="scam", description=desc, points=pts))
    return findings


AI_SCAM_SYSTEM = (
    "You are an expert security NLP classifier for SMS and phishing messages. "
    "Classify whether the text shows signs of social engineering or scam, taking into account the Sender identifier and claimed organization. "
    "Note on SMS Headers: Registered institutional headers (like VM-HDFCBK, AD-SBIINB, AX-ICICIB, BZ-AMAZON) use a 2-letter telecom prefix followed by the organization name. If the header matches the organization (e.g., HDFCBK for HDFC), it is an authentic institutional header—do NOT flag SENDER_NAME_MISMATCH or IMPERSONATION_CLAIM for normal transactional alerts. "
    "Conversely, if a message claiming to be from a bank/courier/tax authority is sent from an ordinary 10-digit personal mobile number, flag SENDER_PERSONAL_NUMBER. "
    "Return JSON ONLY with this exact structure: "
    "{\"is_scam\": true, \"confidence\": 0.95, "
    "\"matched_tactics\": [\"URGENT_LANGUAGE\", \"THREAT_LANGUAGE\", \"MONEY_REQUEST\", "
    "\"ASKS_SENSITIVE_INFO\", \"PRIZE_OR_REFUND_BAIT\", \"IMPERSONATION_CLAIM\", \"KYC_BAIT\", \"SENDER_PERSONAL_NUMBER\", \"SENDER_NAME_MISMATCH\"], "
    "\"reasons\": [\"short reason\"]}. "
    "Only cite tactics from that list. If the message is a legitimate bank transaction notification, is_scam should be false and matched_tactics should be empty."
)


def check_sender_rules(sender: str, text: str, claim: str) -> list[Finding]:
    """Evaluates whether the sender header or phone number matches institutional norms."""
    sender = (sender or "").strip()
    if not sender:
        return []

    findings = []
    # Identify if sender is a personal/unregistered 10+ digit mobile number
    is_personal_phone = bool(re.search(r"^\+?[\d\s()-]{10,}$", sender))

    # Detect institutional authority keywords in text or claim
    has_institution_pretext = bool(re.search(
        r"\b(sbi|hdfc|icici|axis|paytm|phonepe|bank|rbi|income tax|tax department|customs|courier|delivery|india post|fedex|dhl|kyc|pan card|aadhaar|account blocked|credit card)\b",
        text, re.I
    )) or bool(claim and claim.lower() != "not sure")

    if is_personal_phone and has_institution_pretext:
        findings.append(Finding(
            id="SENDER_PERSONAL_NUMBER",
            source="scam",
            description=f"Message claiming to be from {claim or 'a bank/institution'} was sent from an ordinary personal mobile number ({sender}) instead of a registered institutional header ID",
            points=25,
            data={"sender": sender, "sender_type": "personal_mobile_number"}
        ))
    elif not is_personal_phone and len(sender) >= 3:
        # Check alphanumeric header mismatch (e.g. TRAI SMS headers like VM-HDFCBK)
        sender_letters = re.sub(r"[^a-zA-Z]", "", sender).lower()
        text_lower = text.lower()
        if "hdfc" in text_lower and "hdfc" not in sender_letters:
            findings.append(Finding(
                id="SENDER_NAME_MISMATCH",
                source="scam",
                description=f"Message references HDFC Bank, but sender ID '{sender}' does not match official bank headers",
                points=20,
                data={"sender": sender, "expected": "HDFC"}
            ))
        elif ("sbi" in text_lower or "state bank" in text_lower) and "sbi" not in sender_letters:
            findings.append(Finding(
                id="SENDER_NAME_MISMATCH",
                source="scam",
                description=f"Message references State Bank of India, but sender ID '{sender}' does not match official SBI headers",
                points=20,
                data={"sender": sender, "expected": "SBI"}
            ))
        elif "icici" in text_lower and "icici" not in sender_letters:
            findings.append(Finding(
                id="SENDER_NAME_MISMATCH",
                source="scam",
                description=f"Message references ICICI Bank, but sender ID '{sender}' does not match official ICICI headers",
                points=20,
                data={"sender": sender, "expected": "ICICI"}
            ))

    return findings


def classify_message_ai(text: str, sender: str = "", claim: str = "") -> tuple[list[Finding], dict]:
    key = os.environ.get("LLM_API_KEY", "")
    if not key or not text.strip():
        return [], {}

    base_url = os.environ.get("LLM_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
    model = os.environ.get("LLM_MODEL", "openai/gpt-oss-20b")

    user_prompt = (
        f"Sender Header/Number: {sender or 'Not provided'}\n"
        f"Claimed Entity/Category: {claim or 'Not specified'}\n"
        f"Message Text:\n{text[:1000]}"
    )

    try:
        body = {
            "model": model,
            "temperature": 0,
            "max_tokens": 400,
            "messages": [
                {"role": "system", "content": AI_SCAM_SYSTEM},
                {"role": "user", "content": user_prompt}
            ]
        }
        if model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"

        r = httpx.post(
            base_url + "/chat/completions",
            json=body,
            timeout=5.0,
            headers={"Authorization": "Bearer " + key}
        )
        if r.status_code != 200:
            return [], {}

        content = r.json()["choices"][0]["message"]["content"]
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.I)
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end == -1:
            return [], {}

        data = json.loads(content[start:end + 1])
        tactics = data.get("matched_tactics", [])
        conf = float(data.get("confidence", 0.0))

        pts_map = {fid: (pts, desc) for fid, _, pts, desc in RULES}
        ai_findings = []
        for fid in tactics:
            if fid in pts_map:
                pts, desc = pts_map[fid]
                ai_findings.append(Finding(
                    id=fid,
                    source="scam",
                    description=f"{desc} (AI NLP confidence: {int(conf * 100)}%)",
                    points=pts,
                    data={"ai_confidence": conf, "model": model}
                ))
        return ai_findings, {"ai_confidence": conf, "is_scam": data.get("is_scam", False), "ai_provider": "groq"}
    except Exception:
        return [], {}


async def analyze_message(text: str, sender: str = "", claim: str = "", past_scans=None) -> dict:
    from core.orchestrator import scan_url, _fallback_explanation      # inside: avoids an import loop
    start = time.monotonic()
    text = (text or "")[:MAX_TEXT]
    ind = extract_indicators(text)
    urls = ind["urls"][:MAX_LINKS]

    # Run heuristic text scan, sender verification, local ML model, and AI classification
    rule_findings = scan_text(text)
    sender_findings = check_sender_rules(sender, text, claim)
    ml_findings, ml_facts = classify_message_ml(text)
    ai_findings, ai_facts = await asyncio.to_thread(classify_message_ai, text, sender, claim)

    # Merge findings: keep highest points / descriptions
    findings_by_id = {}
    for f in rule_findings + sender_findings + ml_findings + ai_findings:
        if f.id not in findings_by_id or f.points > findings_by_id[f.id].points:
            findings_by_id[f.id] = f

    combined_findings = list(findings_by_id.values())
    facts = {
        "links_found": len(ind["urls"]),
        "emails_found": len(ind["emails"]),
        "phones_found": len(ind["phones"]),
        "sender": sender,
        "claim": claim,
        "is_personal_sender": bool(re.search(r"^\+?[\d\s()-]{10,}$", sender)) if sender else False
    }
    facts.update(ml_facts)
    facts.update(ai_facts)

    scam_result = ModuleResult(module="scam", status="ok", findings=combined_findings,
                               facts=facts, duration_ms=int((time.monotonic() - start) * 1000))
    results = [scam_result]
    checks = [{"module": "scam", "status": "ok", "duration_ms": scam_result.duration_ms}]

    # scan up to 3 links at the same time
    scans = await asyncio.gather(*[scan_url(u, past_scans) for u in urls], return_exceptions=True)
    link_results = []
    for n, (u, s) in enumerate(zip(urls, scans), 1):
        if isinstance(s, Exception):
            link_results.append({"url": u, "label": "Inconclusive", "score": 0,
                                 "error": "blocked or could not be checked"})
            checks.append({"module": f"link{n}", "status": "failed", "duration_ms": 0,
                           "error": str(s)[:100]})
            results.append(ModuleResult(module=f"link{n}", status="failed"))
            continue
        link_results.append({"url": u, "label": s["label"], "score": s["score"]})
        checks.append({"module": f"link{n}", "status": "ok", "duration_ms": 0})
        results.append(ModuleResult(module=f"link{n}", status="ok",
                                    findings=[Finding(**f) for f in s["findings"]]))

    scored = score_scan(results, min_checks=1, expected=1)
    first = urls[0] if urls else ""
    result = {
        "scan_id": uuid.uuid4().hex[:8],
        "url": first,
        "host": urlsplit(first).hostname or "",
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": scored["score"],
        "label": scored["label"],
        "coverage": min(1.0, scored["coverage"]),
        "findings": scored["findings"],
        "facts": {"scam": scam_result.facts},
        "checks": checks,
        "unavailable": scored["unavailable"],
        "recommendations": recommendations_for(scored["label"]),
        "urls_found": ind["urls"],
        "link_results": link_results,
    }
    try:
        from core.explain import explain
        result["explanation"] = await asyncio.to_thread(explain, result)
    except Exception:
        result["explanation"] = _fallback_explanation(result)
    return result                                        # the raw message is never stored or logged


if __name__ == "__main__":
    bad = "URGENT: your account will be suspended. Act now and send a gift card, share your OTP."
    good = "Hi, are we still meeting for lunch tomorrow at 1?"
    bad_ids = {f.id for f in scan_text(bad)}
    good_ids = {f.id for f in scan_text(good)}
    print("bad :", sorted(bad_ids))
    print("good:", sorted(good_ids))
    ok = {"URGENT_LANGUAGE", "MONEY_REQUEST", "ASKS_SENSITIVE_INFO"} <= bad_ids and not good_ids

    # extra offline checks
    warn = scan_text("Never share your OTP with anyone. Bank staff will not ask for it.")
    one_weak = score_scan([ModuleResult(module="scam", findings=scan_text("Please reply urgently."))],
                          min_checks=1, expected=1)["label"]
    ind = extract_indicators("Click http://evil.example.xyz/login. now or www.fake-bank.in/kyc, "
                             "mail help@bank.com or call +91 98765 43210 / 9876543210")
    print("indicators:", ind)
    ok2 = (not warn and one_weak == "Low Risk" and len(ind["urls"]) == 2
           and ind["emails"] == ["help@bank.com"] and len(ind["phones"]) >= 1)

    # full flow with a fake link scanner (no internet needed)
    import core.orchestrator as orch

    async def fake_scan(url, past_scans=None):
        return {"label": "High Risk", "score": 75,
                "findings": [{"id": "LOOKALIKE_BRAND", "source": "url", "description": "Looks like sbi.co.in",
                              "points": 30, "data": {}}]}
    real = orch.scan_url
    orch.scan_url = fake_scan
    try:
        r1 = asyncio.run(analyze_message(bad + " Visit http://sbi-kyc.example.xyz/ now"))
        r2 = asyncio.run(analyze_message(good))
    finally:
        orch.scan_url = real
    print("message with link:", r1["label"], r1["score"], [l["label"] for l in r1["link_results"]])
    print("harmless message :", r2["label"], r2["score"])
    needed = {"scan_id", "url", "host", "checked_at", "score", "label", "coverage", "findings", "facts",
              "checks", "unavailable", "explanation", "recommendations", "urls_found", "link_results"}
    ok3 = (r1["label"] == "High Risk" and len(r1["link_results"]) == 1 and needed <= set(r1)
           and r2["label"] == "Low Risk" and r2["score"] == 0)
    print("PASS" if ok and ok2 and ok3 else "FAIL")