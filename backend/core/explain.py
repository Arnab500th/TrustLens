# backend/core/explain.py
# Writes the plain explanation. AI only explains the findings, it never decides the label.
# explain(result) is a normal function (not async) and never raises.
import json
import os
import re

import httpx

try:                                   # optional: read backend/.env if python-dotenv is installed
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MAX_POINTS = 5
SUMMARIES = {
    "Low Risk": "No significant warning signs were found in the checks that ran. "
                "This does not prove it is safe, so stay careful.",
    "Suspicious": "This shows some warning signs and deserves a closer look before you trust it.",
    "High Risk": "This shows several serious warning signs and is likely a scam or phishing attempt.",
    "Confirmed Malicious": "A trusted threat list reports this as malicious. Do not open it.",
    "Inconclusive": "Too many checks could not run, so there is not enough information to judge this.",
}
NO_FINDINGS = ("No significant warning signs were found in the checks that ran. "
               "This does not prove it is safe, so stay careful.")

SYSTEM_RULES = (
    "You explain a phishing and scam risk result to an ordinary person in plain English. "
    "Use ONLY the findings given. Do not add facts. Cite the finding id that supports each sentence. "
    "Never say a link or message is safe or harmless. Do not change the label. "
    'Answer with JSON only, in this shape: {"summary": "...", '
    '"points": [{"text": "...", "evidence": ["FINDING_ID"]}]}. '
    "Write at most 5 points, each one short sentence."
)


def _template(result: dict) -> dict:
    findings = result.get("findings") or []
    label = result.get("label", "Inconclusive")
    if not findings:
        return {"summary": NO_FINDINGS if label == "Low Risk" else SUMMARIES.get(label, NO_FINDINGS),
                "points": [], "source": "template"}
    top = sorted(findings, key=lambda f: f.get("points", 0), reverse=True)[:MAX_POINTS]
    return {"summary": SUMMARIES.get(label, SUMMARIES["Inconclusive"]),
            "points": [{"text": f["description"], "evidence": [f["id"]]} for f in top],
            "source": "template"}


def _parse_json(text: str):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON found")
    return json.loads(text[start:end + 1])


NEGATION = re.compile(r"(\bnot\b|n't\b|\bnever\b|\bno\b|\bcannot\b|\bun)\W+(?:\w+\W+){0,3}$", re.I)


def _claims_safe(text: str) -> bool:
    """True if the text says the item is safe or harmless (but 'not safe' or 'unsafe' is fine)."""
    for m in re.finditer(r"\b(safe|safely|harmless|risk[- ]free)\b", text, re.I):
        before = text[max(0, m.start() - 40):m.start()]
        if not NEGATION.search(before):
            return True
    return bool(re.search(r"\bno risk\b", text, re.I))


def _validate(data, finding_ids: set) -> dict:
    """Returns a clean explanation or raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError("not an object")
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("empty summary")
    points = data.get("points")
    if not isinstance(points, list):
        raise ValueError("points is not a list")
    clean = []
    for p in points[:MAX_POINTS]:
        text, ev = p.get("text"), p.get("evidence")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("empty point text")
        if not isinstance(ev, list) or not ev or not all(isinstance(e, str) for e in ev):
            raise ValueError("point has no evidence")
        if not set(ev) <= finding_ids:
            raise ValueError("cites an id that is not a finding")
        clean.append({"text": text.strip(), "evidence": ev})
    if _claims_safe(summary) or any(_claims_safe(p["text"]) for p in clean):
        raise ValueError("claims the link is safe")
    return {"summary": summary.strip(), "points": clean, "source": "ai"}


GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_DEFAULT_MODEL = "openai/gpt-oss-20b"      # check console.groq.com/docs/models for current names
TIMEOUT_SECONDS = 8


def _payload_for(result: dict):
    """Finding id, description, points only. Never raw page text or raw message."""
    findings = [{"id": f["id"], "description": f["description"], "points": f["points"]}
                for f in result["findings"]]
    payload = {"label": result["label"], "score": result["score"], "findings": findings}
    return payload, {f["id"] for f in findings}


def _ask_anthropic(result: dict) -> dict:
    import anthropic                                     # only needed for this mode
    key = os.environ.get("LLM_API_KEY", "")
    if not key:
        raise RuntimeError("no LLM_API_KEY")
    model = os.environ.get("LLM_MODEL", "claude-haiku-5-5")   # check the docs for the current name
    payload, ids = _payload_for(result)
    client = anthropic.Anthropic(api_key=key, timeout=TIMEOUT_SECONDS, max_retries=0)
    resp = client.messages.create(model=model, max_tokens=500, temperature=0,
                                  system=SYSTEM_RULES,
                                  messages=[{"role": "user", "content": json.dumps(payload)}])
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    return _validate(_parse_json(text), ids)


def _ask_openai_compatible(result: dict, provider: str) -> dict:
    """Works with Groq and any OpenAI-style endpoint (Mistral, OpenRouter, NVIDIA ...)."""
    key = os.environ.get("LLM_API_KEY", "")
    if not key:
        raise RuntimeError("no LLM_API_KEY")
    if provider == "groq":
        base = os.environ.get("LLM_BASE_URL", GROQ_BASE_URL)
        model = os.environ.get("LLM_MODEL", GROQ_DEFAULT_MODEL)
    else:
        base = os.environ.get("LLM_BASE_URL", "")
        model = os.environ.get("LLM_MODEL", "")
        if not base or not model:
            raise RuntimeError("LLM_BASE_URL and LLM_MODEL are required")
    payload, ids = _payload_for(result)
    body = {"model": model, "temperature": 0, "max_tokens": 700,
            "messages": [{"role": "system", "content": SYSTEM_RULES},
                         {"role": "user", "content": json.dumps(payload)}]}
    if model.startswith("openai/gpt-oss"):
        body["reasoning_effort"] = "low"                 # keeps thinking short so the JSON fits
    r = httpx.post(base.rstrip("/") + "/chat/completions", json=body, timeout=TIMEOUT_SECONDS,
                   headers={"Authorization": "Bearer " + key})
    r.raise_for_status()
    text = r.json()["choices"][0]["message"]["content"] or ""
    try:
        return _validate(_parse_json(text), ids)
    except Exception as e:
        raise ValueError(f"{e} | raw reply: {text[:300]!r}")


def explain(result: dict) -> dict:
    try:
        provider = os.environ.get("LLM_PROVIDER", "template").lower()
        if result.get("findings"):
            if provider == "anthropic":
                return _ask_anthropic(result)
            if provider in ("groq", "openai_compatible"):
                return _ask_openai_compatible(result, provider)
    except Exception as e:
        if os.environ.get("LLM_DEBUG"):
            print("LLM fallback reason:", repr(e)[:600])
        # any failure -> template
    try:
        return _template(result)
    except Exception:
        return {"summary": "No explanation is available.", "points": [], "source": "template"}


if __name__ == "__main__":
    sample = {"label": "High Risk", "score": 75, "findings": [
        {"id": "NEW_DOMAIN", "source": "domain", "description": "Domain is 9 days old", "points": 20},
        {"id": "LOOKALIKE_BRAND", "source": "url", "description": "Name looks like paypal.com", "points": 30}]}
    out = explain(sample)
    print(out)
    ids = {f["id"] for f in sample["findings"]}
    cited = {e for pt in out["points"] for e in pt["evidence"]}
    ok = cited <= ids and bool(out["summary"])
    print("empty:", explain({"label": "Low Risk", "score": 0, "findings": []})["summary"])

    # offline checks of the AI validation (no key needed)
    good = _parse_json('```json\n{"summary":"Likely phishing.","points":[{"text":"New site.","evidence":["NEW_DOMAIN"]}]}\n```')
    ok1 = _validate(good, ids)["source"] == "ai"
    bad_cases = [
        {"summary": "Likely phishing.", "points": [{"text": "x", "evidence": ["MADE_UP"]}]},
        {"summary": "", "points": []},
        {"summary": "This site is safe.", "points": []},
        {"summary": "Fine.", "points": [{"text": "x", "evidence": []}]},
    ]
    ok2 = True
    for b in bad_cases:
        try:
            _validate(b, ids)
            ok2 = False
        except ValueError:
            pass
    # offline test of the Groq path with a fake network reply
    class _Resp:
        def __init__(self, text): self._t = text
        def raise_for_status(self): pass
        def json(self): return {"choices": [{"message": {"content": self._t}}]}

    real_post, saved = httpx.post, {k: os.environ.get(k) for k in ("LLM_PROVIDER", "LLM_API_KEY")}
    os.environ["LLM_PROVIDER"], os.environ["LLM_API_KEY"] = "groq", "test-key"
    try:
        httpx.post = lambda *a, **k: _Resp('```json\n{"summary":"Likely phishing.","points":[{"text":"New site.","evidence":["NEW_DOMAIN"]}]}\n```')
        ok3 = explain(sample)["source"] == "ai"
        httpx.post = lambda *a, **k: _Resp('{"summary":"Likely phishing.","points":[{"text":"x","evidence":["FAKE_ID"]}]}')
        ok4 = explain(sample)["source"] == "template"          # bad id -> template
        def _boom(*a, **k): raise httpx.ConnectError("down")
        httpx.post = _boom
        ok5 = explain(sample)["source"] == "template"          # network down -> template
    finally:
        httpx.post = real_post
        for k, v in saved.items():
            if v is None: os.environ.pop(k, None)
            else: os.environ[k] = v
    ok6 = (not _claims_safe("It impersonates a legitimate brand and is not safe.")
           and not _claims_safe("This does not prove it is safe, so stay careful.")
           and not _claims_safe("The site looks unsafe.")
           and _claims_safe("This site is safe.") and _claims_safe("The link is harmless."))
    print("safe-word check:", "OK" if ok6 else "WRONG")
    ok5 = ok5 and ok6
    print("mock Groq path:", "OK" if ok3 and ok4 and ok5 else "WRONG")

    provider = os.environ.get("LLM_PROVIDER", "template")
    if provider != "template" and os.environ.get("LLM_API_KEY"):
        os.environ["LLM_DEBUG"] = "1"
        live = explain(sample)
        print("live", provider, "->", live["source"], "(template means the call failed: check key, model, internet)")
    else:
        print("AI mode: off (template). Set LLM_PROVIDER=groq and LLM_API_KEY to test live.")
    print("PASS" if ok and ok1 and ok2 and ok3 and ok4 and ok5 else "FAIL")