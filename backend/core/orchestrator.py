# backend/core/orchestrator.py
# Runs all checks at the same time, scores them, adds the explanation, returns one result (shape B4).
import asyncio
import importlib
import time
from datetime import datetime, timezone

from core.context import assert_public, build_context, normalize_url
from core.models import Finding, ModuleResult
from core.scoring import recommendations_for, score_scan

# seconds each check may take
TIMEOUTS = {"url": 2, "domain": 6, "certificate": 6, "headers": 6, "reputation": 5, "page": 10}
NAMES = list(TIMEOUTS)
DEFAULT_TIMEOUT = 10


def _stub(name):
    """Used while a teammate's file has not arrived. Counts as 'skipped'."""
    async def run(ctx):
        return ModuleResult(module=name, status="skipped", error="module file not installed yet")
    return run


def _broken(name, why):
    async def run(ctx):
        return ModuleResult(module=name, status="failed", error=("import error: " + why)[:200])
    return run


def load_module(name):
    """Return modules.<name>.run, or a stub if the file does not exist yet."""
    try:
        return importlib.import_module(f"modules.{name}").run
    except ModuleNotFoundError as e:
        if e.name == f"modules.{name}":      # the file itself is missing
            return _stub(name)
        return _broken(name, str(e))         # the file exists but needs a missing package
    except Exception as e:                   # the file exists but crashes on import
        return _broken(name, repr(e))


async def run_module(name, fn, ctx, timeout=None) -> ModuleResult:
    """Run one check with a time limit. Never raises."""
    limit = timeout if timeout is not None else TIMEOUTS.get(name, DEFAULT_TIMEOUT)
    start = time.monotonic()
    try:
        res = await asyncio.wait_for(fn(ctx), limit)
        if not isinstance(res, ModuleResult):
            res = ModuleResult(module=name, status="failed", error="did not return ModuleResult")
    except asyncio.TimeoutError:
        res = ModuleResult(module=name, status="failed", error="timeout")
    except Exception as e:
        res = ModuleResult(module=name, status="failed", error=(str(e) or repr(e))[:200])
    res.duration_ms = int((time.monotonic() - start) * 1000)
    return res


def _fallback_explanation(result: dict) -> dict:
    """Used only if core/explain.py is missing or crashes. Plain template, no AI."""
    top = result["findings"][:5]
    return {
        "summary": f"Result: {result['label']} (score {result['score']} out of 100).",
        "points": [{"text": f["description"], "evidence": [f["id"]]} for f in top],
        "source": "template",
    }


def _correlation_findings(result_so_far: dict, past_scans) -> list:
    try:
        from core.correlate import correlate
    except ImportError:
        return []
    try:
        return list(correlate(result_so_far, past_scans))
    except Exception:
        return []


async def scan_url(url: str, past_scans=None) -> dict:
    # 1. clean the link and block private addresses (ValueError goes up to main.py)
    clean = normalize_url(url)
    await asyncio.to_thread(assert_public, clean)
    ctx = build_context(clean)

    # 2. run the six checks at the same time
    results = await asyncio.gather(*[run_module(n, load_module(n), ctx) for n in NAMES])
    results = list(results)

    # 3. facts per module
    facts = {r.module: r.facts for r in results}

    # 4. correlation with earlier scans (optional)
    if past_scans:
        first = score_scan(results)
        so_far = {"scan_id": ctx.scan_id, "url": ctx.url, "host": ctx.host,
                  "findings": first["findings"], "facts": facts}
        extra = _correlation_findings(so_far, past_scans)
        if extra:
            results.append(ModuleResult(module="correlation", findings=extra))

    # 5. score and recommendations
    scored = score_scan(results)
    scored["coverage"] = min(1.0, scored["coverage"])
    result = {
        "scan_id": ctx.scan_id,
        "url": ctx.url,
        "host": ctx.host,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": scored["score"],
        "label": scored["label"],
        "coverage": scored["coverage"],
        "findings": scored["findings"],
        "facts": facts,
        "checks": [dict({"module": r.module, "status": r.status, "duration_ms": r.duration_ms},
                        **({"error": r.error} if r.error else {})) for r in results],
        "unavailable": scored["unavailable"],
        "recommendations": recommendations_for(scored["label"]),
    }

    # 6. explanation (AI or template). Never allowed to break the scan.
    try:
        from core.explain import explain
        result["explanation"] = await asyncio.to_thread(explain, result)
    except Exception:
        result["explanation"] = _fallback_explanation(result)
    return result


if __name__ == "__main__":
    import json
    from core.models import ScanContext

    # offline test: a crashing check and a slow check must not break anything
    async def _boom(ctx): raise RuntimeError("boom")
    async def _slow(ctx): await asyncio.sleep(5)
    _ctx = ScanContext(scan_id="t", url="https://example.com/", host="example.com",
                       registered_domain="example.com")
    r1 = asyncio.run(run_module("t", _boom, _ctx))
    r2 = asyncio.run(run_module("t", _slow, _ctx, timeout=0.2))
    print("run_module:", r1.status, r1.error, "|", r2.status, r2.error)
    ok_unit = r1.status == "failed" and r2.status == "failed" and r2.error == "timeout"

    # full scan (needs internet for the address check)
    try:
        result = asyncio.run(scan_url("http://example.com"))
    except ValueError as e:
        print("SKIPPED full scan:", e)
        print("PASS (unit only)" if ok_unit else "FAIL")
    else:
        print(json.dumps({k: result[k] for k in ("url", "score", "label", "coverage")}, indent=2))
        print("still stubbed:", [c["module"] for c in result["checks"] if c["status"] == "skipped"])
        needed = {"scan_id", "url", "host", "checked_at", "score", "label", "coverage", "findings",
                  "facts", "checks", "unavailable", "explanation", "recommendations"}
        missing = needed - set(result)
        print("PASS" if not missing and ok_unit else "FAIL: missing " + str(missing))