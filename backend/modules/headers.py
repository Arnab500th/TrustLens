# backend/modules/headers.py
# Web application security headers and transport posture assessment.
import asyncio
import httpx

from core.context import assert_public
from core.models import Finding, ModuleResult, ScanContext


def findings_from_headers(headers: dict, final_url: str) -> list[Finding]:
    """Pure analysis of HTTP response security headers."""
    findings = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # 1. Transport security (HSTS)
    hsts = headers_lower.get("strict-transport-security", "")
    if not hsts or "max-age=" not in hsts:
        findings.append(Finding(
            id="MISSING_HSTS",
            source="headers",
            description="Missing HTTP Strict Transport Security (HSTS) header",
            points=10
        ))
    else:
        # Check max-age duration
        try:
            for part in hsts.split(";"):
                part = part.strip()
                if part.startswith("max-age="):
                    seconds = int(part.split("=")[1])
                    if seconds < 31536000:  # 1 year
                        findings.append(Finding(
                            id="MISSING_HSTS",
                            source="headers",
                            description=f"HSTS max-age is too short ({seconds} seconds, recommend >= 31536000)",
                            points=5
                        ))
                    break
        except (ValueError, IndexError):
            pass

    # 2. Content Security Policy (CSP)
    csp = headers_lower.get("content-security-policy", "")
    if not csp:
        findings.append(Finding(
            id="MISSING_CSP",
            source="headers",
            description="Missing Content-Security-Policy (CSP) header to prevent XSS and code injection",
            points=10
        ))

    # 3. Clickjacking protection (X-Frame-Options or CSP frame-ancestors)
    xfo = headers_lower.get("x-frame-options", "")
    has_xfo = any(opt in xfo for opt in ("deny", "sameorigin"))
    has_frame_ancestors = "frame-ancestors" in csp
    if not has_xfo and not has_frame_ancestors:
        findings.append(Finding(
            id="MISSING_FRAME_PROTECTION",
            source="headers",
            description="Missing clickjacking protection (neither X-Frame-Options nor CSP frame-ancestors configured)",
            points=10
        ))

    # 4. Insecure HTTP fallback
    if final_url.lower().startswith("http://"):
        findings.append(Finding(
            id="INSECURE_HTTP",
            source="headers",
            description="Destination resolved over unencrypted HTTP protocol",
            points=20
        ))

    return findings


async def run(ctx: ScanContext) -> ModuleResult:
    current_url = ctx.url
    headers = {}
    facts = {}

    try:
        # Follow up to 3 redirects safely with assert_public check on each step
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            for _ in range(3):
                assert_public(current_url)
                resp = await client.get(current_url, follow_redirects=False)
                headers = dict(resp.headers)
                if resp.is_redirect and "location" in resp.headers:
                    next_url = resp.headers["location"]
                    if not next_url.startswith("http"):
                        from urllib.parse import urljoin
                        next_url = urljoin(current_url, next_url)
                    current_url = next_url
                else:
                    break

        findings = findings_from_headers(headers, current_url)
        facts = {
            "has_hsts": "strict-transport-security" in {k.lower(): v for k, v in headers.items()},
            "has_csp": "content-security-policy" in {k.lower(): v for k, v in headers.items()},
            "server": headers.get("server") or headers.get("Server"),
            "final_url": current_url
        }
        return ModuleResult(
            module="headers",
            status="ok",
            findings=findings,
            facts=facts
        )
    except Exception as e:
        return ModuleResult(
            module="headers",
            status="failed",
            error=str(e)[:200],
            facts=facts
        )


if __name__ == "__main__":
    clean = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY"
    }
    f_clean = findings_from_headers(clean, "https://secure.bank.com")
    print("clean headers:", [f.id for f in f_clean])

    poor = {"Server": "Apache"}
    f_poor = findings_from_headers(poor, "http://insecure-site.com")
    print("poor headers :", [f.id for f in f_poor])

    ok = (len(f_clean) == 0 and "MISSING_HSTS" in [f.id for f in f_poor] and
          "MISSING_CSP" in [f.id for f in f_poor] and
          "MISSING_FRAME_PROTECTION" in [f.id for f in f_poor] and
          "INSECURE_HTTP" in [f.id for f in f_poor])
    print("PASS" if ok else "FAIL")

