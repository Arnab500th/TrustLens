# backend/modules/page.py
# Downloads the page text safely (no scripts are ever run) and looks for
# password boxes, hidden frames and redirects.
import asyncio
import re
from urllib.parse import urljoin, urlsplit

import httpx
import tldextract
from bs4 import BeautifulSoup

from core.context import assert_public
from core.models import Finding, ModuleResult

SOURCE = "page"
MAX_REDIRECTS = 5
MAX_BYTES = 500 * 1024
REQUEST_TIMEOUT = 6
TOTAL_TIMEOUT = 8                      # whole module, so the orchestrator limit (10 s) is never hit
HEADERS = {"User-Agent": "TrustLensScanner/1.0 (security research; never runs scripts)",
           "Accept": "text/html,application/xhtml+xml"}

POINTS = {"REDIRECT_TO_OTHER_DOMAIN": 20, "LONG_REDIRECT_CHAIN": 10, "LOGIN_FORM": 10,
          "FORM_SENDS_ELSEWHERE": 25, "BRAND_ON_WRONG_SITE": 25, "HIDDEN_FRAME": 10,
          "PAGE_UNREACHABLE": 0}

_extract = tldextract.TLDExtract(suffix_list_urls=())      # offline-safe
_TRANSPORT = None                                          # tests may put a fake transport here


def registered_domain(url_or_host: str) -> str:
    host = urlsplit(url_or_host).hostname if "://" in url_or_host else url_or_host
    host = (host or "").lower()
    ext = _extract(host)
    return (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or host)


def _finding(fid: str, text: str, **data) -> Finding:
    return Finding(id=fid, source=SOURCE, description=text, points=POINTS[fid], data=data)


def _is_hidden_frame(tag) -> bool:
    style = (tag.get("style") or "").replace(" ", "").lower()
    size = [str(tag.get(a) or "").strip().lower().replace("px", "") for a in ("width", "height")]
    return (tag.has_attr("hidden")
            or "display:none" in style or "visibility:hidden" in style
            or bool(re.search(r"(width|height):0(px)?(;|$)", style))
            or any(s == "0" for s in size))


def parse_html(html: str, page_url: str, brands: list):
    """Look at the page text. Returns (list[Finding], facts). Never runs anything."""
    soup = BeautifulSoup(html or "", "html.parser")
    page_domain = registered_domain(page_url)
    findings, facts = [], {}

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    for t in soup(["script", "style", "noscript"]):        # text only, scripts are just removed
        t.decompose()
    text = soup.get_text(" ", strip=True)[:20000].lower()

    # --- forms with a password box
    pw_forms = [f for f in soup.find_all("form")
                if f.find("input", attrs={"type": re.compile(r"^password$", re.I)})]
    if pw_forms:
        findings.append(_finding("LOGIN_FORM", "The page has a password box.", forms=len(pw_forms)))
        for f in pw_forms:
            action = (f.get("action") or "").strip()
            if not action or action.startswith(("#", "javascript:", "mailto:")):
                continue
            target = urljoin(page_url, action)
            if urlsplit(target).scheme in ("http", "https") and registered_domain(target) != page_domain:
                findings.append(_finding("FORM_SENDS_ELSEWHERE",
                                         "The password form sends data to a different website.",
                                         action=target))
                break

    # --- brand name on a site that is not the brand's
    title_l = title.lower()
    for b in brands or []:
        own = {registered_domain(d) for d in [b.get("canonical_domain", "")] + list(b.get("domains", [])) if d}
        if page_domain in own:
            continue
        for kw in b.get("keywords", []):
            pat = r"\b" + re.escape(kw.lower()) + r"\b"
            in_title = re.search(pat, title_l)
            in_text = re.search(pat, text) and bool(pw_forms)   # text mentions only count with a password box
            if in_title or in_text:
                findings.append(_finding("BRAND_ON_WRONG_SITE",
                                         f"The page uses the name {b.get('name', kw)} but is not that company's website.",
                                         brand=b.get("name", kw), domain=page_domain))
                break
        else:
            continue
        break

    # --- invisible frames
    iframes = soup.find_all("iframe")
    if any(_is_hidden_frame(i) for i in iframes):
        findings.append(_finding("HIDDEN_FRAME", "The page contains an invisible frame."))

    facts.update({"title": title[:120], "forms": len(soup.find_all("form")),
                  "password_forms": len(pw_forms), "iframes": len(iframes)})
    return findings, facts


async def _fetch_hop(url: str, verify: bool):
    """One request, redirects NOT followed. Returns (status, location, html_or_None, content_type)."""
    async with httpx.AsyncClient(follow_redirects=False, timeout=REQUEST_TIMEOUT, verify=verify,
                                 headers=HEADERS, transport=_TRANSPORT) as client:
        async with client.stream("GET", url) as resp:
            status = resp.status_code
            location = resp.headers.get("location")
            ctype = resp.headers.get("content-type", "").lower()
            if 300 <= status < 400 and location:
                return status, location, None, ctype
            if "text/html" not in ctype:
                return status, None, None, ctype
            data = b""
            async for chunk in resp.aiter_bytes():
                data += chunk
                if len(data) >= MAX_BYTES:
                    data = data[:MAX_BYTES]
                    break
            return status, None, data.decode(resp.encoding or "utf-8", errors="replace"), ctype


async def _download(start_url: str):
    """Follow up to 5 redirects by hand, checking every hop. Returns (hops, html, note)."""
    hops, seen, url, tls_failed = [], set(), start_url, False
    for _ in range(MAX_REDIRECTS + 1):
        try:
            await asyncio.to_thread(assert_public, url)
        except ValueError as e:
            hops.append({"url": url, "status": None, "blocked": True})
            return hops, None, f"A redirect pointed to a blocked address ({e}), so it was not followed.", tls_failed
        if url in seen:
            return hops, None, "The redirects go in a circle.", tls_failed
        seen.add(url)
        try:
            try:
                status, location, html, ctype = await _fetch_hop(url, verify=True)
            except httpx.ConnectError as e:
                if "CERTIFICATE" not in str(e).upper() and "SSL" not in str(e).upper():
                    raise
                tls_failed = True                          # bad certificate: still read the page text
                status, location, html, ctype = await _fetch_hop(url, verify=False)
        except (httpx.HTTPError, OSError) as e:
            hops.append({"url": url, "status": None})
            return hops, None, f"The page could not be downloaded ({type(e).__name__}).", tls_failed
        hops.append({"url": url, "status": status})
        if location:
            url = urljoin(url, location)
            continue
        return hops, html, None, tls_failed
    return hops, None, "Too many redirects.", tls_failed


async def run(ctx) -> ModuleResult:
    try:
        try:
            hops, html, note, tls_failed = await asyncio.wait_for(_download(ctx.url), TOTAL_TIMEOUT)
        except asyncio.TimeoutError:
            hops, html, note, tls_failed = [], None, "The page took too long to download.", False

        findings = []
        final_url = hops[-1]["url"] if hops else ctx.url
        ctx.final_url = final_url
        facts = {"redirects": hops, "final_url": final_url, "tls_verify_failed": tls_failed}

        redirects = sum(1 for h in hops[:-1])                 # every hop except the last was a redirect
        if hops and not hops[-1].get("blocked") and registered_domain(final_url) != registered_domain(ctx.url):
            findings.append(_finding("REDIRECT_TO_OTHER_DOMAIN", "The link ends on a different website.",
                                     start=ctx.url, end=final_url))
        if redirects >= 3:
            findings.append(_finding("LONG_REDIRECT_CHAIN", f"The link passes through {redirects} redirects.",
                                     redirects=redirects))
        if note:
            findings.append(_finding("PAGE_UNREACHABLE", note))
        if html is not None:
            f2, facts2 = parse_html(html, final_url, ctx.brands)
            findings += f2
            facts.update(facts2)
        return ModuleResult(module=SOURCE, status="ok", findings=findings, facts=facts)
    except Exception as e:                                    # never raise
        return ModuleResult(module=SOURCE, status="failed", error=repr(e)[:200])


if __name__ == "__main__":
    from core.context import build_context

    brands = [{"name": "PayPal", "canonical_domain": "paypal.com", "keywords": ["paypal"]}]

    # 1. the guide's test
    html = ('<html><title>PayPal Login</title>'
            '<form action="http://evil.example.net/steal"><input type="password"></form></html>')
    f, facts = parse_html(html, "http://paypa1-login.example.org/", brands)
    ids = {x.id for x in f}
    print("evil page:", sorted(ids))
    ok1 = {"LOGIN_FORM", "FORM_SENDS_ELSEWHERE", "BRAND_ON_WRONG_SITE"} <= ids

    # 2. no false alarms
    clean = parse_html('<html><title>Cooking blog</title><p>I paid with PayPal today.</p></html>',
                       "http://blog.example.org/", brands)[0]
    real = parse_html(html.replace("http://evil.example.net/steal", "/login"),
                      "https://www.paypal.com/signin", brands)[0]
    hidden = parse_html('<iframe src="http://x.example/" width="0" height="0"></iframe>',
                        "http://a.example.org/", brands)[0]
    ok2 = (not clean and {x.id for x in real} == {"LOGIN_FORM"}
           and {x.id for x in hidden} == {"HIDDEN_FRAME"})
    print("no false alarms:", "OK" if ok2 else "WRONG", [x.id for x in clean], [x.id for x in real])

    # 3. redirect chain with a fake network (no internet needed)
    import core.context as _c
    pages = {"http://a.example.com/": (302, {"location": "http://b.example.net/"}, ""),
             "http://b.example.net/": (301, {"location": "http://c.example.org/x"}, ""),
             "http://c.example.org/x": (302, {"location": "http://d.example.io/login"}, ""),
             "http://d.example.io/login": (200, {"content-type": "text/html"},
                                           '<form><input type="password"></form>')}

    def handler(request):
        code, headers, body = pages[str(request.url)]
        return httpx.Response(code, headers=headers, text=body)

    real_assert, _TRANSPORT = assert_public, httpx.MockTransport(handler)
    globals()["assert_public"] = lambda u: None
    ctx = build_context("http://a.example.com/")
    res = asyncio.run(run(ctx))
    ids3 = {x.id for x in res.findings}
    print("chain:", sorted(ids3), "final =", ctx.final_url)
    ok3 = {"REDIRECT_TO_OTHER_DOMAIN", "LONG_REDIRECT_CHAIN", "LOGIN_FORM"} <= ids3 and \
        ctx.final_url == "http://d.example.io/login"

    # 4. a redirect to a private address must be blocked (real assert_public)
    globals()["assert_public"] = real_assert
    pages["http://a.example.com/"] = (302, {"location": "http://127.0.0.1/admin"}, "")
    globals()["assert_public"] = lambda u: real_assert(u) if "127.0.0.1" in u else None
    res4 = asyncio.run(run(build_context("http://a.example.com/")))
    ok4 = res4.status == "ok" and "PAGE_UNREACHABLE" in {x.id for x in res4.findings}
    print("private redirect blocked:", "OK" if ok4 else "WRONG")

    # 5. real internet (optional)
    globals()["assert_public"] = real_assert
    _TRANSPORT = None
    live = asyncio.run(run(build_context("http://example.com")))
    print("live example.com:", live.status, [x.id for x in live.findings], live.facts.get("title"))

    print("PASS" if ok1 and ok2 and ok3 and ok4 else "FAIL")