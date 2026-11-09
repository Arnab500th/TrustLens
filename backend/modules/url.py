# backend/modules/url.py
# URL structural heuristics, statistical TLD scoring, and phonetic brand lookalike detection.
import ipaddress
import os
import re
from urllib.parse import urlparse

import jellyfish
import tldextract
from rapidfuzz import distance, fuzz

from core.models import Finding, ModuleResult, ScanContext

LOOKALIKE_MAP = {
    "0": "o", "1": "l", "3": "e", "5": "s",
    "@": "a", "$": "s", "rn": "m", "vv": "w"
}

# Empirical TLD abuse rate index (based on Spamhaus & APWG intelligence metrics)
# Maps abused/disposable TLDs to risk scores [0.0 - 1.0]
TLD_RISK_SCORES = {
    "tk": 0.95, "ml": 0.95, "ga": 0.95, "cf": 0.95, "gq": 0.95,
    "top": 0.90, "click": 0.85, "xyz": 0.70, "zip": 0.85, "mov": 0.80,
    "loan": 0.85, "men": 0.85, "work": 0.75, "country": 0.75,
    "icu": 0.85, "buzz": 0.80, "monster": 0.80, "cfd": 0.80, "sbs": 0.80,
    "rest": 0.75, "fit": 0.70, "casa": 0.70, "surf": 0.70, "link": 0.65
}

_extract = tldextract.TLDExtract(suffix_list_urls=())


def _clean_word(word: str) -> str:
    cleaned = word.lower().replace("-", "")
    for k, v in LOOKALIKE_MAP.items():
        cleaned = cleaned.replace(k, v)
    return cleaned


def analyze_url_string(url: str, brands: list[dict] = None) -> list[Finding]:
    """Pure offline analysis of URL structure and brand impersonation."""
    findings = []
    brands = brands or []

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    netloc = parsed.netloc

    ext = _extract(host)
    subdomain = ext.subdomain.lower()
    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    registered_domain = (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain).lower()

    # 1. IP address as host
    try:
        ipaddress.ip_address(host)
        findings.append(Finding(
            id="IP_AS_HOST",
            source="url",
            description="URL uses an IP address instead of a domain name",
            points=25,
            data={"host": host}
        ))
    except ValueError:
        pass

    # 2. @ symbol trick (e.g. https://google.com@evil.com)
    if "@" in netloc or "@" in url:
        findings.append(Finding(
            id="AT_SYMBOL_URL",
            source="url",
            description="URL contains an '@' symbol used to obscure the destination host",
            points=20
        ))

    # 3. Punycode / Internationalized domain homograph (xn--)
    if "xn--" in host:
        findings.append(Finding(
            id="HOMOGRAPH_DOMAIN",
            source="url",
            description="Domain uses punycode (xn--) which can spoof lookalike characters",
            points=25,
            data={"host": host}
        ))

    # 4. Too many subdomains (e.g. login.secure.bank.update.com)
    if subdomain and len(subdomain.split(".")) >= 3:
        findings.append(Finding(
            id="TOO_MANY_SUBDOMAINS",
            source="url",
            description=f"URL contains excessive subdomain levels ({subdomain})",
            points=15,
            data={"subdomain": subdomain}
        ))

    # 5. Very long URL
    if len(url) > 100:
        findings.append(Finding(
            id="LONG_URL",
            source="url",
            description=f"URL is unusually long ({len(url)} characters)",
            points=10,
            data={"length": len(url)}
        ))

    # 6. Statistical TLD risk scoring
    if suffix in TLD_RISK_SCORES:
        risk_weight = TLD_RISK_SCORES[suffix]
        pts = int(10 + round(15 * risk_weight))
        findings.append(Finding(
            id="SUSPICIOUS_TLD",
            source="url",
            description=f"Domain uses high-abuse TLD (.{suffix}) with statistical risk index {int(risk_weight * 100)}%",
            points=pts,
            data={"tld": suffix, "risk_weight": risk_weight}
        ))

    # 7. Brand lookalike & Phonetic NLP checks
    cleaned_domain = _clean_word(domain)
    meta_domain = jellyfish.metaphone(cleaned_domain)

    for b in brands:
        canonical = (b.get("canonical_domain") or "").lower()
        b_label = (b.get("label") or "").lower()
        keywords = [k.lower() for k in b.get("keywords", []) if len(k) >= 4]

        # Never flag the authentic legitimate domain
        if registered_domain == canonical or host == canonical or host.endswith("." + canonical):
            continue

        matched_lookalike = False

        # Keyword match inside cleaned domain
        for kw in keywords:
            if kw in cleaned_domain and len(cleaned_domain) != len(kw):
                findings.append(Finding(
                    id="LOOKALIKE_BRAND",
                    source="url",
                    description=f"Domain '{registered_domain}' mimics brand '{b.get('name', canonical)}'",
                    points=30,
                    data={"brand": b.get("name", canonical), "matched_keyword": kw}
                ))
                matched_lookalike = True
                break

        # Fuzzy distance & Phonetic match to brand label
        if not matched_lookalike and b_label and len(b_label) >= 4:
            dist = distance.Levenshtein.distance(cleaned_domain, b_label)
            # 1 edit distance for 5-8 chars, 2 edit distance for >= 9 chars
            if (len(b_label) <= 8 and dist == 1) or (len(b_label) > 8 and dist <= 2):
                findings.append(Finding(
                    id="LOOKALIKE_BRAND",
                    source="url",
                    description=f"Domain '{domain}' closely resembles brand label '{b_label}'",
                    points=30,
                    data={"brand": b.get("name", canonical), "edit_distance": dist}
                ))
                matched_lookalike = True

            # ML / Phonetic Similarity (Soundex / Metaphone & Jaro-Winkler)
            if not matched_lookalike:
                meta_brand = jellyfish.metaphone(b_label)
                jw_sim = jellyfish.jaro_winkler_similarity(cleaned_domain, b_label)
                # If phonetic metaphone matches or Jaro-Winkler similarity is exceptionally high (>= 0.88)
                if (meta_domain and meta_brand and meta_domain == meta_brand) or (jw_sim >= 0.88 and dist <= 3):
                    findings.append(Finding(
                        id="LOOKALIKE_BRAND",
                        source="url",
                        description=f"Domain '{domain}' sounds identical/similar to '{b_label}' (phonetic score {int(jw_sim * 100)}%)",
                        points=30,
                        data={"brand": b.get("name", canonical), "phonetic_metaphone": meta_domain, "similarity": round(jw_sim, 2)}
                    ))
                    matched_lookalike = True

        # Check brand keyword in subdomain on unrelated site (e.g. sbi.malicious-site.com)
        if not matched_lookalike and subdomain:
            for kw in keywords:
                if kw in subdomain:
                    findings.append(Finding(
                        id="BRAND_IN_SUBDOMAIN",
                        source="url",
                        description=f"Brand keyword '{kw}' placed inside subdomain of unrelated domain '{registered_domain}'",
                        points=25,
                        data={"brand": b.get("name", canonical), "subdomain": subdomain}
                    ))
                    break

    return findings


async def run(ctx: ScanContext) -> ModuleResult:
    try:
        findings = analyze_url_string(ctx.url, ctx.brands)
        ext = _extract(ctx.host)
        facts = {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "registered_domain": ctx.registered_domain,
            "url_length": len(ctx.url)
        }
        return ModuleResult(
            module="url",
            status="ok",
            findings=findings,
            facts=facts
        )
    except Exception as e:
        return ModuleResult(
            module="url",
            status="failed",
            error=str(e)[:200]
        )


if __name__ == "__main__":
    brands = [
        {"name": "PayPal", "canonical_domain": "paypal.com", "label": "paypal", "keywords": ["paypal"]},
        {"name": "SBI", "canonical_domain": "sbi.co.in", "label": "statebank", "keywords": ["onlinesbi", "statebank"]}
    ]

    def ids(u): return {f.id for f in analyze_url_string(u, brands)}

    a = ids("http://paypa1-login.com/")
    b = ids("http://192.168.1.1/login")
    c = ids("https://www.paypal.com/signin")
    d = ids("http://statebank.verify-acc.xyz/secure")

    print("paypa1-login.com        :", sorted(a))
    print("192.168.1.1/login       :", sorted(b))
    print("paypal.com (legit)      :", sorted(c))
    print("statebank.verify-acc.xyz:", sorted(d))

    ok = ("LOOKALIKE_BRAND" in a and "IP_AS_HOST" in b and not c and "SUSPICIOUS_TLD" in d and "BRAND_IN_SUBDOMAIN" in d)
    print("PASS" if ok else "FAIL")
