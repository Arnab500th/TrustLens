import ipaddress
from urllib.parse import urlparse

from rapidfuzz import fuzz

# We reuse the functions from Url_Analysis.py (keep it in the same folder)
from Url_Analysis import analyzation, normalize


# ................
# |   Settings   |
# ................

BRANDS = [
    # Big tech and social
    "google.com", "microsoft.com", "apple.com", "amazon.com", "amazon.in",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "twitter.com", "netflix.com", "dropbox.com", "github.com", "adobe.com",
    "spotify.com", "ebay.com", "icloud.com", "office.com", "outlook.com",
    "telegram.org", "discord.com", "yahoo.com", "snapchat.com", "tiktok.com",
    "reddit.com", "zoom.us",

    # Payments and banks
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "americanexpress.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "hsbc.com", "coinbase.com", "binance.com",

    # India
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "paytm.com", "phonepe.com", "flipkart.com", "irctc.co.in",

    # Shipping (often used in parcel scams)
    "dhl.com", "fedex.com", "ups.com", "usps.com",
] #official sites to protect

LOOKALIKE_MAP = {"0": "o", "1": "l", "3": "e", "5": "s"}


# ..........................
# |   1. Lookalike check   |
# ..........................

def check_lookalike(domain: str) -> list[dict]:
    findings = []

    # swap look-alike digits to letters (paypa1.com -> paypal.com)
    cleaned = domain.lower()
    for digit, letter in LOOKALIKE_MAP.items():
        cleaned = cleaned.replace(digit, letter)

    for brand in BRANDS:
        if domain.lower() == brand:
            continue  # this is the real website, so skip it

        score = fuzz.ratio(cleaned, brand)   # 0 to 100
        if score >= 80:                      # high but not perfect = suspicious
            findings.append({
                "id": "LOOKALIKE_BRAND",
                "source": "phishing",
                "description": f"Domain resembles {brand}",
                "points": 30,
            })

    return findings


# ..........................
# |   2. Structure check   |
# ..........................

def check_structure(url: str, parts: dict) -> list[dict]:
    findings = []
    host = urlparse(url).hostname or ""

    # IP address as host
    try:
        ipaddress.ip_address(host)
        findings.append({"id": "IP_AS_HOST", "source": "phishing",
                         "description": "URL uses an IP address as host", "points": 25})
    except ValueError:
        pass  # not an IP address, which is good

    # '@' in the URL
    if "@" in url:
        findings.append({"id": "AT_SYMBOL", "source": "phishing",
                         "description": "URL contains an @ symbol", "points": 20})

    # very long URL
    if len(url) > 75:
        findings.append({"id": "LONG_URL", "source": "phishing",
                         "description": "URL is very long", "points": 10})

    # many subdomains (blog.shop.login.example.com has 3)
    subdomain = parts["Subdomain"]
    if subdomain != "" and len(subdomain.split(".")) > 3:
        findings.append({"id": "MANY_SUBDOMAINS", "source": "phishing",
                         "description": "URL has many subdomains", "points": 15})

    # punycode
    if "xn--" in host:
        findings.append({"id": "PUNYCODE", "source": "phishing",
                         "description": "Domain uses punycode (xn--)", "points": 25})

    return findings


# ..................
# |   3. Age check |
# ..................

def check_age(age_days: int | None) -> list[dict]:
    if age_days is not None and age_days < 30:
        return [{"id": "NEW_DOMAIN", "source": "phishing",
                 "description": f"Domain registered only {age_days} day(s) ago",
                 "points": 25}]
    return []


# ..................
# |   4. DNS check |
# ..................

def check_dns(dns_info: dict) -> list[dict]:
    findings = []

    # get_DNS_info gives a list when records exist, or a text message when they don't
    if not isinstance(dns_info["A"], list):
        findings.append({"id": "NO_A_RECORD", "source": "phishing",
                         "description": "Domain has no A record", "points": 20})

    if not isinstance(dns_info["NS"], list):
        findings.append({"id": "NO_NS_RECORD", "source": "phishing",
                         "description": "Domain has no NS records", "points": 10})

    return findings


# ......................
# |   5. Redirect check |
# ......................

def check_redirect_chain(redirects: list, parts: dict) -> list[dict]:
    findings = []

    # each item looks like "301:https://site.com", so keep only those
    urls = []
    for item in redirects:
        if item.startswith("http"):
            urls.append(item)

    if len(urls) == 0:
        return findings

    hops = len(urls) - 1   # the last url is the final page

    if hops > 2:
        findings.append({"id": "MANY_REDIRECTS", "source": "phishing",
                         "description": f"URL redirects {hops} times", "points": 10})

    # does the final page belong to a different domain?
    final = normalize(urls[-1])
    if hops > 0 and (final["Domain"], final["Suffix"]) != (parts["Domain"], parts["Suffix"]):
        findings.append({"id": "REDIRECT_OFF_DOMAIN", "source": "phishing",
                         "description": "URL redirects to a different domain", "points": 20})

    return findings


# ..................................
# |   Combine everything           |
# ..................................

def phishing_indicators(url_info: dict) -> list[dict]:
    url = url_info["Url"]
    parts = url_info["parts"]
    domain = parts["Domain"] + "." + parts["Suffix"]

    age = url_info["Age"]                       # a dict, or None
    age_days = age["Days"] if age else None

    findings = []
    findings += check_lookalike(domain)
    findings += check_structure(url, parts)
    findings += check_age(age_days)
    findings += check_dns(url_info["DNS-Info"])
    findings += check_redirect_chain(url_info["redirects"], parts)

    if len(findings) == 0:
        findings.append({
            "id": "NO_INDICATORS",
            "source": "phishing",
            "description": "No phishing indicators found",
            "points": 0,
        })
    return findings

print(phishing_indicators(analyzation("https://blog.linksflys.com/h11pBlfN")))
