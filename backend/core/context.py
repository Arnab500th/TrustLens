# backend/core/context.py
# Cleans a link, blocks dangerous addresses, builds the ScanContext.
# page.py and headers.py import assert_public and call it before every request.
import ipaddress
import json
import os
import socket
import uuid
from urllib.parse import urlsplit, urlunsplit

import tldextract

from core.models import ScanContext

BRANDS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "data", "brands.json")

# Offline-safe: use the suffix list that ships with tldextract, never download one.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def normalize_url(raw: str) -> str:
    """Trim spaces, add https:// if missing, lowercase scheme and host, drop #fragment."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty link")
    if "://" not in raw:
        raw = "https://" + raw.lstrip("/")
    parts = urlsplit(raw)
    # lowercase only the host part; keep any user@ part so url.py can still see the @ trick
    userinfo, at, hostport = parts.netloc.rpartition("@")
    netloc = userinfo + at + hostport.lower()
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def _bad_ip(ip) -> bool:
    if getattr(ip, "ipv4_mapped", None):          # ::ffff:127.0.0.1 style
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified or not ip.is_global)


def assert_public(url: str) -> None:
    """Raise ValueError if the link is not http/https or points to a private address."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http and https links are allowed")
    host = parts.hostname
    if not host:
        raise ValueError("Link has no host")

    # Check if host is an explicit IP address
    try:
        ip = ipaddress.ip_address(host)
        if _bad_ip(ip):
            raise ValueError("Link points to a private or reserved address")
        return
    except ValueError:
        pass

    # Check loopback hostnames
    if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback", "local"):
        raise ValueError("Link points to a private or reserved address")

    # If host resolves, ensure it does not resolve to an internal/private IP (SSRF defense)
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
        for info in infos:
            addr = info[4][0].split("%")[0]           # drop IPv6 zone id
            if _bad_ip(ipaddress.ip_address(addr)):
                raise ValueError("Link points to a private or reserved address")
    except (socket.gaierror, UnicodeError):
        # Host could not be resolved in DNS. Phishing sites and test domains frequently
        # lack active DNS records; allow them through so domain.py flags NO_DNS_RECORDS.
        pass


def _load_brands() -> list:
    try:
        with open(BRANDS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def build_context(url: str, brands=None) -> ScanContext:
    """Build the ScanContext every check receives. Does not touch the network."""
    url = normalize_url(url)
    host = urlsplit(url).hostname or ""
    ext = _extract(host)
    registered = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    return ScanContext(
        scan_id=uuid.uuid4().hex[:8],
        url=url,
        host=host,
        registered_domain=registered or host,
        brands=_load_brands() if brands is None else brands,
    )


if __name__ == "__main__":
    ctx = build_context("example.com")
    print(ctx.url, ctx.host, ctx.registered_domain)
    ok1 = ctx.url.startswith("https://") and ctx.host == "example.com"
    try:
        assert_public("http://127.0.0.1/admin")
        ok2 = False
    except ValueError:
        ok2 = True
    print("PASS" if ok1 and ok2 else "FAIL")

    # extra offline checks
    ok3 = (normalize_url("  HTTP://Evil.COM/Path#x ") == "http://evil.com/Path"
           and normalize_url("https://paypal.com@Evil.com").endswith("@evil.com/")
           and build_context("http://a.b.example.co.in/x").registered_domain == "example.co.in")
    blocked = ["http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.169.254/",
               "http://localhost/", "ftp://example.com/", "http://[::1]/"]
    ok4 = True
    for b in blocked:
        try:
            assert_public(b)
            ok4 = False
            print("NOT BLOCKED:", b)
        except ValueError:
            pass
    print("PASS (extra)" if ok3 and ok4 else "FAIL (extra)")