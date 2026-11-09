# backend/core/correlate.py
# Correlates the current scan with past scan records to detect shared infrastructure
# and repeated malicious reports.
from core.models import Finding


def correlate(result_so_far: dict, past_scans: list) -> list[Finding]:
    """Inspects past scans for repeated reports or shared hosting infrastructure."""
    if not past_scans or not isinstance(past_scans, list):
        return []

    findings = []
    current_host = (result_so_far.get("host") or "").lower()
    current_url = result_so_far.get("url") or ""
    current_ips = set(result_so_far.get("facts", {}).get("domain", {}).get("ips", []))

    # 1. Repeated report detection: Has this exact host or URL been flagged previously?
    prior_matches = [
        s for s in past_scans
        if (s.get("host", "").lower() == current_host or s.get("url") == current_url)
        and s.get("score", 0) >= 50
    ]
    if len(prior_matches) >= 2:
        findings.append(Finding(
            id="REPEATED_REPORT",
            source="correlation",
            description=f"Host '{current_host}' has been repeatedly flagged across {len(prior_matches)} prior scans",
            points=15,
            data={"prior_scan_count": len(prior_matches)}
        ))

    # 2. Shared infrastructure: Does this host share IP addresses with known malicious hosts?
    if current_ips:
        shared_bad_hosts = set()
        for s in past_scans:
            if s.get("score", 0) >= 60 and s.get("host", "").lower() != current_host:
                past_ips = set(s.get("facts", {}).get("domain", {}).get("ips", []))
                if current_ips & past_ips:
                    shared_bad_hosts.add(s.get("host"))

        if shared_bad_hosts:
            sample_hosts = list(shared_bad_hosts)[:3]
            findings.append(Finding(
                id="SHARED_INFRASTRUCTURE",
                source="correlation",
                description=f"Host shares IP hosting infrastructure with known malicious domains ({', '.join(sample_hosts)})",
                points=20,
                data={"shared_hosts": sample_hosts, "shared_ips": list(current_ips)}
            ))

    return findings


if __name__ == "__main__":
    test_result = {
        "host": "evil-phish.top",
        "url": "http://evil-phish.top/login",
        "facts": {"domain": {"ips": ["1.2.3.4"]}}
    }
    past = [
        {"host": "evil-phish.top", "url": "http://evil-phish.top/login", "score": 80},
        {"host": "evil-phish.top", "url": "http://evil-phish.top/account", "score": 75},
        {"host": "another-phish.xyz", "score": 85, "facts": {"domain": {"ips": ["1.2.3.4"]}}}
    ]
    res = correlate(test_result, past)
    print("Correlate test findings:", [f.id for f in res])
    assert any(f.id == "REPEATED_REPORT" for f in res)
    assert any(f.id == "SHARED_INFRASTRUCTURE" for f in res)
    print("PASS")

