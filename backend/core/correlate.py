# backend/core/correlate.py
# Correlates the current scan with past scan records to detect shared infrastructure
# and repeated malicious reports.
from core.models import Finding


def correlate(result_so_far: dict, past_scans: list) -> list[Finding]:
    """Inspects past scans for repeated reports or shared hosting infrastructure."""
    if not past_scans or not isinstance(past_scans, list):
        return []

    findings = []
    current_host = str(result_so_far.get("host") or "").lower()
    current_url = str(result_so_far.get("url") or "")

    facts = result_so_far.get("facts") or {}
    domain_facts = (facts.get("domain") or {}) if isinstance(facts, dict) else {}
    current_ips = set(domain_facts.get("ips") or [])

    # 1. Repeated report detection: Has this exact host or URL been flagged previously?
    prior_matches = [
        s for s in past_scans
        if isinstance(s, dict)
        and (str(s.get("host") or "").lower() == current_host or str(s.get("url") or "") == current_url)
        and (s.get("score") or 0) >= 50
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
            if not isinstance(s, dict):
                continue
            s_score = s.get("score") or 0
            s_host = str(s.get("host") or "")
            if s_score >= 60 and s_host.lower() != current_host:
                s_facts = s.get("facts") or {}
                s_domain = (s_facts.get("domain") or {}) if isinstance(s_facts, dict) else {}
                past_ips = set(s_domain.get("ips") or [])
                if current_ips & past_ips and s_host:
                    shared_bad_hosts.add(s_host)

        if shared_bad_hosts:
            sample_hosts = [h for h in list(shared_bad_hosts)[:3] if h]
            if sample_hosts:
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

