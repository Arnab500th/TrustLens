# backend/modules/domain.py
# Domain age and DNS record validation.
import asyncio
import dns.resolver

from core.models import Finding, ModuleResult, ScanContext
from providers.whois_provider import lookup as whois_lookup


def findings_from_age(age_days: int | None) -> list[Finding]:
    """Pure helper converting domain age to risk findings."""
    if age_days is None:
        return []
    if age_days < 7:
        return [Finding(
            id="VERY_NEW_DOMAIN",
            source="domain",
            description=f"Domain registered only {age_days} days ago (critical phishing window)",
            points=25,
            data={"age_days": age_days}
        )]
    if age_days < 30:
        return [Finding(
            id="NEW_DOMAIN",
            source="domain",
            description=f"Domain registered recently ({age_days} days ago)",
            points=20,
            data={"age_days": age_days}
        )]
    return []


def resolve_dns(domain: str) -> tuple[list[str], bool]:
    """Resolve A and AAAA records for a domain."""
    ips = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, rtype)
            ips.extend([r.to_text() for r in answers])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass

    has_records = len(ips) > 0
    return ips, has_records


async def run(ctx: ScanContext) -> ModuleResult:
    findings = []
    facts = {"ips": [], "age_days": None, "registrar": None}

    try:
        # 1. DNS Resolution (threaded to avoid event loop blocking)
        ips, has_records = await asyncio.to_thread(resolve_dns, ctx.host)
        facts["ips"] = ips

        if not has_records:
            findings.append(Finding(
                id="NO_DNS_RECORDS",
                source="domain",
                description=f"Host '{ctx.host}' has no active DNS A/AAAA address records",
                points=20
            ))

        # 2. Domain age lookup via WHOIS
        whois_data = await asyncio.to_thread(whois_lookup, ctx.registered_domain)
        if whois_data.get("available"):
            age_days = whois_data.get("age_days")
            facts["age_days"] = age_days
            facts["registrar"] = whois_data.get("registrar")
            findings.extend(findings_from_age(age_days))
        else:
            facts["whois_error"] = whois_data.get("reason")

        return ModuleResult(
            module="domain",
            status="ok",
            findings=findings,
            facts=facts
        )
    except Exception as e:
        return ModuleResult(
            module="domain",
            status="failed",
            error=str(e)[:200],
            facts=facts
        )


if __name__ == "__main__":
    t1 = findings_from_age(3)
    t2 = findings_from_age(20)
    t3 = findings_from_age(900)
    t4 = findings_from_age(None)

    ok1 = (len(t1) == 1 and t1[0].id == "VERY_NEW_DOMAIN" and
           len(t2) == 1 and t2[0].id == "NEW_DOMAIN" and
           t3 == [] and t4 == [])

    print("findings_from_age test:", "PASS" if ok1 else "FAIL")

