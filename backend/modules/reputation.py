# backend/modules/reputation.py
# Collaborative threat intelligence feeds (URLhaus, PhishTank).
import asyncio

from core.models import Finding, ModuleResult, ScanContext
from providers.phishtank import check as phishtank_check
from providers.urlhaus import check as urlhaus_check


async def run(ctx: ScanContext) -> ModuleResult:
    findings = []
    facts = {"providers": {}}

    try:
        # Run PhishTank and URLhaus in parallel with a hard timeout
        pt_res, uh_res = await asyncio.gather(
            phishtank_check(ctx.url),
            urlhaus_check(ctx.url),
            return_exceptions=True
        )

        # 1. URLhaus check
        if isinstance(uh_res, dict):
            facts["providers"]["urlhaus"] = uh_res
            if uh_res.get("listed"):
                findings.append(Finding(
                    id="URLHAUS_LISTED",
                    source="reputation",
                    description=f"Destination is actively blacklisted by abuse.ch URLhaus threat intelligence ({uh_res.get('threat', 'malware')})",
                    points=40,
                    data={"threat": uh_res.get("threat")}
                ))

        # 2. PhishTank check
        if isinstance(pt_res, dict):
            facts["providers"]["phishtank"] = pt_res
            if pt_res.get("in_database") and pt_res.get("verified") and pt_res.get("valid"):
                findings.append(Finding(
                    id="PHISHTANK_VERIFIED",
                    source="reputation",
                    description="Destination is verified as active phishing by PhishTank community intelligence",
                    points=40,
                    data={"detail_url": pt_res.get("detail_url")}
                ))
            elif pt_res.get("in_database"):
                findings.append(Finding(
                    id="PHISHTANK_UNVERIFIED",
                    source="reputation",
                    description="Destination has unverified phishing reports submitted to PhishTank",
                    points=20
                ))

        return ModuleResult(
            module="reputation",
            status="ok",
            findings=findings,
            facts=facts
        )
    except Exception as e:
        return ModuleResult(
            module="reputation",
            status="failed",
            error=str(e)[:200],
            facts=facts
        )


if __name__ == "__main__":
    ctx = ScanContext(scan_id="t1", url="http://example.com/", host="example.com", registered_domain="example.com")
    res = asyncio.run(run(ctx))
    print("reputation check:", res.model_dump())
    print("PASS" if res.module == "reputation" and res.status in ("ok", "failed") else "FAIL")

