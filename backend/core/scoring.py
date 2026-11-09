# backend/core/scoring.py
# Adds up finding points, picks the risk label, lists checks that could not run.
# The points decide the label. AI never does.
from core.models import ModuleResult

# ---- Constants (change numbers here only) ----
SCORE_CAP = 100                  # total points never go above this
LOW_MAX = 30                     # 0 to 30   -> Low Risk
SUSPICIOUS_MAX = 60              # 31 to 60  -> Suspicious, above 60 -> High Risk
CONFIRMED_IDS = {"PHISHTANK_VERIFIED", "URLHAUS_LISTED"}   # trusted lists
CONFIRMED_MIN_SCORE = 90         # Confirmed Malicious scores at least this
DEFAULT_MIN_CHECKS = 3           # fewer ok checks than this -> Inconclusive
DEFAULT_EXPECTED = 6             # checks we normally run (for coverage)

LOW, SUSPICIOUS, HIGH = "Low Risk", "Suspicious", "High Risk"
CONFIRMED, INCONCLUSIVE = "Confirmed Malicious", "Inconclusive"

RECOMMENDATIONS = {
    LOW: [
        "No significant warning signs were found in the checks that ran.",
        "This does not prove the link or message is safe, so stay careful.",
        "Avoid entering passwords unless you reached the site yourself.",
    ],
    SUSPICIOUS: [
        "Do not enter passwords or card details on this site.",
        "Check the address carefully, or open the official site by typing it yourself.",
        "If the message came from someone you know, confirm with them another way.",
    ],
    HIGH: [
        "Do not open this link and do not enter any information.",
        "Do not reply to the message or call numbers it gives.",
        "Report it to your bank, workplace or the real company if it pretends to be one.",
    ],
    CONFIRMED: [
        "A trusted threat list reports this link as malicious. Do not open it.",
        "If you already entered a password, change it now and watch your accounts.",
        "Report the link to your bank or workplace.",
    ],
    INCONCLUSIVE: [
        "Too many checks could not run, so there is not enough information.",
        "Treat the link with care and try the scan again later.",
        "Do not enter passwords unless you are sure of the site.",
    ],
}


def recommendations_for(label: str) -> list:
    """2 or 3 plain sentences for each label. Never says safe."""
    return list(RECOMMENDATIONS.get(label, RECOMMENDATIONS[INCONCLUSIVE]))


def score_scan(results: list, min_checks: int = DEFAULT_MIN_CHECKS,
               expected: int = DEFAULT_EXPECTED) -> dict:
    # 1. collect findings, keep one per id (the one with the most points)
    by_id = {}
    for r in results:
        for f in r.findings:
            if f.id not in by_id or f.points > by_id[f.id].points:
                by_id[f.id] = f

    # 2. total points, capped
    score = min(SCORE_CAP, sum(f.points for f in by_id.values()))

    # 3. how many checks worked
    ok_count = sum(1 for r in results if r.status == "ok")

    # 4. pick the label
    if by_id.keys() & CONFIRMED_IDS:
        label = CONFIRMED
        score = max(score, CONFIRMED_MIN_SCORE)
    elif ok_count < min_checks:
        label = INCONCLUSIVE
    elif score <= LOW_MAX:
        label = LOW
    elif score <= SUSPICIOUS_MAX:
        label = SUSPICIOUS
    else:
        label = HIGH

    coverage = round(ok_count / expected, 2) if expected else 0.0
    findings = sorted((f.model_dump() for f in by_id.values()),
                      key=lambda d: d["points"], reverse=True)
    unavailable = [r.module for r in results if r.status in ("failed", "skipped")]
    return {"score": score, "label": label, "coverage": coverage,
            "findings": findings, "unavailable": unavailable}


if __name__ == "__main__":
    from core.models import ModuleResult, Finding

    def F(i, pts): return Finding(id=i, source="t", description=i, points=pts)

    def M(name, *fs): return ModuleResult(module=name, findings=list(fs))

    names = ("url", "domain", "certificate", "headers", "reputation", "page")

    clean = [M(n) for n in names]
    risky = [M("url", F("LOOKALIKE_BRAND", 30)), M("domain", F("NEW_DOMAIN", 20)),
             M("certificate", F("CERT_EXPIRED", 25)), M("headers"), M("reputation"), M("page")]
    bad = [M("reputation", F("PHISHTANK_VERIFIED", 40)), M("url"), M("domain")]
    thin = [M("url")]

    tests = [("clean", score_scan(clean)["label"], "Low Risk"),
             ("risky", score_scan(risky)["label"], "High Risk"),
             ("confirmed", score_scan(bad)["label"], "Confirmed Malicious"),
             ("thin", score_scan(thin)["label"], "Inconclusive")]
    for name, got, want in tests:
        print(name, "->", got, "PASS" if got == want else "FAIL (wanted " + want + ")")