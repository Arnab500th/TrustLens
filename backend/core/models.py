from pydantic import BaseModel, Field
from typing import Literal, Optional


class Finding(BaseModel):
    id: str                      # short code in CAPITALS, from the master list
    source: str                  # which check found it: url, domain, certificate ...
    description: str             # plain English, shown to the user
    points: int = 0              # how risky this sign is
    data: dict = Field(default_factory=dict)   # optional extra evidence


class ModuleResult(BaseModel):   # what every check returns
    module: str                  # "url", "domain", "certificate", "headers", "reputation", "page"
    status: Literal["ok", "failed", "skipped"] = "ok"
    findings: list[Finding] = Field(default_factory=list)
    facts: dict = Field(default_factory=dict)   # raw facts, e.g. {"age_days": 9}
    error: Optional[str] = None
    duration_ms: int = 0


class ScanContext(BaseModel):    # what every check receives
    scan_id: str
    url: str                     # cleaned link, e.g. "https://example.com/"
    host: str                    # "example.com"
    registered_domain: str       # "example.com" (from tldextract)
    final_url: Optional[str] = None   # set by page.py after redirects
    brands: list[dict] = Field(default_factory=list)  # from data/brands.json


if __name__ == "__main__":
    f = Finding(id="NEW_DOMAIN", source="domain", description="Domain is 9 days old", points=20)
    r = ModuleResult(module="domain", findings=[f], facts={"age_days": 9})
    print(r.model_dump_json(indent=2))
    print("PASS" if r.findings[0].points == 20 and r.status == "ok" else "FAIL")
