# backend/scripts/smoke.py   run from the backend folder:  python -m scripts.smoke
# Runs three links through the whole scanner and prints label and score for each.
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import scan_url

LINKS = [
    "https://www.wikipedia.org/",
    "https://expired.badssl.com/",
    "http://paypa1-secure-login.example-test.xyz/",
]
NEEDED = {"scan_id", "url", "host", "checked_at", "score", "label", "coverage", "findings",
          "facts", "checks", "unavailable", "explanation", "recommendations"}


async def main():
    good = True
    done = 0
    stubbed = set()
    for link in LINKS:
        try:
            res = await scan_url(link)
        except ValueError as e:
            print(f"{link}\n   BLOCKED or unresolved: {e}")
            continue          # a dead test domain is not a code failure
        except Exception as e:
            print(f"{link}\n   CRASH: {e!r}")
            good = False
            continue
        done += 1
        missing = NEEDED - set(res)
        if missing:
            good = False
        top = res["findings"][0]["id"] if res["findings"] else "-"
        ok = sum(1 for c in res["checks"] if c["status"] == "ok")
        print(f"{link}\n   {res['label']}  score={res['score']}  top={top}  checks_ok={ok}/{len(res['checks'])}"
              + (f"  MISSING {missing}" if missing else ""))
        stubbed |= {c["module"] for c in res["checks"] if c["status"] == "skipped"}
    if stubbed:
        print("modules not installed yet:", sorted(stubbed))
    return None if done == 0 else good


if __name__ == "__main__":
    outcome = asyncio.run(main())
    if outcome is None:
        print("SKIPPED: no link could be scanned (check your internet connection)")
    else:
        print("PASS" if outcome else "FAIL")