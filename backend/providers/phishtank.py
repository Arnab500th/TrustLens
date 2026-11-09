# backend/providers/phishtank.py
# Query PhishTank API or mock fallback for verified phishing URLs.
import base64
import os
import httpx


async def check(url: str, timeout: float = 4.0) -> dict:
    """Check if a URL is in the PhishTank community database."""
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    app_key = os.getenv("PHISHTANK_APP_KEY")

    data = {
        "url": base64.b64encode(url.encode("utf-8")).decode("ascii"),
        "format": "json"
    }
    if app_key:
        data["app_key"] = app_key

    headers = {"User-Agent": "phishtank/trustlens-hackathon"}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, data=data, headers=headers)
            if resp.status_code == 200:
                body = resp.json()
                results = body.get("results", {})
                in_db = results.get("in_database") in (True, "y", "true")
                verified = results.get("verified") in (True, "y", "true")
                valid = results.get("valid") in (True, "y", "true")

                return {
                    "available": True,
                    "in_database": in_db,
                    "verified": verified,
                    "valid": valid,
                    "detail_url": results.get("phish_detail_page")
                }
            elif resp.status_code == 509:
                return {"available": False, "reason": "rate_limited"}
            else:
                return {"available": False, "reason": f"http_{resp.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)[:100]}


if __name__ == "__main__":
    import asyncio
    res = asyncio.run(check("http://example.com/"))
    print("PhishTank check:", res)
    print("PASS" if "available" in res else "FAIL")

