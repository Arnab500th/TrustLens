# backend/providers/urlhaus.py
# Query abuse.ch URLhaus malware and phishing distribution API.
import httpx


async def check(url: str, timeout: float = 4.0) -> dict:
    """Check if a URL is listed in URLhaus database."""
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, data={"url": url})
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok":
                    return {
                        "available": True,
                        "listed": True,
                        "threat": data.get("threat"),
                        "tags": data.get("tags") or [],
                        "urlhaus_reference": data.get("urlhaus_reference")
                    }
                elif status == "no_results":
                    return {"available": True, "listed": False}
                else:
                    return {"available": False, "reason": status}
            return {"available": False, "reason": f"http_{resp.status_code}"}
    except Exception as e:
        return {"available": False, "reason": str(e)[:100]}


if __name__ == "__main__":
    import asyncio
    res = asyncio.run(check("http://example.com/"))
    print("URLhaus check:", res)
    print("PASS" if "available" in res else "FAIL")

