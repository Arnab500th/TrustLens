# backend/providers/whois_provider.py
# Retrieves domain registration age and registrar. Never raises.
from datetime import datetime, timezone
import whois


def lookup(domain: str) -> dict:
    """Return registration age and metadata for a registered domain."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if not creation_date:
            return {"available": False, "reason": "no_creation_date"}

        if creation_date.tzinfo is not None:
            now = datetime.now(creation_date.tzinfo)
        else:
            now = datetime.now()

        age_days = int((now - creation_date).total_seconds() / 86400)
        registrar = w.registrar if isinstance(w.registrar, str) else (w.registrar[0] if w.registrar else None)

        return {
            "available": True,
            "created": creation_date.strftime("%Y-%m-%d"),
            "age_days": max(0, age_days),
            "registrar": registrar,
            "nameservers": list(w.name_servers or [])
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:100]}


if __name__ == "__main__":
    result = lookup("google.com")
    print("google.com whois:", result)
    if result.get("available"):
        print("PASS" if result.get("age_days", 0) > 365 else "FAIL")
    else:
        print("SKIPPED (network/whois unavailable):", result.get("reason"))

