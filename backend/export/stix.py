# backend/export/stix.py
# Exports scan findings into standard OASIS STIX 2.1 Threat Intelligence JSON format.
from datetime import datetime, timezone
import uuid


def generate_stix_bundle(scan_result: dict) -> dict:
    """Transform a TrustLens scan result into a valid STIX 2.1 bundle."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url = scan_result.get("url", "")
    host = scan_result.get("host", "")
    label = scan_result.get("label", "Unknown")
    score = scan_result.get("score", 0)
    findings = scan_result.get("findings", [])

    bundle_id = f"bundle--{uuid.uuid4()}"
    indicator_id = f"indicator--{uuid.uuid4()}"
    report_id = f"report--{uuid.uuid4()}"

    is_malicious = score >= 60 or label in ("High Risk", "Confirmed Malicious")
    indicator_types = ["malicious-activity", "phishing"] if is_malicious else ["anomalous-activity"]

    finding_summaries = "; ".join(f"{f.get('id')}: {f.get('description')}" for f in findings[:5])

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"TrustLens Detection: {host}",
        "description": f"Risk Level: {label} (Score {score}/100). Findings: {finding_summaries or 'None'}",
        "indicator_types": indicator_types,
        "pattern": f"[url:value = '{url}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now_iso,
        "confidence": int(scan_result.get("confidence", 0.8) * 100),
        "labels": ["trustlens", "phishing-detection", label.lower().replace(" ", "-")]
    }

    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"TrustLens Assessment Report for {host}",
        "description": scan_result.get("explanation", f"Automated 4-pillar security scan of {url}"),
        "published": now_iso,
        "report_types": ["threat-report"],
        "object_refs": [indicator_id],
        "custom_properties": {
            "x_trustlens_score": score,
            "x_trustlens_label": label,
            "x_trustlens_scan_id": scan_result.get("scan_id")
        }
    }

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": [indicator, report]
    }


if __name__ == "__main__":
    test_scan = {
        "scan_id": "test-123",
        "url": "http://paypa1-secure.xyz/login",
        "host": "paypa1-secure.xyz",
        "label": "High Risk",
        "score": 85,
        "confidence": 0.9,
        "findings": [{"id": "LOOKALIKE_BRAND", "description": "Mimics PayPal brand"}]
    }
    bundle = generate_stix_bundle(test_scan)
    print("STIX 2.1 Bundle type:", bundle["type"])
    print("Objects count:", len(bundle["objects"]))
    print("PASS" if bundle["type"] == "bundle" and len(bundle["objects"]) == 2 else "FAIL")

