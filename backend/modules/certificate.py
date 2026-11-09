# backend/modules/certificate.py
# SSL/TLS certificate validation and cryptographic weakness detection (eMudhra incident angle).
import asyncio
from datetime import datetime, timezone
import hashlib
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from core.models import Finding, ModuleResult, ScanContext


def _match_hostname(pattern: str, host: str) -> bool:
    """Check if host matches pattern (including wildcard *.example.com)."""
    pattern = pattern.lower()
    host = host.lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
            return True
    return False


def findings_from_cert(info: dict, host: str) -> list[Finding]:
    """Pure analysis of extracted certificate properties."""
    findings = []
    if info.get("error") == "no_https":
        return [Finding(
            id="NO_HTTPS",
            source="certificate",
            description="Website does not provide HTTPS / port 443 connection",
            points=20
        )]

    days_left = info.get("days_left")
    if days_left is not None and days_left < 0:
        findings.append(Finding(
            id="CERT_EXPIRED",
            source="certificate",
            description=f"TLS certificate expired {abs(days_left)} days ago",
            points=25,
            data={"days_left": days_left}
        ))

    # SAN match check
    sans = info.get("san", [])
    if sans and not any(_match_hostname(pattern, host) for pattern in sans):
        findings.append(Finding(
            id="CERT_NAME_MISMATCH",
            source="certificate",
            description=f"Certificate common names {sans[:3]} do not match visited host '{host}'",
            points=25,
            data={"san": sans[:5], "host": host}
        ))

    # Self-signed
    issuer = info.get("issuer")
    subject = info.get("subject")
    is_self_signed = issuer and subject and (issuer == subject)
    if is_self_signed:
        findings.append(Finding(
            id="CERT_SELF_SIGNED",
            source="certificate",
            description="Certificate is self-signed and not issued by a trusted Certificate Authority",
            points=25
        ))

    # Untrusted root
    trust_err = info.get("trust_error")
    if trust_err and not is_self_signed and (days_left is None or days_left >= 0):
        findings.append(Finding(
            id="CERT_UNTRUSTED",
            source="certificate",
            description=f"Certificate chain trust validation failed: {trust_err}",
            points=25,
            data={"error": trust_err}
        ))

    # Age of certificate
    age_days = info.get("age_days")
    if age_days is not None and age_days < 7:
        findings.append(Finding(
            id="CERT_NEW",
            source="certificate",
            description=f"Certificate was issued only {age_days} days ago (common in temporary phishing infrastructure)",
            points=20,
            data={"age_days": age_days}
        ))

    # Weak key (Key check addressing the eMudhra incident)
    k_type = info.get("key_type")
    k_size = info.get("key_size")
    if (k_type == "RSA" and k_size and k_size < 2048) or (k_type == "EC" and k_size and k_size < 256):
        findings.append(Finding(
            id="CERT_WEAK_KEY",
            source="certificate",
            description=f"Certificate uses weak cryptographic key ({k_type} {k_size}-bit, vulnerable to forgery)",
            points=30,
            data={"key_type": k_type, "key_size": k_size}
        ))

    # Weak signature hash
    sig_hash = (info.get("sig_hash") or "").lower()
    if sig_hash in ("sha1", "md5"):
        findings.append(Finding(
            id="CERT_WEAK_SIGNATURE",
            source="certificate",
            description=f"Certificate uses cryptographically broken signature algorithm ({sig_hash})",
            points=25,
            data={"algorithm": sig_hash}
        ))

    # Deprecated TLS version
    tls_ver = info.get("tls_version")
    if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(Finding(
            id="TLS_OLD_VERSION",
            source="certificate",
            description=f"Server negotiates outdated and insecure protocol {tls_ver}",
            points=20,
            data={"tls_version": tls_ver}
        ))

    return findings


def fetch_certificate(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Connect to host, verify trust, then extract certificate parameters."""
    trust_error = None
    cert_der = None
    tls_version = None

    # Step 1: verify trust with default store
    try:
        ctx_ver = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx_ver.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        trust_error = e.verify_message or str(e)
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
        return {"error": "no_https"}

    # Step 2: If verification failed, connect without verification to read cert details
    if not cert_der:
        try:
            ctx_nover = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_nover.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
        except Exception:
            return {"error": "no_https"}

    if not cert_der:
        return {"error": "no_https"}

    try:
        cert = x509.load_der_x509_certificate(cert_der)
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        days_left = int((not_after - now).total_seconds() / 86400)
        age_days = int((now - not_before).total_seconds() / 86400)

        # Subject and Issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()

        # Subject Alternative Names
        san = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        # Public key type & size
        pubkey = cert.public_key()
        key_type = "UNKNOWN"
        key_size = 0
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_type = "EC"
            key_size = pubkey.key_size

        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        return {
            "issuer": issuer,
            "subject": subject,
            "san": san,
            "days_left": days_left,
            "age_days": max(0, age_days),
            "key_type": key_type,
            "key_size": key_size,
            "sig_hash": sig_hash,
            "tls_version": tls_version,
            "trust_error": trust_error,
            "fingerprint": fingerprint
        }
    except Exception as e:
        return {"error": f"parse_error: {e}"}


async def run(ctx: ScanContext) -> ModuleResult:
    try:
        info = await asyncio.to_thread(fetch_certificate, ctx.host)
        if "error" in info and info["error"] != "no_https":
            return ModuleResult(module="certificate", status="failed", error=info["error"])

        findings = findings_from_cert(info, ctx.host)
        facts = {
            "issuer": info.get("issuer"),
            "days_left": info.get("days_left"),
            "fingerprint": info.get("fingerprint"),
            "tls_version": info.get("tls_version"),
            "key_type": info.get("key_type"),
            "key_size": info.get("key_size")
        }
        return ModuleResult(
            module="certificate",
            status="ok",
            findings=findings,
            facts=facts
        )
    except Exception as e:
        return ModuleResult(
            module="certificate",
            status="failed",
            error=str(e)[:200]
        )


if __name__ == "__main__":
    fake = {
        "days_left": -5, "san": ["example.com"], "issuer": "A", "subject": "B", "age_days": 400,
        "key_type": "RSA", "key_size": 2048, "sig_hash": "sha256", "tls_version": "TLSv1.3",
        "trust_error": None
    }
    offline = {f.id for f in findings_from_cert(fake, "example.com")}
    print("offline test:", offline)

    weak = {
        "days_left": 50, "san": ["bank.com"], "issuer": "CA", "subject": "bank.com", "age_days": 2,
        "key_type": "RSA", "key_size": 1024, "sig_hash": "sha1", "tls_version": "TLSv1.0",
        "trust_error": None
    }
    weak_findings = {f.id for f in findings_from_cert(weak, "bank.com")}
    print("weak cert test:", sorted(weak_findings))

    ok = (offline == {"CERT_EXPIRED"} and "CERT_WEAK_KEY" in weak_findings and
          "CERT_NEW" in weak_findings and "CERT_WEAK_SIGNATURE" in weak_findings and
          "TLS_OLD_VERSION" in weak_findings)
    print("PASS" if ok else "FAIL")

