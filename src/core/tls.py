"""TLS certificate helpers for the HTTPS web UI and MCP listener."""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Tuple

from .logging import get_logger

logger = get_logger("sami.core.tls")

DEFAULT_CERT_DIR = Path("certs")
DEFAULT_CERT_PATH = DEFAULT_CERT_DIR / "server.crt"
DEFAULT_KEY_PATH = DEFAULT_CERT_DIR / "server.key"


def ensure_tls_certs(
    cert_path: str | Path = DEFAULT_CERT_PATH,
    key_path: str | Path = DEFAULT_KEY_PATH,
    extra_hosts: Iterable[str] | None = None,
) -> Tuple[str, str]:
    """
    Return paths to a TLS cert/key pair, generating a self-signed cert if needed.

    Browsers will warn on the generated certificate until you replace it with
    one from a trusted CA (or add this cert to the local trust store).
    """
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)

    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hostname = socket.gethostname() or "localhost"
    names = {"localhost", "sami-gpt", hostname}
    ips = {"127.0.0.1", "::1"}
    for host in extra_hosts or []:
        if not host:
            continue
        try:
            ips.add(str(ipaddress.ip_address(host)))
        except ValueError:
            if host not in ("0.0.0.0", "::"):
                names.add(host)

    san: List[x509.GeneralName] = [x509.DNSName(name) for name in sorted(names)]
    for ip in sorted(ips):
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SamiGPT"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SamiGPT"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_file.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.chmod(0o600)
    cert_file.chmod(0o644)
    logger.warning(
        "Generated self-signed TLS certificate at %s (browsers will show a warning until you trust it or replace it)",
        cert_file,
    )
    return str(cert_file), str(key_file)


def client_ssl_context(cert_path: str | Path = DEFAULT_CERT_PATH):
    """
    Build a client SSL context that trusts our self-signed server certificate.

    The generated cert is a leaf (`ca=False`), so OpenSSL rejects it as a trust
    anchor unless partial chains are allowed. Without that flag, callers see
    "unable to get local issuer certificate" and fall back to no verification.
    Returns False when the certificate is missing, matching httpx's `verify`.
    """
    import ssl

    cert_file = Path(cert_path)
    if not cert_file.exists():
        logger.warning("TLS certificate %s not found; client verification disabled", cert_file)
        return False

    try:
        context = ssl.create_default_context(cafile=str(cert_file))
    except Exception as e:
        logger.warning("Could not load %s as a trust anchor: %s", cert_file, e)
        return False

    partial_chain = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", None)
    if partial_chain is not None:
        context.verify_flags |= partial_chain
    return context


def uvicorn_ssl_kwargs(
    cert_path: str | Path = DEFAULT_CERT_PATH,
    key_path: str | Path = DEFAULT_KEY_PATH,
) -> dict:
    """Keyword arguments to pass to uvicorn so it only serves HTTPS."""
    cert_file, key_file = ensure_tls_certs(cert_path, key_path)
    return {"ssl_certfile": cert_file, "ssl_keyfile": key_file}
