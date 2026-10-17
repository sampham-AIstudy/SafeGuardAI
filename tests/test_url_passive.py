import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import ssl
import tempfile
import threading
import time
from unittest.mock import MagicMock
import pytest

from codebase.config import get_settings
from codebase.url_analysis.analyzer import UrlAnalyzer
from codebase.url_analysis.models import UrlFinding, UrlSignal
from codebase.url_analysis.passive import PassiveIntel, _is_valid_domain, _parse_iso_date
from codebase.url_analysis.resolver import (
    SafeRedirectResolver,
    probe_tls_certificate,
)


@pytest.fixture
def enable_network_settings(monkeypatch):
    """Enable network and offline=0 for passive intel test suite."""
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "0")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "1")
    settings = get_settings(refresh=True)
    monkeypatch.setattr(settings, "network_enabled", True)
    monkeypatch.setattr(settings, "offline", False)
    yield
    monkeypatch.setenv("SAFEGUARD_OFFLINE", "1")
    monkeypatch.setenv("SAFEGUARD_NETWORK", "off")
    get_settings(refresh=True)


# ============================================================================
# Helper: TLS Cert Generator using cryptography
# ============================================================================

def _generate_cert(
    common_name="localhost",
    san_list=None,
    expired=False,
    not_before_days_ago=10,
    validity_days=30,
):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SafeGuardAI Test Org"),
    ])

    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=60)
        not_after = now - timedelta(days=10)
    else:
        not_before = now - timedelta(days=not_before_days_ago)
        not_after = not_before + timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    names = []
    if san_list:
        for name in san_list:
            try:
                ip = ipaddress.ip_address(name)
                names.append(x509.IPAddress(ip))
            except ValueError:
                names.append(x509.DNSName(name))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)

    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def _generate_ca_and_cert(leaf_cn="localhost", san_list=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Org"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=100))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, leaf_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Leaf Org"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
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
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    names = []
    if san_list:
        for name in san_list:
            try:
                ip = ipaddress.ip_address(name)
                names.append(x509.IPAddress(ip))
            except ValueError:
                names.append(x509.DNSName(name))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)

    leaf_cert = builder.sign(ca_key, hashes.SHA256())
    return ca_cert, leaf_cert, leaf_key


def _start_loopback_tls_server(cert, key):
    from cryptography.hazmat.primitives import serialization

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_path = cf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as kf:
        kf.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        key_path = kf.name

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]

    running = [True]

    def accept_loop():
        sock.settimeout(0.2)
        while running[0]:
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                tls_client = ctx.wrap_socket(client, server_side=True)
                time.sleep(0.05)
                tls_client.close()
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass

    th = threading.Thread(target=accept_loop, daemon=True)
    th.start()

    def cleanup():
        running[0] = False
        th.join(timeout=1.0)
        try:
            sock.close()
        except Exception:
            pass
        for path in (cert_path, key_path):
            try:
                os.remove(path)
            except Exception:
                pass

    return port, cert_path, cleanup


# ============================================================================
# 1. RDAP DOMAIN AGE TESTS
# ============================================================================

def test_rdap_registration_event_parsing(enable_network_settings):
    """RDAP valid registration event calculates age_days correctly."""
    now = datetime.now(timezone.utc)
    reg_date = now - timedelta(days=20)
    rdap_payload = {
        "events": [
            {"eventAction": "last changed", "eventDate": now.isoformat()},
            {"eventAction": "registration", "eventDate": reg_date.isoformat()},
        ]
    }

    def mock_fetch(url, **kwargs):
        assert "rdap.org/domain/example.vn" in url
        return 200, {"content-type": "application/json"}, json.dumps(rdap_payload).encode()

    intel = PassiveIntel(fetch=mock_fetch)
    res = intel.domain_age("example.vn")
    assert res is not None
    assert res["age_days"] == 20
    assert "created" in res


def test_rdap_missing_registration_event(enable_network_settings):
    """RDAP without registration event returns None age_days."""
    rdap_payload = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2023-01-01T00:00:00Z"},
        ]
    }
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, json.dumps(rdap_payload).encode()))
    res = intel.domain_age("example.com")
    assert res is not None
    assert res["created"] is None
    assert res["age_days"] == None


def test_rdap_missing_events_field(enable_network_settings):
    """RDAP payload missing 'events' returns None age_days."""
    rdap_payload = {"objectClassName": "domain", "handle": "123"}
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, json.dumps(rdap_payload).encode()))
    res = intel.domain_age("example.com")
    assert res is not None
    assert res["age_days"] is None


def test_rdap_404_not_found(enable_network_settings):
    """RDAP 404 response returns None."""
    intel = PassiveIntel(fetch=lambda url, **kw: (404, {}, b'{"errorCode": 404}'))
    assert intel.domain_age("nonexistent-domain.xyz") is None


def test_rdap_corrupted_json(enable_network_settings):
    """RDAP malformed JSON returns None."""
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, b'{"events": broken json'))
    assert intel.domain_age("example.com") is None


def test_rdap_date_without_timezone(enable_network_settings):
    """RDAP date without timezone offset is parsed safely."""
    rdap_payload = {
        "events": [
            {"eventAction": "registration", "eventDate": "2023-05-15 10:30:00"},
        ]
    }
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, json.dumps(rdap_payload).encode()))
    res = intel.domain_age("example.com")
    assert res is not None
    assert res["age_days"] is not None
    assert res["age_days"] > 0


def test_rdap_unreasonable_years(enable_network_settings):
    """RDAP year 1900 or 3000 is rejected as invalid."""
    for yr in ("1900-01-01T00:00:00Z", "3000-01-01T00:00:00Z"):
        payload = {"events": [{"eventAction": "registration", "eventDate": yr}]}
        intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, json.dumps(payload).encode()))
        res = intel.domain_age("example.com")
        assert res is not None
        assert res["age_days"] is None


def test_rdap_domain_linear_validation(enable_network_settings):
    """RDAP domain validation rejects invalid inputs linearly."""
    fetch_mock = MagicMock()
    intel = PassiveIntel(fetch=fetch_mock)

    assert intel.domain_age("") is None
    assert intel.domain_age("localhost") is None
    assert intel.domain_age("invalid..domain.com") is None
    assert intel.domain_age("a" * 64 + ".com") is None
    assert intel.domain_age("space in domain.com") is None
    assert intel.domain_age("http://full-url.com/path") is None
    fetch_mock.assert_not_called()


# ============================================================================
# 2. CRT.SH CERTIFICATE TRANSPARENCY TESTS
# ============================================================================

def test_crtsh_multiple_elements_and_earliest_date(enable_network_settings):
    """crt.sh parses multiple cert items, finds earliest entry, and counts certs."""
    now = datetime.now(timezone.utc)
    d1 = (now - timedelta(days=10)).isoformat()
    d2 = (now - timedelta(days=50)).isoformat()
    d3 = (now - timedelta(days=20)).isoformat()

    items = [
        {"entry_timestamp": d1, "not_before": d1},
        {"entry_timestamp": d2, "not_before": d2},
        {"entry_timestamp": d3, "not_before": d3},
    ]

    def mock_fetch(url, **kw):
        assert "crt.sh/?q=example.com&output=json" in url
        return 200, {}, json.dumps(items).encode()

    intel = PassiveIntel(fetch=mock_fetch)
    res = intel.ct_first_seen("example.com")
    assert res is not None
    assert res["cert_count"] == 3
    assert res["first_seen"] is not None
    # Earliest date should be d2 (~50 days ago)
    dt = datetime.fromisoformat(res["first_seen"])
    assert (now - dt).days >= 49


def test_crtsh_html_error_response(enable_network_settings):
    """crt.sh returning HTML (e.g. 502 Bad Gateway) returns None."""
    html_body = b"<html><head><title>502 Bad Gateway</title></head><body>502</body></html>"
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, html_body))
    assert intel.ct_first_seen("example.com") is None


def test_crtsh_malformed_items_skipped(enable_network_settings):
    """crt.sh skips malformed entries and processes valid ones."""
    items = [
        "not a dict",
        {"broken": "no dates"},
        {"entry_timestamp": "2024-01-01T00:00:00Z"},
    ]
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, json.dumps(items).encode()))
    res = intel.ct_first_seen("example.com")
    assert res is not None
    assert res["cert_count"] == 1
    assert res["first_seen"] is not None


def test_crtsh_empty_list(enable_network_settings):
    """crt.sh returning empty list returns cert_count 0 and None first_seen."""
    intel = PassiveIntel(fetch=lambda url, **kw: (200, {}, b"[]"))
    res = intel.ct_first_seen("example.com")
    assert res is not None
    assert res["cert_count"] == 0
    assert res["first_seen"] is None


# ============================================================================
# 3. TLS CERTIFICATE PROBE TESTS
# ============================================================================

def test_probe_self_signed_cert(enable_network_settings):
    """Self-signed cert is flagged as valid=False, reason='self_signed'."""
    cert, key = _generate_cert(common_name="127.0.0.1", san_list=["127.0.0.1"])
    port, _, cleanup = _start_loopback_tls_server(cert, key)
    try:
        res = probe_tls_certificate(
            "127.0.0.1",
            timeout=2.0,
            _test_ip_filter=lambda ip: ip == "127.0.0.1",
            _test_port=port,
        )
        assert res is not None
        assert res["valid"] is False
        assert res["reason"] == "self_signed"
    finally:
        cleanup()


def test_probe_hostname_mismatch(enable_network_settings):
    """Cert for different hostname is flagged as valid=False, reason='hostname_mismatch'."""
    from cryptography.hazmat.primitives import serialization

    ca_cert, leaf_cert, leaf_key = _generate_ca_and_cert(leaf_cn="mismatch.domain.com", san_list=["mismatch.domain.com"])
    port, _, cleanup = _start_loopback_tls_server(leaf_cert, leaf_key)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as ca_f:
        ca_f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        ca_path = ca_f.name
    try:
        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.check_hostname = True
        res = probe_tls_certificate(
            "127.0.0.1",
            timeout=2.0,
            _test_ip_filter=lambda ip: ip == "127.0.0.1",
            _test_ssl_context=ctx,
            _test_port=port,
        )
        assert res is not None
        assert res["valid"] is False
        assert res["reason"] == "hostname_mismatch"
    finally:
        cleanup()
        try:
            os.remove(ca_path)
        except Exception:
            pass


def test_probe_expired_cert(enable_network_settings):
    """Expired cert is flagged as valid=False, reason='expired'."""
    cert, key = _generate_cert(common_name="127.0.0.1", san_list=["127.0.0.1"], expired=True)
    port, cert_path, cleanup = _start_loopback_tls_server(cert, key)
    try:
        ctx = ssl.create_default_context(cafile=cert_path)
        ctx.check_hostname = True
        res = probe_tls_certificate(
            "127.0.0.1",
            timeout=2.0,
            _test_ip_filter=lambda ip: ip == "127.0.0.1",
            _test_ssl_context=ctx,
            _test_port=port,
        )
        assert res is not None
        assert res["valid"] is False
        assert res["reason"] == "expired"
    finally:
        cleanup()


def test_probe_valid_cert_with_trusted_ca(enable_network_settings):
    """Valid cert trusted by injected context returns full cert metadata."""
    from cryptography.hazmat.primitives import serialization

    ca_cert, leaf_cert, leaf_key = _generate_ca_and_cert(
        leaf_cn="127.0.0.1",
        san_list=["127.0.0.1", "test.local"],
    )
    port, _, cleanup = _start_loopback_tls_server(leaf_cert, leaf_key)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as ca_f:
        ca_f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        ca_path = ca_f.name
    try:
        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.check_hostname = True
        res = probe_tls_certificate(
            "127.0.0.1",
            timeout=2.0,
            _test_ip_filter=lambda ip: ip == "127.0.0.1",
            _test_ssl_context=ctx,
            _test_port=port,
        )
        assert res is not None
        assert res["valid"] is True
        assert res["subject_cn"] == "127.0.0.1"
        assert "127.0.0.1" in res["san"]
        assert res["issuer_org"] == "Test CA Org"
        assert res["days_since_issued"] is not None
        assert res["days_until_expiry"] is not None
    finally:
        cleanup()
        try:
            os.remove(ca_path)
        except Exception:
            pass


def test_probe_ssrf_forbidden_destination(enable_network_settings):
    """Probe to private IP (e.g. 10.0.0.1) without _test_ip_filter returns None immediately."""
    res = probe_tls_certificate("10.0.0.1", timeout=1.0)
    assert res is None


# ============================================================================
# 4. RESOLVER.FETCH SSRF & REDIRECT TESTS
# ============================================================================

def test_fetch_ssrf_private_destination_blocked(enable_network_settings):
    """fetch() blocks private destination and returns None."""
    resolver = SafeRedirectResolver(mode="all")
    res = resolver.fetch("https://10.0.0.1/rdap")
    assert res is None


def test_fetch_allow_hosts_mismatch(enable_network_settings):
    """fetch() rejects initial host not in allow_hosts."""
    resolver = SafeRedirectResolver(mode="all")
    res = resolver.fetch("https://evil.org/domain", allow_hosts={"rdap.org"})
    assert res is None


def test_fetch_redirect_to_private_host_blocked(enable_network_settings):
    """fetch() blocks redirect to internal IP address."""
    def fake_transport(method, scheme, ip, port, host, path_and_query, headers, timeout, max_body_bytes, deadline):
        if host == "rdap.org":
            return 302, {"location": "https://192.168.1.1/registry"}, b""
        return 200, {}, b"internal data"

    resolver = SafeRedirectResolver(mode="all", transport=fake_transport)
    res = resolver.fetch("https://rdap.org/domain/test.com", allow_hosts={"rdap.org"})
    assert res is None


def test_fetch_https_only_enforced(enable_network_settings):
    """fetch() refuses http:// scheme."""
    resolver = SafeRedirectResolver(mode="all")
    assert resolver.fetch("http://rdap.org/domain/test.com") is None


# ============================================================================
# 5. OFFLINE MODE AND PRIVACY TESTS
# ============================================================================

def test_offline_mode_makes_zero_network_calls():
    """When SAFEGUARD_OFFLINE=1 or network disabled, PassiveIntel makes 0 calls."""
    fetch_mock = MagicMock()
    probe_mock = MagicMock()
    dns_mock = MagicMock()

    intel = PassiveIntel(fetch=fetch_mock, probe=probe_mock, dns=dns_mock)
    f = UrlFinding(
        raw="https://phishing.example.com/login",
        normalized="https://phishing.example.com/login",
        final_url="https://phishing.example.com/login",
        display_host="phishing.example.com",
        effective_host="phishing.example.com",
        effective_host_unicode="phishing.example.com",
        registrable_domain="example.com",
        is_official=False,
        brand_match=None,
        source="text",
    )

    res = intel.analyze(f)
    assert res is None
    fetch_mock.assert_not_called()
    probe_mock.assert_not_called()
    dns_mock.assert_not_called()


def test_privacy_only_registrable_domain_queried(enable_network_settings):
    """PassiveIntel sends only registrable domain to RDAP and crt.sh, never full URL/path."""
    queried_urls = []

    def spy_fetch(url, **kw):
        queried_urls.append(url)
        return 200, {}, b"{}"

    intel = PassiveIntel(fetch=spy_fetch, probe=lambda *a, **kw: None, dns=lambda *a, **kw: "ok")
    f = UrlFinding(
        raw="https://subdomain.target-phish.vn/path/secret?token=123",
        normalized="https://subdomain.target-phish.vn/path/secret?token=123",
        final_url="https://subdomain.target-phish.vn/path/secret?token=123",
        display_host="subdomain.target-phish.vn",
        effective_host="subdomain.target-phish.vn",
        effective_host_unicode="subdomain.target-phish.vn",
        registrable_domain="target-phish.vn",
        is_official=False,
        brand_match=None,
        source="text",
    )
    intel.analyze(f)

    for url in queried_urls:
        assert "/path/secret" not in url
        assert "token=123" not in url
        assert "subdomain" not in url
        assert "target-phish.vn" in url


# ============================================================================
# 6. CACHING & THREAD-SAFETY
# ============================================================================

def test_caching_and_ttl(enable_network_settings):
    """Subsequent queries within TTL return cached result without calling fetch again."""
    call_count = 0

    def mock_fetch(url, **kw):
        nonlocal call_count
        call_count += 1
        return 200, {}, json.dumps({"events": [{"eventAction": "registration", "eventDate": "2023-01-01T00:00:00Z"}]}).encode()

    fake_time = [1000.0]
    intel = PassiveIntel(fetch=mock_fetch, cache_ttl_s=100, clock=lambda: fake_time[0])

    r1 = intel.domain_age("cached-test.com")
    assert r1 is not None
    assert call_count == 1

    # Second call returns from cache
    r2 = intel.domain_age("cached-test.com")
    assert r2 == r1
    assert call_count == 1

    # Advance time beyond TTL
    fake_time[0] += 150.0
    r3 = intel.domain_age("cached-test.com")
    assert r3 is not None
    assert call_count == 2


def test_thread_safety_16_threads(enable_network_settings):
    """16 threads querying PassiveIntel simultaneously operate without corruption."""
    def mock_fetch(url, **kw):
        time.sleep(0.01)
        return 200, {}, json.dumps({"events": [{"eventAction": "registration", "eventDate": "2023-01-01T00:00:00Z"}]}).encode()

    intel = PassiveIntel(fetch=mock_fetch)

    def worker(i):
        dom = f"domain{i % 4}.com"
        res = intel.domain_age(dom)
        assert res is not None
        assert res["age_days"] is not None

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3.0)
        assert not t.is_alive()


def test_bounded_timeout_handling(enable_network_settings):
    """A hanging source does not block analyze() beyond overall budget."""
    def hanging_fetch(*args, **kwargs):
        time.sleep(10.0)
        return 200, {}, b"{}"

    intel = PassiveIntel(fetch=hanging_fetch, probe=lambda *a, **kw: None, dns=lambda *a, **kw: "ok")
    f = UrlFinding(
        raw="https://hanging-test.com",
        normalized="https://hanging-test.com",
        final_url="https://hanging-test.com",
        display_host="hanging-test.com",
        effective_host="hanging-test.com",
        effective_host_unicode="hanging-test.com",
        registrable_domain="hanging-test.com",
        is_official=False,
        brand_match=None,
        source="text",
    )

    t0 = time.monotonic()
    res = intel.analyze(f, deadline_s=1.0)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0
    assert res is not None
    assert res["domain_age"] is None


# ============================================================================
# 7. ANALYZER PASSIVE SIGNALS INTEGRATION TESTS
# ============================================================================

def test_analyzer_domain_new_and_brand_signals(enable_network_settings):
    """Domain registered 3 days ago triggers DOMAIN_NEW (high weight 40)."""
    mock_intel = MagicMock()
    mock_intel.analyze.return_value = {
        "domain_age": {"created": "2026-10-14T00:00:00Z", "age_days": 3},
        "ct": None,
        "tls": None,
        "dns_status": "ok",
    }

    analyzer = UrlAnalyzer(passive_intel=mock_intel)
    report = analyzer.analyze_text("Truy cập http://vietcombank-xacthuc.online ngay", allow_network=True)
    assert len(report.findings) > 0
    f = report.findings[0]
    assert any(s.code == "DOMAIN_NEW" for s in f.signals)
    dom_sig = next(s for s in f.signals if s.code == "DOMAIN_NEW")
    assert dom_sig.weight == 40
    assert "3 ngày trước" in dom_sig.message_vi
    assert f.verdict in ("dangerous", "suspicious")


def test_analyzer_cert_new_and_cert_invalid(enable_network_settings):
    """CERT_NEW and CERT_INVALID signals added with Vietnamese messages."""
    mock_intel = MagicMock()
    mock_intel.analyze.return_value = {
        "domain_age": None,
        "ct": None,
        "tls": {"valid": False, "reason": "self_signed"},
        "dns_status": "ok",
    }

    analyzer = UrlAnalyzer(passive_intel=mock_intel)
    report = analyzer.analyze_text("Xem tại http://random-phish-domain.xyz", allow_network=True)
    f = report.findings[0]
    assert any(s.code == "CERT_INVALID" for s in f.signals)
    cert_sig = next(s for s in f.signals if s.code == "CERT_INVALID")
    assert cert_sig.weight == 25
    assert "tự ký" in cert_sig.message_vi


def test_analyzer_domain_dead_nxdomain(enable_network_settings):
    """DOMAIN_DEAD is added for nxdomain and verdict is never official or benign."""
    mock_intel = MagicMock()
    mock_intel.analyze.return_value = {
        "domain_age": None,
        "ct": None,
        "tls": None,
        "dns_status": "nxdomain",
    }

    analyzer = UrlAnalyzer(passive_intel=mock_intel)
    report = analyzer.analyze_text("Link http://dead-link-test.top/abc", allow_network=True)
    f = report.findings[0]
    assert any(s.code == "DOMAIN_DEAD" for s in f.signals)
    dead_sig = next(s for s in f.signals if s.code == "DOMAIN_DEAD")
    assert dead_sig.weight == 10
    assert f.verdict not in ("official", "benign")


def test_analyzer_official_domain_never_penalized(enable_network_settings):
    """Official domain even with simulated young age is NEVER penalized by passive signals."""
    mock_intel = MagicMock()
    mock_intel.analyze.return_value = {
        "domain_age": {"created": "2026-10-15T00:00:00Z", "age_days": 2},
        "ct": {"first_seen": "2026-10-15T00:00:00Z", "cert_count": 1},
        "tls": {"valid": False, "reason": "expired"},
        "dns_status": "nxdomain",
    }

    analyzer = UrlAnalyzer(passive_intel=mock_intel)
    report = analyzer.analyze_text("Đăng nhập https://portal.vietcombank.com.vn", allow_network=True)
    f = report.findings[0]
    assert f.is_official is True
    assert f.url_risk_score == 0
    assert f.verdict == "official"
    assert not any(s.code in ("DOMAIN_NEW", "CERT_NEW", "CERT_INVALID", "DOMAIN_DEAD") for s in f.signals)


# ============================================================================
# 8. MUTATION TESTS (>= 6 mutations verified killed)
# ============================================================================

def test_mutation_allow_hosts_ignored():
    """Mutation: Dropping allow_hosts check in fetch allows forbidden destination."""
    resolver = SafeRedirectResolver(mode="all")
    # Must reject hosts outside allow_hosts
    assert resolver.fetch("https://attacker.example/api", allow_hosts={"rdap.org"}) is None


def test_mutation_probe_without_is_public():
    """Mutation: Dropping is_public_destination check in probe connects to private IP."""
    # probe_tls_certificate to 127.0.0.1 without _test_ip_filter MUST be blocked
    res = probe_tls_certificate("127.0.0.1", timeout=1.0)
    assert res is None


def test_mutation_using_cert_none(enable_network_settings):
    """Mutation: probe_tls_certificate must never accept CERT_NONE."""
    # In probe_tls_certificate, ctx.verify_mode is ssl.CERT_REQUIRED
    # If self-signed cert is probed, it MUST report valid=False, never valid=True!
    cert, key = _generate_cert(common_name="127.0.0.1", san_list=["127.0.0.1"])
    port, _, cleanup = _start_loopback_tls_server(cert, key)
    try:
        res = probe_tls_certificate(
            "127.0.0.1",
            timeout=1.0,
            _test_ip_filter=lambda ip: ip == "127.0.0.1",
            _test_port=port,
        )
        assert res is not None
        assert res["valid"] is False  # A CERT_NONE mutation would return valid=True
    finally:
        cleanup()


def test_mutation_full_url_sent_to_rdap(enable_network_settings):
    """Mutation: Sending full URL/path to RDAP leaks user path."""
    queried = []
    intel = PassiveIntel(fetch=lambda u, **kw: (queried.append(u), (200, {}, b"{}"))[1])
    f = UrlFinding(
        raw="https://bank-login.com/secret_token",
        normalized="https://bank-login.com/secret_token",
        final_url="https://bank-login.com/secret_token",
        display_host="bank-login.com",
        effective_host="bank-login.com",
        effective_host_unicode="bank-login.com",
        registrable_domain="bank-login.com",
        is_official=False,
        brand_match=None,
        source="text",
    )
    intel.analyze(f)
    assert len(queried) > 0
    for q in queried:
        assert "secret_token" not in q


def test_mutation_official_domain_penalized(enable_network_settings):
    """Mutation: Official domain risk score elevated by passive signals."""
    mock_intel = MagicMock()
    mock_intel.analyze.return_value = {
        "domain_age": {"age_days": 1},
        "tls": {"valid": False, "reason": "expired"},
        "dns_status": "nxdomain",
    }
    analyzer = UrlAnalyzer(passive_intel=mock_intel)
    report = analyzer.analyze_text("https://vietcombank.com.vn", allow_network=True)
    f = report.findings[0]
    assert f.url_risk_score == 0
    assert f.verdict == "official"


def test_mutation_offline_bypassed():
    """Mutation: Bypassing offline check in PassiveIntel performs network calls."""
    fetch_mock = MagicMock()
    intel = PassiveIntel(fetch=fetch_mock)
    # When offline (default in test suite), domain_age must return None immediately
    res = intel.domain_age("example.com")
    assert res is None
    fetch_mock.assert_not_called()


# ============================================================================
# Phase 3E-2 Tests: Truncated JSON recovery, RDAP URL format, Probe SSRF
# ============================================================================

def test_crt_sh_truncated_json_recovery(enable_network_settings):
    """
    Nit: crt.sh truncated JSON (> 256KB or connection cut off) is parsed incrementally
    up to the last valid complete object, rather than discarding all data as None.
    """
    # Create valid JSON with 3 objects, then truncate in the middle of 4th object
    items = [
        {"entry_timestamp": "2026-01-01T00:00:00", "not_before": "2026-01-01T00:00:00"},
        {"entry_timestamp": "2026-02-01T00:00:00", "not_before": "2026-02-01T00:00:00"},
        {"entry_timestamp": "2026-03-01T00:00:00", "not_before": "2026-03-01T00:00:00"},
    ]
    truncated_bytes = json.dumps(items).encode("utf-8")[:-1] + b',{"entry_timestamp": "2026-04-01T'  # cut off

    def mock_fetch(url, **kw):
        return 200, {"content-type": "application/json"}, truncated_bytes

    intel = PassiveIntel(fetch=mock_fetch)
    res = intel.ct_first_seen("test-domain.top")
    assert res is not None
    assert res["cert_count"] == 3
    assert res["first_seen"] == "2026-01-01T00:00:00+00:00"


def test_rdap_url_strictly_formatted(enable_network_settings):
    """
    Mutation kill: RDAP lookup must use strictly formatted URL https://rdap.org/domain/{domain}
    with no extraneous query parameters or altered paths.
    """
    requested_urls = []

    def mock_fetch(url, **kw):
        requested_urls.append(url)
        return 200, {"content-type": "application/json"}, b'{"events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}]}'

    intel = PassiveIntel(fetch=mock_fetch)
    res = intel.domain_age("safe-example.com")
    assert res is not None
    assert len(requested_urls) == 1
    assert requested_urls[0] == "https://rdap.org/domain/safe-example.com"


def test_probe_tls_certificate_rejects_domain_resolving_to_private_ip(enable_network_settings, monkeypatch):
    """
    Mutation kill: probe_tls_certificate must block domains resolving to private/loopback IP.
    """
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    res = probe_tls_certificate("evil-private.example", timeout=1.0)
    assert res is None


def test_passive_intel_with_recorder_preserves_data(enable_network_settings):
    """
    Nit: Passing a recorder to PassiveIntel.analyze must return a valid analysis dict,
    not return None accidentally.
    """
    from codebase.url_analysis.resolver import NetworkRecorder
    recorder = NetworkRecorder()

    def mock_fetch(url, **kw):
        if "rdap.org" in url:
            return 200, {}, b'{"events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}]}'
        elif "crt.sh" in url:
            return 200, {}, b'[{"entry_timestamp": "2026-01-01T00:00:00", "not_before": "2026-01-01T00:00:00"}]'
        return 404, {}, b""

    intel = PassiveIntel(fetch=mock_fetch)
    finding = UrlFinding(
        raw="https://example.com/test",
        normalized="https://example.com/test",
        final_url="https://example.com/test",
        display_host="example.com",
        effective_host="example.com",
        effective_host_unicode="example.com",
        registrable_domain="example.com",
        is_official=False,
        brand_match=None,
        source="text",
    )
    res = intel.analyze(finding, recorder=recorder)
    assert res is not None
    assert "domain_age" in res
    assert res["domain_age"] is not None
    assert len(recorder.get_actions()) > 0

