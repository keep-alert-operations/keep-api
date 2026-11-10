"""ServiceNow ticket count client limits and secrecy (REV-65 security review)."""

import asyncio
from datetime import UTC, datetime, timedelta
import gzip
import logging
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import httpx
from pydantic import SecretStr
import pytest

from keep.configuration import ticket_counts
from keep.configuration.ticket_count_routes import TicketCountQuery
from keep.configuration.ticket_counts import TicketCounts, parse_endpoint, query_url
from test_ticket_counts import KEY, URL, Clock, Service, counter, run, streamed


def test_a_flood_never_caches_busy_answers_or_records_failures(monkeypatch, caplog):
    """Requirements: REV-65; dashboard operations 3 (D3 load control); reliability 8."""
    monkeypatch.setattr(ticket_counts, "SLOT_WAIT", 0.05)

    class Slow(httpx.AsyncBaseTransport):
        def __init__(self):
            self.teams = []

        async def handle_async_request(self, request):
            team = dict(parse_qsl(request.url.query.decode()))["team"]
            self.teams.append(team)
            if team != "warm":
                await asyncio.sleep(0.3)
            return streamed(httpx.Response(200, json={"count": 9 if team == "warm" else 1}))

    clock = Clock()
    service = Slow()
    counts = TicketCounts(
        parse_endpoint(URL), transport=service, clock=clock, now=clock.now, slots=2
    )
    queries = [TicketCountQuery(team=f"team-{n}") for n in range(23)]
    queries.append(TicketCountQuery(team="warm"))

    async def scenario():
        await counts.lookup("warm", "open", "hamal")
        clock.value += 31  # the warm answer has expired
        with caplog.at_level(logging.WARNING):
            return await counts.lookup_many(queries)

    results = run(scenario())
    statuses = [result["status"] for result in results]
    assert statuses[:2] == ["count", "count"]
    assert statuses[2:] == ["unavailable"] * 22
    assert all(result["checked_at"] is None for result in results[2:])
    # The pre-warmed key keeps its last count and its cached count answer.
    assert (results[-1]["status"], results[-1]["last_count"]) == ("unavailable", 9)
    assert counts.answers[("warm", "open", "hamal")].reply.status == "count"
    assert {key[0] for key in counts.answers} == {"warm", "team-0", "team-1"}
    assert counts.integration()["last_error"] is None
    assert counts.integration()["last_failure_at"] is None
    assert service.teams == ["warm", "team-0", "team-1"]
    # One rate-limited warning for the whole flood.
    assert [record.getMessage() for record in caplog.records] == [
        "Ticket counting service at https://tickets.example.com:8443 is busy: no free call slot"
    ]
    # A key that got no slot is looked up again next time.
    assert run(counts.lookup("team-5", "open", "hamal"))["status"] == "count"
    assert service.teams[-1] == "team-5"


def test_the_service_timeout_starts_once_a_slot_is_held(monkeypatch):
    """Requirements: REV-65; reliability 8."""
    monkeypatch.setattr(ticket_counts, "SLOT_WAIT", 1.0)
    monkeypatch.setattr(ticket_counts, "TIMEOUT", 0.4)

    class Paced(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(0.25)
            return streamed(httpx.Response(200, json={"count": 2}))

    clock = Clock()
    counts = TicketCounts(
        parse_endpoint(URL), transport=Paced(), clock=clock, now=clock.now, slots=1
    )

    async def scenario():
        # The second call waits 0.25 s for the slot, then gets its own 0.4 s.
        return await asyncio.gather(
            counts.lookup("a", "open", "hamal"), counts.lookup("b", "open", "hamal")
        )

    assert [result["count"] for result in run(scenario())] == [2, 2]


def test_failure_warnings_are_rate_limited_per_kind():
    """Requirements: REV-65; reliability 8."""
    clock = Clock()
    service = Service(lambda r: httpx.Response(503))
    counts = counter(service, clock=clock)
    logged = []
    handler = logging.Handler()
    handler.emit = logged.append
    ticket_counts.log.addHandler(handler)
    try:
        for _ in range(3):
            run(counts.check())
        clock.value += 60
        run(counts.check())
        service.reply = lambda r: httpx.Response(200, content=b"nope")
        run(counts.check())
    finally:
        ticket_counts.log.removeHandler(handler)
    assert [record.getMessage().rsplit(": ", 1)[1] for record in logged] == [
        "status 503",
        "status 503",
        "invalid JSON",
    ]
    assert len(service.requests) == 5
    assert counts.integration()["last_error"] == "invalid JSON"


def test_request_logs_never_carry_the_address(caplog):
    """Requirements: REV-65; operators 14 (the address is a secret)."""
    saved = {name: logging.getLogger(name).level for name in ("httpx", "httpcore")}
    try:
        for name in saved:
            logging.getLogger(name).setLevel(logging.NOTSET)
        settings = SimpleNamespace(ticket_count_url=SecretStr(URL), environment="production")
        counts = TicketCounts.from_settings(settings, transport=httpx.MockTransport(Service()))
        with caplog.at_level(logging.DEBUG):
            assert run(counts.lookup("Ops", "open", "hamal"))["status"] == "count"
            assert run(counts.check())["ok"]
        assert KEY not in caplog.text and "/api/count" not in caplog.text
        assert logging.getLogger("httpx").getEffectiveLevel() == logging.WARNING
        assert logging.getLogger("httpcore").getEffectiveLevel() == logging.WARNING
    finally:
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


def test_compressed_replies_are_refused_and_identity_is_asked_for():
    """Requirements: REV-65; reliability 8 (64 KiB raw reply limit)."""

    def compressed(request):
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
            stream=httpx.ByteStream(gzip.compress(b'{"count": 3}')),
        )

    service = Service(compressed)
    counts = counter(service)
    assert run(counts.lookup("Ops", "open", "hamal"))["status"] == "unavailable"
    assert counts.integration()["last_error"] == "encoding"
    assert service.requests[0].headers["accept-encoding"] == "identity"
    service.reply = lambda r: httpx.Response(
        200, headers={"Content-Encoding": "identity"}, json={"count": 3}
    )
    assert run(counts.lookup("Ops", "both", "all"))["count"] == 3
    # The cap applies to the bytes received.
    service.reply = lambda r: httpx.Response(200, content=b" " * (64 * 1024) + b'{"count": 1}')
    assert run(counts.lookup("Ops", "open", "all"))["status"] == "unavailable"
    assert counts.integration()["last_error"] == "reply over 64 KiB"


@pytest.mark.parametrize(
    ("detection", "query"),
    [
        (
            "hamal",
            "key=a%20b%2Bc&debug&x=1&format=&team=Net+Ops+%26+Co&state=new&system_failure=true",
        ),
        (
            "all",
            "key=a%20b%2Bc&debug&x=1&system%5Ffailure=yes&format=&team=Net+Ops+%26+Co&state=new",
        ),
    ],
)
def test_the_configured_query_is_kept_byte_for_byte(detection, query):
    """Requirements: REV-65; dashboard operations 3 (KeepHQ's query parameters)."""
    configured = (
        "https://tickets.example.com/c?key=a%20b%2Bc&debug&x=1&team=old"
        "&system%5Ffailure=yes&&format=&state=closed"
    )
    service = Service()
    counts = counter(service, url=configured)
    assert urlsplit(query_url(counts.endpoint, "Net Ops & Co", "open", detection)).query == query
    run(counts.lookup("Net Ops & Co", "open", detection))
    assert service.requests[0].url.query.decode() == query
    assert service.requests[0].url.path == "/c"


def test_a_configured_ca_file_alone_verifies_the_service(tmp_path):
    """Requirements: REV-65; operators 14 (deployment TLS)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Keep ticket test CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    settings = SimpleNamespace(ticket_count_url=SecretStr(URL), ticket_count_ca_file=str(path))
    context = TicketCounts.from_settings(settings).client._transport._pool._ssl_context
    subjects = [cert["subject"] for cert in context.get_ca_certs()]
    assert subjects == [((("commonName", "Keep ticket test CA"),),)]
    assert context.verify_mode.name == "CERT_REQUIRED" and context.check_hostname
    default = TicketCounts.from_settings(SimpleNamespace(ticket_count_url=SecretStr(URL)))
    default_context = default.client._transport._pool._ssl_context
    assert [cert["subject"] for cert in default_context.get_ca_certs()] != subjects
