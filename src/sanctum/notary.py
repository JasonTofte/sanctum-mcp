"""RFC 3161 Trusted Timestamp notary for the Sanctum audit ledger.

Sanctum's HMAC-chained ledger is tamper-evident under the honest-logger
assumption: any mutation of a past entry breaks the chain. It is not, by
itself, **non-repudiable** — a local attacker who holds the HMAC key can
still forge a consistent chain retroactively.

An RFC 3161 Time-Stamp Authority (TSA) provides the missing third-party
witness. The TSA signs a ``TimeStampToken`` that binds the ledger head's
hash to a wall-clock time; the TSA's signing cert chains to a public PKI
root. A forger now also needs to compromise the TSA — impractical for any
single attacker. This is the tier required for court-admissible chain of
custody (FRE 902(13)/(14); NIST SP 800-53 AU-10(5) Digital Signatures;
AU-11(1) Long-term Retrieval).

This module wraps ``openssl ts`` for request construction and response
parsing, so there are no new Python dependencies — only the ``openssl``
binary (ubiquitous on SIFT and every mainstream Linux distribution).

Usage::

    from sanctum.notary import stamp_head
    result = stamp_head()  # stamps the current ledger head to the default TSA
    # result.tsr_path — archive this file alongside the ledger for audit

Call :func:`stamp_head` once per session, per N entries, or per hour —
choose cadence based on incident-response context. Each call writes:

- ``<ledger>.tsq.<ts>`` — DER-encoded timestamp request (kept for reproducibility)
- ``<ledger>.tsr.<ts>`` — DER-encoded timestamp response with the TSA's signature

Free public TSAs known to implement RFC 3161 (as of 2026-04):

- ``https://rfc3161.ai.moda`` (default; reported "few million requests/month")
- ``http://timestamp.digicert.com`` (bundled with DigiCert code-signing)
- ``http://time.certum.pl``
- ``http://freetsa.org/tsr``

References:

- RFC 3161 — Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)
- NIST SP 800-53 r5 — AU-9(3), AU-10(5), AU-11(1)
- RFC 9162 — Certificate Transparency v2 (companion pattern; future upgrade)
- FRE 902(13)/(14) — self-authentication of electronic records
- ``docs/THREAT_MODEL_LEDGER.md`` — full threat model for the ledger posture
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sanctum.audit import _last_line_hash, _ledger_path

DEFAULT_TSA_URL = "https://rfc3161.ai.moda"
TSA_REQUEST_CONTENT_TYPE = "application/timestamp-query"
TSA_RESPONSE_CONTENT_TYPE = "application/timestamp-reply"
_OPENSSL_TIMEOUT_SECONDS = 30

_log = logging.getLogger("sanctum.notary")


@dataclass(frozen=True)
class StampResult:
    """Artefacts produced by a successful :func:`stamp_head` call."""

    ledger_path: Path
    head_hash: str
    tsa_url: str
    tsq_path: Path
    tsr_path: Path
    status_text: str


@dataclass(frozen=True)
class StampOutcome:
    """Demo-side result wrapper for :func:`stamp_head_or_log`.

    ``stamp_head`` itself raises on failure — that contract is preserved
    for production callers that want exception-driven retry/queue logic.
    The graceful-degradation wrapper used by ``scripts/quickstart.py``
    needs a structured success-vs-fallback signal it can route on without
    parsing logs, hence this separate type.

    ``rung_reached`` is the single dispatch field: ``2`` means the TSA
    granted a stamp (``result`` is populated); ``1`` means the call fell
    back to the HMAC-only chain. ``cause`` names the failure class for
    operator triage; ``reachable`` distinguishes "POST succeeded but the
    payload was rejected" (TSA-side issue) from "POST never completed"
    (network/local-tooling issue).
    """

    rung_reached: int
    reachable: bool
    cause: str | None
    result: StampResult | None
    head_hash: str
    tsa_url: str


def stamp_head(
    ledger_path: Path | None = None,
    tsa_url: str = DEFAULT_TSA_URL,
    *,
    archive_dir: Path | None = None,
    timeout: int = _OPENSSL_TIMEOUT_SECONDS,
) -> StampResult:
    """Stamp the current ledger head to an RFC 3161 TSA.

    Args:
        ledger_path: Path to the ledger; defaults to :func:`sanctum.audit._ledger_path`.
        tsa_url: TSA endpoint; defaults to :data:`DEFAULT_TSA_URL`.
        archive_dir: Directory for ``.tsq``/``.tsr`` artefacts; defaults to
            ``ledger_path.parent``.
        timeout: HTTP timeout in seconds (default 30).

    Returns:
        :class:`StampResult` with paths to the archived request/response.

    Raises:
        RuntimeError: if ``openssl`` is not installed, or the TSA returned a
            non-``granted`` status.
        urllib.error.URLError: on network failure.
    """

    if shutil.which("openssl") is None:
        raise RuntimeError(
            "openssl is required for RFC 3161 stamping but was not found on "
            "PATH. Install via `apt install openssl` on Debian/Ubuntu."
        )

    path = ledger_path or _ledger_path()
    head = _last_line_hash(path)
    archive = archive_dir or path.parent
    archive.mkdir(parents=True, exist_ok=True)
    ts_tag = _compact_utc_now()
    tsq_path = archive / f"{path.name}.tsq.{ts_tag}"
    tsr_path = archive / f"{path.name}.tsr.{ts_tag}"

    # Build the TimeStampReq bound to the current HMAC head.
    tsq_bytes = _build_timestamp_query(head)
    tsq_path.write_bytes(tsq_bytes)

    # POST to the TSA and persist the response bytes verbatim. Any parsing
    # we do is for status verification only — the archived file is the
    # court-facing artefact.
    # Audited URL open: scheme is HTTP/HTTPS per RFC 3161 convention; no
    # file:/custom schemes are accepted by the TSA we target.
    req = urllib.request.Request(  # noqa: S310
        tsa_url,
        data=tsq_bytes,
        headers={"Content-Type": TSA_REQUEST_CONTENT_TYPE},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        tsr_bytes = resp.read()
    tsr_path.write_bytes(tsr_bytes)

    status_text = _parse_timestamp_reply_status(tsr_path)
    if "Status: Granted" not in status_text:
        raise RuntimeError(
            f"TSA {tsa_url} did not grant the stamp. "
            f"Parsed status:\n{status_text}"
        )

    return StampResult(
        ledger_path=path,
        head_hash=head,
        tsa_url=tsa_url,
        tsq_path=tsq_path,
        tsr_path=tsr_path,
        status_text=status_text,
    )


def stamp_head_or_log(
    ledger_path: Path | None = None,
    tsa_url: str = DEFAULT_TSA_URL,
    *,
    archive_dir: Path | None = None,
    timeout: int = _OPENSSL_TIMEOUT_SECONDS,
    logger: logging.Logger | None = None,
) -> StampOutcome:
    """Try :func:`stamp_head`; on documented failure, log a structured WARN
    and return a rung-1 :class:`StampOutcome` instead of raising.

    The three failure classes the wrapper catches are exactly the ones
    documented as residuals in ``docs/THREAT_MODEL_LEDGER.md``:

    - ``urllib.error.URLError`` (and subclasses) — network unreachable, DNS
      failure, TLS handshake failure → ``cause="network"``, ``reachable=False``.
    - ``RuntimeError`` raised by :func:`stamp_head` for ``openssl`` missing →
      ``cause="openssl_missing"``, ``reachable=False``. The POST never starts.
    - ``RuntimeError`` raised by :func:`stamp_head` for a non-Granted TSA
      reply → ``cause="tsa_reject"``, ``reachable=True``. The POST completed;
      the TSA returned a structured rejection.

    Any other exception (``MemoryError``, ``CalledProcessError`` from a
    crashing openssl, etc.) is *not* caught — those are programming or
    environment errors that should not be silently demoted to rung-1.

    Args:
        ledger_path: Forwarded to :func:`stamp_head`.
        tsa_url: Forwarded to :func:`stamp_head`.
        archive_dir: Forwarded to :func:`stamp_head`.
        timeout: Forwarded to :func:`stamp_head`.
        logger: Optional override for the module logger; tests use this to
            scope ``caplog`` capture. Defaults to ``sanctum.notary``.

    Returns:
        :class:`StampOutcome` with ``rung_reached`` set to ``2`` on success
        or ``1`` on documented fallback. ``head_hash`` and ``tsa_url`` are
        always populated so a fallback log line still pins which state
        the demo was at when rung-2 became unreachable.
    """

    use_log = logger or _log

    # Resolve the head hash up front so it is available for the WARN line
    # even when the underlying stamp_head call fails before reading it
    # (e.g., openssl-missing path raises before _last_line_hash runs).
    path = ledger_path or _ledger_path()
    head_hash = _last_line_hash(path)

    try:
        result = stamp_head(
            ledger_path=ledger_path,
            tsa_url=tsa_url,
            archive_dir=archive_dir,
            timeout=timeout,
        )
    except urllib.error.URLError as exc:
        _emit_fallback_warning(use_log, "network", tsa_url, head_hash, str(exc))
        return StampOutcome(
            rung_reached=1,
            reachable=False,
            cause="network",
            result=None,
            head_hash=head_hash,
            tsa_url=tsa_url,
        )
    except RuntimeError as exc:
        # stamp_head raises RuntimeError for two distinct conditions; we
        # disambiguate by message because the underlying function does not
        # use a typed error hierarchy and changing that is out of B6 scope.
        message = str(exc)
        if "openssl is required" in message:
            cause = "openssl_missing"
            reachable = False
        elif "did not grant" in message:
            cause = "tsa_reject"
            reachable = True
        else:
            # Unexpected RuntimeError shape — propagate, do not silently
            # demote. The wrapper's contract is to handle the documented
            # classes only.
            raise
        _emit_fallback_warning(use_log, cause, tsa_url, head_hash, message)
        return StampOutcome(
            rung_reached=1,
            reachable=reachable,
            cause=cause,
            result=None,
            head_hash=head_hash,
            tsa_url=tsa_url,
        )

    return StampOutcome(
        rung_reached=2,
        reachable=True,
        cause=None,
        result=result,
        head_hash=result.head_hash,
        tsa_url=result.tsa_url,
    )


def _emit_fallback_warning(
    logger: logging.Logger,
    cause: str,
    tsa_url: str,
    head_hash: str,
    detail: str,
) -> None:
    """Single emission point for the rung-1 demotion log line.

    Stable token ``event=tsa_stamp_fallback`` is the soft-alarm signal CI
    can grep for even when ``quickstart.py`` exits 0 on fallback. The
    ``extra`` dict surfaces the same fields as structured attributes so
    log pipelines that parse JSON-formatted records get them as columns.
    """
    logger.warning(
        "event=tsa_stamp_fallback cause=%s tsa_url=%s head_hash=%s detail=%s",
        cause,
        tsa_url,
        head_hash,
        detail,
        extra={
            "event": "tsa_stamp_fallback",
            "cause": cause,
            "tsa_url": tsa_url,
            "head_hash": head_hash,
            "detail": detail,
        },
    )


def _build_timestamp_query(digest_hex: str) -> bytes:
    """Build an RFC 3161 ``TimeStampReq`` for the given SHA-256 digest hex.

    The ``-cert`` flag asks the TSA to include its signing cert in the reply
    so downstream verifiers don't need a cert-path lookup. ``-no_nonce``
    produces deterministic bytes for the same digest (easier to diff).
    """
    # Fully-controlled argv: ``openssl`` resolved via PATH per
    # :func:`shutil.which` in :func:`stamp_head` (presence check); ``digest_hex``
    # is a hex string read from the ledger (untrusted-input risk: none — hex
    # alphabet cannot contain shell metacharacters).
    argv = [  # noqa: S607 — openssl is a stable, universally-present binary; pre-check in stamp_head()
        "openssl", "ts", "-query",
        "-digest", digest_hex,
        "-sha256",
        "-no_nonce",
        "-cert",
    ]
    result = subprocess.run(argv, capture_output=True, check=True)  # noqa: S603
    return result.stdout


def _parse_timestamp_reply_status(tsr_path: Path) -> str:
    """Run ``openssl ts -reply -in <tsr> -text`` and return the stdout.

    The text block contains a ``Status: Granted`` line on success; anything
    else is a protocol-level rejection that we surface as a RuntimeError.
    """
    # Same rationale as ``_build_timestamp_query`` — see comment there.
    argv = ["openssl", "ts", "-reply", "-in", str(tsr_path), "-text"]  # noqa: S607
    result = subprocess.run(argv, capture_output=True, check=True)  # noqa: S603
    return result.stdout.decode("utf-8", errors="replace")


def _compact_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
