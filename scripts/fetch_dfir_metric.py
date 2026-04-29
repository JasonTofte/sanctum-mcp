"""Runtime fetcher for the DFIR-Metric upstream JSON (license-clean reproduction).

The DFIR-Metric repository carries ``license: null``; we therefore do
NOT vendor the upstream content into Sanctum's source tree. Instead,
this fetcher downloads it once into ``.cache/dfir-metric/`` (gitignored)
and writes a sibling ``PROVENANCE.json`` recording the URL, retrieved
SHA-256, and fetch timestamp so that a reviewer can verify which
upstream revision Sanctum's numbers were computed against.

Security posture (post-Phase-B-review HIGH+MEDIUM fixes):
  * ``expected_sha256`` is REQUIRED — there is no default-None bypass.
    A caller must opt-IN to verification, not opt-OUT. This is the
    integrity gate that protects the threat-model claim that
    parser-input bytes are checked.
  * ``upstream_url`` is restricted to ``https://`` on a host allowlist.
    Defends against caller-side SSRF via ``file://`` / RFC1918 hosts
    (CWE-918 surface for any future config-driven invocation).
  * Response size is capped at ``MAX_RESPONSE_BYTES`` to defeat OOM
    on a hostile multi-GB stream (CWE-770).
  * Cache write is atomic via ``os.replace`` — a SHA-256 mismatch or
    crash leaves NO partial cache for the next reader to ingest.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

UPSTREAM_DEFAULT = (
    "https://raw.githubusercontent.com/DFIR-Metric/DFIR-Metric/main/DFIR-Metric-CTF.json"
)
CACHE_FILENAME = "DFIR-Metric-CTF.json"
PROVENANCE_FILENAME = "PROVENANCE.json"

ALLOWED_SCHEME = "https"
ALLOWED_HOSTS: frozenset[str] = frozenset({"raw.githubusercontent.com"})
MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB plausibility ceiling


def _validate_upstream_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != ALLOWED_SCHEME:
        raise ValueError(
            f"upstream_url scheme must be {ALLOWED_SCHEME!r} (got {parsed.scheme!r}); "
            f"file:// and other schemes are blocked to defeat SSRF (CWE-918)"
        )
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"upstream_url host not in allowlist {sorted(ALLOWED_HOSTS)}; got {parsed.hostname!r}"
        )


def fetch_upstream(
    *,
    expected_sha256: str,  # REQUIRED — no default
    cache_dir: Path = Path(".cache/dfir-metric"),
    upstream_url: str = UPSTREAM_DEFAULT,
    timeout_s: int = 30,
) -> Path:
    """Download upstream, verify, write cache + provenance, return cache path.

    A SHA-256 mismatch (or any other validation failure) leaves NO file on
    disk — the body is buffered in memory, validated, and only then
    atomically renamed into place via ``os.replace``.
    """
    _validate_upstream_url(upstream_url)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / CACHE_FILENAME
    provenance_path = cache_dir / PROVENANCE_FILENAME

    with urllib.request.urlopen(upstream_url, timeout=timeout_s) as response:  # noqa: S310
        # urlopen with explicit https-only URL on a host allowlist enforced
        # above by `_validate_upstream_url`. The S310 ban exists because
        # urlopen accepts file:// schemes; the allowlist defeats that.
        # MAX_RESPONSE_BYTES + 1 lets us detect truncation (full read of
        # MAX_RESPONSE_BYTES is ambiguous between "exactly that big" and
        # "truncated").
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"upstream response exceeded size cap ({MAX_RESPONSE_BYTES} bytes); "
            f"refused to write cache (CWE-770 OOM defense)"
        )

    sha256 = hashlib.sha256(body).hexdigest()
    if sha256 != expected_sha256:
        raise RuntimeError(
            f"DFIR-Metric upstream sha256 mismatch: expected {expected_sha256}, got {sha256}"
        )

    # Atomic write: write to a temp path in the same directory, then
    # os.replace into place. If a crash happens between the two writes,
    # neither cache nor provenance lands — the next caller starts clean.
    cache_tmp = cache_dir / f".{CACHE_FILENAME}.tmp"
    provenance_tmp = cache_dir / f".{PROVENANCE_FILENAME}.tmp"
    cache_tmp.write_bytes(body)
    provenance_tmp.write_text(
        json.dumps(
            {
                "upstream_url": upstream_url,
                "sha256": sha256,
                "fetched_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "byte_length": len(body),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(cache_tmp, cache_path)
    os.replace(provenance_tmp, provenance_path)
    return cache_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Fetch the DFIR-Metric upstream JSON into .cache/dfir-metric/."
    )
    parser.add_argument(
        "--sha256",
        required=True,
        help="Required SHA-256 hex digest of the expected upstream body.",
    )
    args = parser.parse_args()
    out = fetch_upstream(expected_sha256=args.sha256)
    print(f"cached at {out}")
