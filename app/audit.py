"""Tamper-evident audit chain for recovery-session state changes.

Every state-changing business transaction appends an audit event (rotation
appends one to each of the old and the new session). Events deliberately hold
only non-sensitive metadata -- a session identifier, an event type, a UTC
timestamp and a coarse result plus a few counters/links. Keys, raw shares,
share tokens and digests are never written to the audit log.

Chain construction (per session)::

    seq:        starts at 1 and is contiguous
    prev_hash:  event_hash of the previous event ("" for the genesis event)
    event_hash: SHA-256(prev_hash + canonical_event_content)

The canonical event content is a compact JSON document with sorted keys and no
insignificant whitespace, so hashes are reproducible on any platform::

    {"details":{...},"result":"...","seq":1,"session_id":"...",
     "timestamp":"...","type":"..."}

A targeted modification of any historical field (or of a previous hash) breaks
the hash at that event and at every event built on top of it; verification
walks the chain using the *stored* predecessor hash, which localises the first
failing sequence number.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Iterable, Mapping

# SHA-256 over (prev_hash || canonical content); genesis links to "".
GENESIS_HASH = ""
HASH_ALGORITHM = "SHA-256"

# Event types -- one per state change in the service's lifecycle.
SESSION_CREATED = "session_created"
SHARES_SUBMITTED = "shares_submitted"
SESSION_RECOVERED = "session_recovered"
SESSION_REVOKED = "session_revoked"
SESSION_ROTATED = "session_rotated"

EVENT_TYPES = frozenset(
    {
        SESSION_CREATED,
        SHARES_SUBMITTED,
        SESSION_RECOVERED,
        SESSION_REVOKED,
        SESSION_ROTATED,
    }
)

# Coarse, non-sensitive result vocabulary.
RESULT_CREATED = "created"
RESULT_PENDING = "pending"      # shares accepted but threshold not reached
RESULT_RECOVERED = "recovered"  # threshold reached, key reconstructed
RESULT_REVOKED = "revoked"
RESULT_ROTATED = "rotated"

# Verification failure codes.
FAIL_SEQUENCE = "gap_or_duplicate_sequence"
FAIL_MALFORMED_DETAILS = "malformed_details"
FAIL_CONTENT = "event_content_tampered"
FAIL_PREV_HASH = "previous_hash_mismatch"
FAIL_HASH = "hash_mismatch"


def canonical_details(details: Mapping[str, Any] | None) -> str:
    """Deterministic JSON encoding of the non-sensitive details object."""
    return json.dumps(
        dict(details or {}),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_content(
    session_id: str,
    seq: int,
    event_type: str,
    occurred_at: str,
    result: str,
    details: Mapping[str, Any] | None,
) -> bytes:
    """Reproducible bytes covered by the event hash."""
    document = {
        "session_id": session_id,
        "seq": seq,
        "type": event_type,
        "timestamp": occurred_at,
        "result": result,
        "details": dict(details or {}),
    }
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_event_hash(prev_hash: str, content: bytes) -> str:
    """SHA-256(prev_hash || canonical event content), hex encoded."""
    return hashlib.sha256(prev_hash.encode("ascii") + content).hexdigest()


def verify_chain(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify an ordered (seq ASC) audit chain.

    Returns ``(events, summary)``: ``events`` exposes each stored event with a
    per-event ``valid`` flag and parsed ``details``; ``summary`` carries the
    whole-chain ``valid`` state and, on failure, the ``first_invalid_seq`` and
    a machine-readable ``failure_reason``.

    Verification always walks the full chain and advances the running hash with
    the *stored* predecessor hash, so a break at sequence k is attributed to k
    itself rather than to every later event.
    """
    events: list[dict[str, Any]] = []
    prev_hash = GENESIS_HASH
    expected_seq = 1
    first_invalid_seq: int | None = None
    failure_reason: str | None = None

    for row in rows:
        seq = row["seq"]
        stored_details = row["details"]
        reason: str | None = None

        if seq != expected_seq:
            # Duplicate seq is prevented by the primary key on write; an
            # externally edited DB can create gaps or repeats.
            reason = FAIL_SEQUENCE

        try:
            details = (
                json.loads(stored_details)
                if stored_details is not None
                else {}
            )
            if not isinstance(details, dict):
                raise ValueError("details must be a JSON object")
        except (TypeError, ValueError):
            details = {}
            reason = reason or FAIL_MALFORMED_DETAILS

        if reason is None:
            content = canonical_content(
                row["session_id"],
                seq,
                row["event_type"],
                row["occurred_at"],
                row["result"],
                details,
            )
            if content.decode("utf-8") != row["canonical_content"]:
                reason = FAIL_CONTENT
            elif row["prev_hash"] != prev_hash:
                reason = FAIL_PREV_HASH
            else:
                expected_hash = build_event_hash(prev_hash, content)
                if not hmac.compare_digest(expected_hash, row["event_hash"]):
                    reason = FAIL_HASH

        if reason is not None and first_invalid_seq is None:
            first_invalid_seq = seq
            failure_reason = reason

        events.append(
            {
                "seq": seq,
                "type": row["event_type"],
                "timestamp": row["occurred_at"],
                "result": row["result"],
                "details": details,
                "prev_hash": row["prev_hash"],
                "event_hash": row["event_hash"],
                "valid": reason is None,
            }
        )

        # Use stored values so the *first* break is localised precisely.
        prev_hash = row["event_hash"]
        expected_seq += 1

    summary = {
        "hash_algorithm": HASH_ALGORITHM,
        "valid": first_invalid_seq is None,
        "event_count": len(events),
        "first_invalid_seq": first_invalid_seq,
        "failure_reason": failure_reason,
    }
    return events, summary
