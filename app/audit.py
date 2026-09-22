"""Tamper-evident, append-only audit hash chain for recovery sessions.

Every state-changing operation on a session (creation, share submission,
successful recovery, revocation, rotation) appends one audit event **inside the
same business transaction** that performs the change. Events are linked with

    event_hash = SHA-256(prev_hash + canonical_event_content)

where the canonical content is deterministic compact JSON over only the
non-sensitive fields: session id, event type, timestamp, sequence number and a
small, structured, non-sensitive result. No key material and no share bytes are
ever recorded. Sequence numbers start at 1 and are gap-free per session.

Changing any stored field (or a previous hash) breaks the link at the first
tampered event, which :func:`verify_chain` reports via ``first_invalid_seq``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

# SHA-256 of an empty input, expressed as 64 zero hex chars: the anchor that
# the first event of every session chains from.
GENESIS_HASH = "0" * 64

# Allowed event types. Kept as constants so call sites and the DB layer share
# one vocabulary.
EVENT_SESSION_CREATED = "session_created"
EVENT_SHARES_SUBMITTED = "shares_submitted"
EVENT_RECOVERED = "recovered"
EVENT_REVOKED = "revoked"
EVENT_ROTATED = "rotated"

EVENT_TYPES = frozenset(
    {
        EVENT_SESSION_CREATED,
        EVENT_SHARES_SUBMITTED,
        EVENT_RECOVERED,
        EVENT_REVOKED,
        EVENT_ROTATED,
    }
)


def canonical_content(
    session_id: str, seq: int, event_type: str, event_time: str, result: Any
) -> bytes:
    """Deterministic byte representation of an event's hash-covered fields.

    Only these five fields are covered by ``event_hash``; the stored previous
    hash is chained in by :func:`compute_hash`. Compact separators and sorted
    keys make the encoding independent of dict insertion order, and
    ``ensure_ascii`` stays at its default so every byte of the JSON text is
    predictable ASCII.
    """
    payload = {
        "session_id": session_id,
        "seq": seq,
        "type": event_type,
        "time": event_time,
        "result": result,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def compute_hash(
    prev_hash: str,
    session_id: str,
    seq: int,
    event_type: str,
    event_time: str,
    result: Any,
) -> str:
    """SHA-256(prev_hash + canonical event content), hex-encoded."""
    body = prev_hash.encode("ascii") + canonical_content(
        session_id, seq, event_type, event_time, result
    )
    return hashlib.sha256(body).hexdigest()


def _as_result(raw: Any) -> Any:
    """Parse the persisted JSON result text back into structured data."""
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return {"_raw": raw}
    if isinstance(raw, (dict, list, int, float, bool)):
        return raw
    return {"_raw": str(raw)}


def verify_chain(
    events: list[Mapping[str, Any]] | list[Any],
) -> dict[str, Any]:
    """Recompute the whole chain for one session.

    ``events`` must be ordered by sequence number. Each entry exposes the
    stored columns ``session_id, seq, type, time, result, prev_hash,
    event_hash`` (sqlite3.Row works directly).

    Returns the ordered event views plus the chain status::

        {
          "valid": bool,            # True only if every link checks out
          "length": int,
          "first_invalid_seq": int | None,
          "first_invalid_reason": str | None,
          "events": [ {..., "valid": bool}, ... ],
        }

    Every event from the first broken link onwards is reported invalid with
    reason ``"chain_broken"``; the event that first fails carries the concrete
    reason (bad hash, gap, duplicate, malformed content, ...). A tampered
    historical field therefore surfaces at exactly the first affected
    sequence number.
    """
    out: list[dict[str, Any]] = []
    expected_seq = 1
    prev_hash = GENESIS_HASH
    first_invalid_seq: int | None = None
    first_invalid_reason: str | None = None
    broken = False

    for raw in events:
        seq = raw["seq"]
        event_view: dict[str, Any] = {
            "seq": seq,
            "type": raw["type"],
            "time": raw["time"],
            "result": _as_result(raw["result"]),
            "prev_hash": raw["prev_hash"],
            "event_hash": raw["event_hash"],
            "valid": False,
        }

        if broken:
            # A prior link already failed; every later event inherits the
            # break because its prev_hash can no longer be trusted.
            event_view["invalid_reason"] = "chain_broken"
            out.append(event_view)
            continue

        reason: str | None = None
        if not isinstance(seq, int):
            reason = "malformed_seq"
        elif seq != expected_seq:
            # Either a gap (a missing sequence) or a duplicate sequence.
            reason = "duplicate_seq" if seq < expected_seq else "seq_gap"

        stored_prev = raw["prev_hash"]
        stored_hash = raw["event_hash"]
        if reason is None and not isinstance(stored_prev, str):
            reason = "malformed_prev_hash"
        elif reason is None and stored_prev != prev_hash:
            # The event no longer follows the real predecessor -- the classic
            # signature of a re-linked / forked chain.
            reason = "prev_hash_mismatch"

        if reason is None:
            try:
                recomputed = compute_hash(
                    stored_prev,
                    raw["session_id"],
                    seq,
                    raw["type"],
                    raw["time"],
                    _as_result(raw["result"]),
                )
            except (TypeError, ValueError):
                recomputed = None
            if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                reason = "malformed_event_hash"
            elif recomputed is None:
                reason = "malformed_content"
            elif stored_hash != recomputed:
                # A stored field (type/time/result/...) was altered after the
                # fact, or the event hash itself was forged.
                reason = "hash_mismatch"

        if reason is None:
            event_view["valid"] = True
            prev_hash = stored_hash
            expected_seq = seq + 1
        else:
            event_view["valid"] = False
            event_view["invalid_reason"] = reason
            broken = True
            first_invalid_seq = seq
            first_invalid_reason = reason
        out.append(event_view)

    return {
        "valid": first_invalid_seq is None,
        "length": len(out),
        "first_invalid_seq": first_invalid_seq,
        "first_invalid_reason": first_invalid_reason,
        "events": out,
    }
