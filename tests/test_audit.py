"""Tests for the tamper-evident audit hash chain.

Covers: per-operation event sequencing inside the business transaction,
exclusion of secrets/shares, whole-chain verification, first-invalid-seq
localisation for every tampering class, concurrency (no duplicate seq / fork),
and atomic rollback on failed rotations.
"""

import importlib
import json
import os
import sqlite3
import threading
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.db"
    monkeypatch.setenv("DR_DB_PATH", str(db_file))
    import app.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def create(client, secret="audit-secret", t=3, n=5, **extra):
    body = {"secret": secret, "encoding": "utf-8", "threshold": t, "total": n}
    body.update(extra)
    r = client.post("/api/v1/sessions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def audit_of(client, sid):
    r = client.get(f"/api/v1/sessions/{sid}/audit")
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------
# Event sequencing on each state change
# --------------------------------------------------------------------------

def test_create_appends_session_created_event(client):
    data = create(client, t=3, n=5)
    chain = audit_of(client, data["session_id"])
    assert chain["valid"] is True
    assert chain["length"] == 1
    ev = chain["events"][0]
    assert ev["seq"] == 1
    assert ev["type"] == "session_created"
    assert ev["prev_hash"] == "0" * 64
    assert len(ev["event_hash"]) == 64
    assert ev["result"] == {
        "threshold": 3,
        "total_shares": 5,
        "status": "active",
    }
    assert ev["time"]


def test_partial_submission_appends_event_without_recovery(client):
    data = create(client, t=3, n=5)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert r.json()["recovered"] is False
    chain = audit_of(client, sid)
    assert chain["valid"] is True
    assert [e["type"] for e in chain["events"]] == [
        "session_created",
        "shares_submitted",
    ]
    submitted = chain["events"][1]
    assert submitted["seq"] == 2
    assert submitted["result"] == {
        "outcome": "accepted",
        "accepted_count": 2,
        "rejected_count": 0,
    }


def test_successful_recovery_appends_submit_and_recovered_events(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    chain = audit_of(client, sid)
    types = [e["type"] for e in chain["events"]]
    assert types == ["session_created", "shares_submitted", "recovered"]
    assert [e["seq"] for e in chain["events"]] == [1, 2, 3]
    assert chain["events"][1]["result"]["outcome"] == "recovered"
    assert chain["events"][1]["result"]["accepted_count"] == 2
    assert chain["events"][2]["result"] == {"status": "recovered"}
    # Each link chains from the previous one.
    assert chain["events"][1]["prev_hash"] == chain["events"][0]["event_hash"]
    assert chain["events"][2]["prev_hash"] == chain["events"][1]["event_hash"]


def test_rejected_shares_recorded_as_rejected_outcome(client):
    data = create(client, t=3, n=5)
    sid = data["session_id"]
    from app.sharing import decode_share, encode_share

    _, x, y = decode_share(data["shares"][0])
    tampered = encode_share(sid, x, bytes([y[0] ^ 0xFF]) + y[1:])
    client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [tampered] + data["shares"][1:3]},
    )
    chain = audit_of(client, sid)
    ev = chain["events"][-1]
    assert ev["type"] == "shares_submitted"
    assert ev["result"]["outcome"] == "rejected"
    assert ev["result"]["accepted_count"] == 2
    assert ev["result"]["rejected_count"] == 1
    # A request containing rejected shares bumps the attempt counter, even when
    # the same request reaches the threshold and recovers.
    data2 = create(client, t=2, n=3)
    sid2 = data2["session_id"]
    from app.sharing import encode_share as enc, decode_share as dec

    _, x2, y2 = dec(data2["shares"][0])
    bad = enc(sid2, x2, bytes([y2[0] ^ 0x01]) + y2[1:])
    # One tampered (rejected) + two valid shares -> still recovered.
    r = client.post(
        f"/api/v1/sessions/{sid2}/shares",
        json={"shares": [bad, data2["shares"][1], data2["shares"][2]]},
    )
    assert r.json()["recovered"] is True
    assert (
        client.get(f"/api/v1/sessions/{sid2}").json()["recovery_attempts"] == 1
    )
    sub = [
        e for e in audit_of(client, sid2)["events"]
        if e["type"] == "shares_submitted"
    ][0]
    assert sub["result"]["outcome"] == "recovered"
    assert sub["result"]["rejected_count"] == 1


def test_recovery_replay_does_not_append_event(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    before = audit_of(client, sid)["length"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert r.json()["replay"] is True
    after = audit_of(client, sid)
    assert after["length"] == before  # no new sequence on replay
    assert after["valid"] is True


def test_revoke_appends_event_and_repeat_replay_does_not(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    assert client.post(f"/api/v1/sessions/{sid}/revoke").json()["revoked"] is True
    assert client.post(f"/api/v1/sessions/{sid}/revoke").json()["replay"] is True
    chain = audit_of(client, sid)
    assert [e["type"] for e in chain["events"]] == [
        "session_created",
        "revoked",
    ]
    assert chain["events"][-1]["result"] == {"status": "revoked"}
    assert chain["valid"] is True


def test_rotation_appends_events_to_both_sessions_in_one_chain_each(client):
    data = create(client, t=3, n=5)
    old_id = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{old_id}/rotate",
        json={"shares": data["shares"][:3], "new_threshold": 2, "new_total": 4},
    )
    assert r.status_code == 201, r.text
    new_id = r.json()["session_id"]

    old_chain = audit_of(client, old_id)
    assert [e["type"] for e in old_chain["events"]] == [
        "session_created",
        "rotated",
    ]
    assert old_chain["events"][1]["result"]["status"] == "rotated"
    assert (
        old_chain["events"][1]["result"]["replacement_session_id"] == new_id
    )

    new_chain = audit_of(client, new_id)
    assert len(new_chain["events"]) == 1
    assert new_chain["events"][0]["type"] == "session_created"
    assert new_chain["events"][0]["result"]["replaces_session_id"] == old_id
    assert new_chain["events"][0]["result"]["threshold"] == 2
    assert old_chain["valid"] and new_chain["valid"]


def test_full_lifecycle_sequence_is_contiguous(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]}
    )
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]}
    )  # same share again, still outcome=accepted (no new index)
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    chain = audit_of(client, sid)
    seqs = [e["seq"] for e in chain["events"]]
    assert seqs == list(range(1, len(seqs) + 1))
    assert chain["valid"] is True


def test_audit_unknown_session_404(client):
    r = client.get("/api/v1/sessions/deadbeef/audit")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "session_not_found"


# --------------------------------------------------------------------------
# No sensitive data in the audit trail
# --------------------------------------------------------------------------

def test_audit_events_never_store_secret_or_shares(client):
    secret = "AUDIT-DO-NOT-LEAK-🔑"
    data = create(client, secret=secret, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    chain_text = json.dumps(audit_of(client, sid))
    assert secret not in chain_text
    for token in data["shares"]:
        assert token not in chain_text

    # And directly in the database table.
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    rows = conn.execute("SELECT * FROM session_audit_events").fetchall()
    blob = json.dumps(rows, default=str, ensure_ascii=False)
    assert secret not in blob
    for token in data["shares"]:
        assert token not in blob
    # Only the documented non-sensitive columns exist.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(session_audit_events)")}
    assert cols == {
        "session_id",
        "seq",
        "event_type",
        "event_time",
        "result",
        "prev_hash",
        "event_hash",
    }
    conn.close()


# --------------------------------------------------------------------------
# Tamper detection: first invalid seq localisation
# --------------------------------------------------------------------------

def _tamper(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def test_modify_result_field_breaks_chain_at_that_seq(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    # Forge the recovery result.
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET result = ? "
        "WHERE session_id = ? AND seq = 2",
        (json.dumps({"outcome": "accepted", "accepted_count": 0,
                     "rejected_count": 0}), sid),
    )
    chain = audit_of(client, sid)
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 2
    assert chain["first_invalid_reason"] == "hash_mismatch"
    validity = {e["seq"]: e["valid"] for e in chain["events"]}
    assert validity == {1: True, 2: False, 3: False}
    assert chain["events"][2]["invalid_reason"] == "chain_broken"


def test_modify_event_type_breaks_chain_at_that_seq(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET event_type = 'revoked' WHERE seq = 3",
    )
    chain = audit_of(client, sid)
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 3
    assert chain["first_invalid_reason"] == "hash_mismatch"
    assert chain["events"][2]["valid"] is False


def test_modify_timestamp_breaks_chain_at_that_seq(client):
    data = create(client)
    sid = data["session_id"]
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET event_time = '1999-01-01T00:00:00.0Z' "
        "WHERE seq = 1",
    )
    chain = audit_of(client, sid)
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 1
    assert chain["first_invalid_reason"] == "hash_mismatch"


def test_modify_prev_hash_creates_fork_and_is_detected(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET prev_hash = ? WHERE seq = 2",
        ("f" * 64,),
    )
    chain = audit_of(client, sid)
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 2
    assert chain["first_invalid_reason"] == "prev_hash_mismatch"


def test_forged_event_hash_that_matches_nothing_is_detected(client):
    data = create(client)
    sid = data["session_id"]
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET event_hash = ? WHERE seq = 1",
        ("a" * 64,),
    )
    chain = audit_of(client, sid)
    assert chain["first_invalid_seq"] == 1
    assert chain["first_invalid_reason"] == "hash_mismatch"


def test_recompute_hash_after_tampering_still_flags_next_link(client):
    """An attacker who also recomputes hashes forward only hides the forged
    event if they recompute EVERY later link; deleting an event creates a
    gap which is still detected."""
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    # Delete the middle event (can't normally be done via the API).
    _tamper(
        os.environ["DR_DB_PATH"],
        "DELETE FROM session_audit_events WHERE session_id = ? AND seq = 2",
        (sid,),
    )
    chain = audit_of(client, sid)
    assert chain["valid"] is False
    # Event 3 now follows seq 1: the first inconsistency is the gap at 3.
    assert chain["first_invalid_seq"] == 3
    assert chain["first_invalid_reason"] == "seq_gap"


def test_tampered_chain_per_event_flags(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/revoke")
    _tamper(
        os.environ["DR_DB_PATH"],
        "UPDATE session_audit_events SET result = ? WHERE seq = 1",
        (json.dumps({"threshold": 9, "total_shares": 9, "status": "active"}),),
    )
    chain = audit_of(client, sid)
    assert not chain["events"][0]["valid"]
    assert chain["events"][0]["invalid_reason"] == "hash_mismatch"
    assert not chain["events"][1]["valid"]
    assert chain["events"][1]["invalid_reason"] == "chain_broken"


# --------------------------------------------------------------------------
# Concurrency: no duplicate sequence numbers, no forks
# --------------------------------------------------------------------------

def test_concurrent_submissions_get_contiguous_unique_seqs(client):
    database = client.app.state.db
    sid = create(client, t=2, n=3)["session_id"]
    outcomes = []
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        try:
            outcomes.append(
                database.record_share_submission(
                    sid,
                    accepted=[i + 1] if i < 3 else [1],
                    rejected_count=0,
                    outcome="accepted",
                )
            )
        except Exception as exc:  # pragma: no cover - failure path
            outcomes.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not any(isinstance(o, Exception) for o in outcomes), outcomes
    chain = audit_of(client, sid)
    seqs = [e["seq"] for e in chain["events"]]
    assert seqs == list(range(1, len(seqs) + 1))
    assert len(seqs) == len(set(seqs)) == 9  # create + 8 submissions
    assert chain["valid"] is True


def test_concurrent_revoke_and_submit_leave_consistent_chain(client):
    """A recovery and a revoke racing: one winner; the chain still verifies."""
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    errors = []

    def submit():
        try:
            client.post(
                f"/api/v1/sessions/{sid}/shares",
                json={"shares": data["shares"][:2]},
            )
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    def revoke():
        try:
            client.post(f"/api/v1/sessions/{sid}/revoke")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    t1 = threading.Thread(target=submit)
    t2 = threading.Thread(target=revoke)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    assert not errors

    chain = audit_of(client, sid)
    assert chain["valid"] is True
    status = client.get(f"/api/v1/sessions/{sid}").json()["status"]
    assert status in ("revoked", "recovered")
    types = [e["type"] for e in chain["events"]]
    # Whichever won, its terminal event is present exactly and last.
    assert types[0] == "session_created"
    assert types[-1] in ("revoked", "recovered")


def test_concurrent_rotations_audit_chain_has_single_winner(client):
    from app.database import RotationStateError

    database = client.app.state.db
    # Create a raw session at the DB layer so the race exercises rotate only.
    sid = "rotrace"
    database.create_session(
        sid,
        threshold=2,
        total_shares=3,
        key_digest="d",
        key_encoding="utf-8",
        key_length=1,
        share_checksums={1: "a", 2: "b", 3: "c"},
        idempotency_key=None,
        request_hash="h",
    )
    outcomes = []
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        try:
            outcomes.append(
                database.rotate_session(
                    sid,
                    f"new{i}",
                    threshold=2,
                    total_shares=4,
                    key_digest="d",
                    key_encoding="utf-8",
                    key_length=1,
                    share_checksums={1: "x", 2: "y", 3: "z", 4: "w"},
                    idempotency_key=None,
                    request_hash="h",
                )
            )
        except RotationStateError:
            outcomes.append("state-conflict")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    old_chain = audit_of(client, sid)
    # Exactly one rotated event; sequence contiguous and chain valid.
    rotated = [e for e in old_chain["events"] if e["type"] == "rotated"]
    assert len(rotated) == 1
    assert old_chain["valid"] is True
    winners = [o for o in outcomes if o != "state-conflict"]
    new_id = winners[0][0]
    new_chain = audit_of(client, new_id)
    assert len(new_chain["events"]) == 1
    assert new_chain["valid"] is True


# --------------------------------------------------------------------------
# Transactionality: failed operations append no events
# --------------------------------------------------------------------------

def test_failed_rotation_appends_no_events(client):
    data = create(client, t=3, n=5)
    sid = data["session_id"]
    from app.sharing import decode_share, encode_share

    _, x, y = decode_share(data["shares"][0])
    tampered = encode_share(sid, x, bytes([y[0] ^ 0xFF]) + y[1:])
    r = client.post(
        f"/api/v1/sessions/{sid}/rotate",
        json={"shares": [tampered] + data["shares"][1:3],
              "new_threshold": 2, "new_total": 4},
    )
    assert r.status_code == 400
    chain = audit_of(client, sid)
    assert [e["type"] for e in chain["events"]] == ["session_created"]
    assert chain["valid"] is True


def test_revoked_session_submit_adds_no_event(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/revoke")
    before = audit_of(client, sid)["length"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert r.status_code == 409
    assert audit_of(client, sid)["length"] == before


def test_creation_replay_adds_no_event(client):
    body = {
        "secret": "idem",
        "threshold": 2,
        "total": 3,
        "idempotency_key": "audit-idem-1",
    }
    r1 = client.post("/api/v1/sessions", json=body)
    r2 = client.post("/api/v1/sessions", json=body)
    sid = r1.json()["session_id"]
    assert r2.json()["replay"] is True
    chain = audit_of(client, sid)
    assert chain["length"] == 1 and chain["valid"] is True


# --------------------------------------------------------------------------
# Unit checks for the canonicalisation / hashing primitives
# --------------------------------------------------------------------------

def test_hash_chain_formula_and_genesis():
    from app import audit

    h1 = audit.compute_hash(
        audit.GENESIS_HASH, "s1", 1, audit.EVENT_SESSION_CREATED, "t1",
        {"a": 1},
    )
    h1_again = audit.compute_hash(
        audit.GENESIS_HASH, "s1", 1, audit.EVENT_SESSION_CREATED, "t1",
        {"a": 1},
    )
    assert h1 == h1_again and len(h1) == 64
    # Result key ordering must not matter (canonical JSON sorts keys).
    h1b = audit.compute_hash(
        audit.GENESIS_HASH, "s1", 1, audit.EVENT_SESSION_CREATED, "t1",
        {"a": 1, "b": 2},
    )
    h1c = audit.compute_hash(
        audit.GENESIS_HASH, "s1", 1, audit.EVENT_SESSION_CREATED, "t1",
        {"b": 2, "a": 1},
    )
    assert h1b == h1c
    assert h1 != h1b

    # Empty / legacy chain verifies as valid.
    report = audit.verify_chain([])
    assert report["valid"] is True and report["length"] == 0
    assert report["first_invalid_seq"] is None


def test_chain_deterministic_across_db_roundtrip(tmp_path):
    from app.database import Database
    from app import audit

    db = Database(str(tmp_path / "unit.db"))
    db.create_session(
        "s1",
        threshold=2,
        total_shares=3,
        key_digest="d",
        key_encoding="utf-8",
        key_length=1,
        share_checksums={1: "a", 2: "b", 3: "c"},
        idempotency_key=None,
        request_hash="h",
    )
    db.record_share_submission(
        "s1", accepted=[1, 2], rejected_count=0, outcome="recovered"
    )
    report = audit.verify_chain(db.get_audit_events("s1"))
    assert report["valid"] is True
    assert [e["type"] for e in report["events"]] == [
        "session_created",
        "shares_submitted",
        "recovered",
    ]
    db.close()
