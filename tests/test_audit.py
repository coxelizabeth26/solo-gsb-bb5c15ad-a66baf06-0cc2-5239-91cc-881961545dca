"""Tests for the tamper-evident per-session audit chain."""

import hashlib
import importlib
import json
import os
import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DR_DB_PATH", str(tmp_path / "audit.db"))
    import app.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def create(client, secret="audit-secret", t=2, n=3, **extra):
    body = {"secret": secret, "encoding": "utf-8", "threshold": t, "total": n}
    body.update(extra)
    r = client.post("/api/v1/sessions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def audit(client, sid):
    return client.get(f"/api/v1/sessions/{sid}/audit")


def types(payload):
    return [(e["seq"], e["type"], e["result"]) for e in payload["events"]]


# --------------------------------------------------------------------------
# Events appended on every state change, in the same business transaction
# --------------------------------------------------------------------------

def test_create_appends_genesis_event(client):
    data = create(client, t=3, n=5)
    body = audit(client, data["session_id"]).json()
    assert body["chain"]["valid"] is True
    assert body["chain"]["event_count"] == 1
    ev = body["events"][0]
    assert ev["seq"] == 1
    assert ev["type"] == "session_created"
    assert ev["result"] == "created"
    assert ev["prev_hash"] == ""
    assert len(ev["event_hash"]) == 64
    assert ev["details"] == {
        "threshold": 3,
        "total_shares": 5,
        "created_by_rotation": False,
    }


def test_full_lifecycle_chain_order(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]})
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][1]]})
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    body = audit(client, sid).json()
    assert body["chain"]["valid"] is True
    assert types(body) == [
        (1, "session_created", "created"),
        (2, "shares_submitted", "pending"),
        (3, "shares_submitted", "pending"),
        (4, "shares_submitted", "recovered"),
        (5, "session_recovered", "recovered"),
    ]
    # Submission details are non-sensitive counters only.
    ev2 = body["events"][1]
    assert ev2["details"] == {
        "accepted_count": 1,
        "newly_accepted": 1,
        "rejected_count": 0,
        "submitted_total": 1,
    }
    # The second distinct share raises the running progress; the third request
    # reaches the threshold and recovers.
    assert body["events"][2]["details"]["submitted_total"] == 2
    assert body["events"][3]["details"]["submitted_total"] == 2
    # Seqs are contiguous from 1.
    assert [e["seq"] for e in body["events"]] == list(range(1, 6))


def test_rejected_share_is_reflected_in_pending_event(client):
    from app.sharing import decode_share, encode_share

    data = create(client, t=2, n=3)
    sid = data["session_id"]
    _, x, y = decode_share(data["shares"][0])
    bad = encode_share(sid, x, bytes([y[0] ^ 0xFF]) + y[1:])
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [bad]})
    body = audit(client, sid).json()
    assert body["chain"]["valid"] is True
    ev = body["events"][1]
    assert ev["type"] == "shares_submitted"
    assert ev["result"] == "pending"
    assert ev["details"]["rejected_count"] == 1
    assert ev["details"]["accepted_count"] == 0
    assert ev["details"]["newly_accepted"] == 0


def test_revoked_session_has_single_revoke_event_and_replay_adds_none(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r1 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r1.json()["revoked"] is True
    r2 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r2.json()["replay"] is True
    body = audit(client, sid).json()
    assert body["chain"]["valid"] is True
    assert types(body) == [
        (1, "session_created", "created"),
        (2, "session_revoked", "revoked"),
    ]


def test_rotation_appends_events_to_both_sessions(client):
    old = create(client, t=3, n=5)
    old_id = old["session_id"]
    r = client.post(
        f"/api/v1/sessions/{old_id}/rotate",
        json={"shares": old["shares"][:3], "new_threshold": 2, "new_total": 4},
    )
    assert r.status_code == 201, r.text
    new_id = r.json()["session_id"]

    old_body = audit(client, old_id).json()
    assert old_body["chain"]["valid"] is True
    assert types(old_body) == [
        (1, "session_created", "created"),
        (2, "session_rotated", "rotated"),
    ]
    link = old_body["events"][1]["details"]
    assert link == {
        "replacement_session_id": new_id,
        "new_threshold": 2,
        "new_total_shares": 4,
    }

    new_body = audit(client, new_id).json()
    assert new_body["chain"]["valid"] is True
    assert types(new_body) == [(1, "session_created", "created")]
    assert new_body["events"][0]["details"] == {
        "threshold": 2,
        "total_shares": 4,
        "created_by_rotation": True,
        "previous_session_id": old_id,
    }


def test_failed_rotation_appends_no_audit_events(client):
    old = create(client, t=3, n=5)
    old_id = old["session_id"]
    before = audit(client, old_id).json()["chain"]["event_count"]
    r = client.post(
        f"/api/v1/sessions/{old_id}/rotate",
        json={"shares": old["shares"][:2], "new_threshold": 2, "new_total": 4},
    )
    assert r.status_code == 400
    after = audit(client, old_id).json()
    # Whole transaction rolled back: chain unchanged and still valid.
    assert after["chain"]["event_count"] == before
    assert after["chain"]["valid"] is True
    assert types(after) == [(1, "session_created", "created")]


def test_idempotent_create_replay_appends_no_event(client):
    body = {
        "secret": "s",
        "threshold": 2,
        "total": 3,
        "idempotency_key": "idem-audit-1",
    }
    r1 = client.post("/api/v1/sessions", json=body)
    r2 = client.post("/api/v1/sessions", json=body)
    sid = r1.json()["session_id"]
    assert r2.json()["session_id"] == sid
    chain = audit(client, sid).json()
    assert chain["chain"]["event_count"] == 1
    assert chain["chain"]["valid"] is True


def test_idempotent_rotation_replay_appends_no_event(client):
    old = create(client, t=2, n=3)
    body = {
        "shares": old["shares"][:2],
        "new_threshold": 2,
        "new_total": 3,
        "idempotency_key": "idem-audit-rot",
    }
    client.post(f"/api/v1/sessions/{old['session_id']}/rotate", json=body)
    r2 = client.post(
        f"/api/v1/sessions/{old['session_id']}/rotate", json=body
    )
    assert r2.json()["replay"] is True
    chain = audit(client, old["session_id"]).json()
    assert types(chain) == [
        (1, "session_created", "created"),
        (2, "session_rotated", "rotated"),
    ]


def test_audit_not_found(client):
    assert audit(client, "deadbeefdead").status_code == 404


def test_empty_fresh_chain_still_valid(client):
    data = create(client)
    body = audit(client, data["session_id"]).json()
    assert body["chain"]["valid"] is True
    assert body["chain"]["first_invalid_seq"] is None
    assert body["chain"]["failure_reason"] is None


# --------------------------------------------------------------------------
# Events never carry secrets, share bytes, tokens or digests
# --------------------------------------------------------------------------

def test_audit_events_never_contain_secret_or_shares(client):
    secret = "AUDIT-DO-NOT-LEAK-ME"
    data = create(client, secret=secret, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]})
    client.post(f"/api/v1/sessions/{sid}/revoke")

    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    rows = conn.execute(
        "SELECT session_id, seq, event_type, occurred_at, result, details, "
        "prev_hash, event_hash, canonical_content FROM audit_events"
    ).fetchall()
    blob = json.dumps(rows, default=str)
    assert secret not in blob
    for token in data["shares"]:
        assert token not in blob
    # Key/share digests must not leak into the audit log either.
    key_digest = client.get(f"/api/v1/sessions/{sid}").json()["key_digest"]
    assert key_digest not in blob


# --------------------------------------------------------------------------
# Hash specification: SHA-256(prev_hash + canonical event content)
# --------------------------------------------------------------------------

def test_event_hashes_match_specification(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]})
    body = audit(client, sid).json()

    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    rows = conn.execute(
        "SELECT prev_hash, canonical_content, event_hash FROM audit_events "
        "WHERE session_id = ? ORDER BY seq",
        (sid,),
    ).fetchall()
    prev = ""
    for (stored_prev, content, stored_hash), ev in zip(rows, body["events"]):
        assert stored_prev == prev
        expected = hashlib.sha256(
            stored_prev.encode("ascii") + content.encode("utf-8")
        ).hexdigest()
        assert stored_hash == expected
        assert ev["event_hash"] == expected
        prev = stored_hash

    # Canonical content is compact, key-sorted JSON of exactly the documented
    # fields -- no extra sensitive columns.
    doc = json.loads(rows[0][1])
    assert set(doc.keys()) == {
        "session_id",
        "seq",
        "type",
        "timestamp",
        "result",
        "details",
    }
    # No insignificant whitespace in the canonical form.
    assert ", " not in rows[0][1] and ": " not in rows[0][1]


def test_hash_is_stable_across_verification_runs(client):
    data = create(client)
    sid = data["session_id"]
    first = audit(client, sid).json()["events"][0]["event_hash"]
    second = audit(client, sid).json()["events"][0]["event_hash"]
    assert first == second


# --------------------------------------------------------------------------
# Tamper detection: first invalid seq + failure reason
# --------------------------------------------------------------------------

def _tamper(conn, sid, sql, *args):
    conn.execute(sql, (sid, *args))
    conn.commit()


def test_tampered_result_field_detected_at_that_seq(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]})
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]})
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    _tamper(
        conn,
        sid,
        "UPDATE audit_events SET result='recovered' "
        "WHERE session_id=? AND seq=2",
    )
    chain = audit(client, sid).json()["chain"]
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 2
    assert chain["failure_reason"] == "event_content_tampered"
    # Earlier event is still reported valid; the break is localised at seq 2.
    events = audit(client, sid).json()["events"]
    assert events[0]["valid"] is True
    assert events[1]["valid"] is False


def test_tampered_details_detected(client):
    data = create(client)
    sid = data["session_id"]
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    _tamper(
        conn,
        sid,
        "UPDATE audit_events SET details='{\"threshold\":99}' WHERE session_id=? AND seq=1",
    )
    chain = audit(client, sid).json()["chain"]
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 1
    assert chain["failure_reason"] == "event_content_tampered"


def test_tampered_timestamp_detected(client):
    data = create(client)
    sid = data["session_id"]
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    _tamper(
        conn,
        sid,
        "UPDATE audit_events SET occurred_at='1999-01-01T00:00:00.000000Z' "
        "WHERE session_id=? AND seq=1",
    )
    chain = audit(client, sid).json()["chain"]
    assert chain["first_invalid_seq"] == 1
    assert chain["failure_reason"] == "event_content_tampered"


def test_tampered_previous_hash_links_to_first_break(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]})
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]})
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    # Rewrite event 2's own hash: its stored hash no longer matches the
    # content, so seq 2 is the first invalid event.
    conn.execute(
        "UPDATE audit_events SET event_hash=? WHERE session_id=? AND seq=2",
        ("0" * 64, sid),
    )
    conn.commit()
    chain = audit(client, sid).json()["chain"]
    assert chain["valid"] is False
    assert chain["first_invalid_seq"] == 2
    assert chain["failure_reason"] == "hash_mismatch"


def test_rewriting_a_predecessor_hash_breaks_predecessor_first(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]})
    # 3 events: created, submitted(recovered), recovered.
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    rows = conn.execute(
        "SELECT seq, event_hash FROM audit_events WHERE session_id=? ORDER BY seq",
        (sid,),
    ).fetchall()
    # Point seq 2's prev_hash at garbage instead of seq 1's real hash.
    conn.execute(
        "UPDATE audit_events SET prev_hash=? WHERE session_id=? AND seq=2",
        ("f" * 64, sid),
    )
    conn.commit()
    body = audit(client, sid).json()
    assert body["chain"]["first_invalid_seq"] == 2
    assert body["chain"]["failure_reason"] == "previous_hash_mismatch"
    assert body["events"][0]["valid"] is True


def test_deleted_event_creates_gap_at_next_stored_seq(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": [data["shares"][0]]})
    client.post(f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]})
    conn = sqlite3.connect(os.environ["DR_DB_PATH"])
    _tamper(conn, sid, "DELETE FROM audit_events WHERE session_id=? AND seq=2")
    body = audit(client, sid).json()
    assert body["chain"]["valid"] is False
    # Stored seq 3 now follows seq 1: it is the first failing record.
    assert body["chain"]["first_invalid_seq"] == 3
    assert body["chain"]["failure_reason"] == "gap_or_duplicate_sequence"


# --------------------------------------------------------------------------
# Concurrency: no duplicate seqs, no forks
# --------------------------------------------------------------------------

def test_concurrent_partial_submissions_use_contiguous_seqs(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]

    def submit(share):
        client.post(
            f"/api/v1/sessions/{sid}/shares", json={"shares": [share]}
        )

    threads = [
        threading.Thread(target=submit, args=(data["shares"][0],)),
        threading.Thread(target=submit, args=(data["shares"][0],)),  # duplicate
        threading.Thread(target=submit, args=(data["shares"][1],)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    body = audit(client, sid).json()
    seqs = [e["seq"] for e in body["events"]]
    # genesis + exactly one event per committed request.
    assert seqs == list(range(1, len(seqs) + 1))
    assert len(seqs) == 4
    assert body["chain"]["valid"] is True


def test_concurrent_recovery_and_revoke_single_winner_chain_valid(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    barrier = threading.Barrier(2)
    outcomes = []

    def recover():
        barrier.wait()
        outcomes.append(
            client.post(
                f"/api/v1/sessions/{sid}/shares",
                json={"shares": data["shares"][:2]},
            ).json()
        )

    def revoke():
        barrier.wait()
        outcomes.append(client.post(f"/api/v1/sessions/{sid}/revoke").json())

    threads = [threading.Thread(target=recover), threading.Thread(target=revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    info = client.get(f"/api/v1/sessions/{sid}").json()
    assert info["status"] in {"recovered", "revoked"}
    body = audit(client, sid).json()
    seqs = [e["seq"] for e in body["events"]]
    assert seqs == list(range(1, len(seqs) + 1))
    assert body["chain"]["valid"] is True
    # Exactly one terminal event type made it onto the chain.
    terminal = [e["type"] for e in body["events"][1:]]
    assert terminal.count("session_recovered") + terminal.count(
        "session_revoked"
    ) == 1


def test_db_level_concurrent_append_never_duplicates_seq(tmp_path):
    """The (session_id, seq) primary key plus BEGIN IMMEDIATE forbid forks."""
    from app.database import Database

    db = Database(str(tmp_path / "c.db"))
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
    errors = []
    barrier = threading.Barrier(10)

    def append(i):
        barrier.wait()
        try:
            with db._lock, db._transaction():
                db._append_audit_event(
                    "s1", "shares_submitted", "pending", {"i": i}
                )
        except Exception as exc:  # pragma: no cover - should not trigger
            errors.append(exc)

    threads = [threading.Thread(target=append, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    rows = db.get_audit_events("s1")
    seqs = [r["seq"] for r in rows]
    assert seqs == list(range(1, 12))  # genesis + 10 appends
    assert len({r["event_hash"] for r in rows}) == len(rows)
    db.close()


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

class TestAuditApiKeyAuth:
    @pytest.fixture()
    def authed_client(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DR_DB_PATH", str(tmp_path / "auth-audit.db"))
        monkeypatch.setenv("DR_API_KEY", "audit-token")
        import app.main as main

        importlib.reload(main)
        with TestClient(main.app) as c:
            yield c

    def test_audit_requires_api_key(self, authed_client):
        r = authed_client.get("/api/v1/sessions/whatever/audit")
        assert r.status_code == 401

    def test_audit_with_key_works(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
            headers={"X-API-Key": "audit-token"},
        )
        sid = r.json()["session_id"]
        r = authed_client.get(
            f"/api/v1/sessions/{sid}/audit",
            headers={"X-API-Key": "audit-token"},
        )
        assert r.status_code == 200
        assert r.json()["chain"]["valid"] is True
