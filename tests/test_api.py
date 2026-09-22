"""End-to-end API tests using FastAPI TestClient with a temporary SQLite DB."""

import base64
import importlib
import json
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DR_DB_PATH", str(db_file))
    import app.main as main

    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def create(client, secret="my-db-root-password", t=3, n=5, **extra):
    body = {"secret": secret, "encoding": "utf-8", "threshold": t, "total": n}
    body.update(extra)
    r = client.post("/api/v1/sessions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_returns_shares_once(client):
    data = create(client)
    assert data["shares_returned"] is True
    assert len(data["shares"]) == 5
    assert data["status"] == "active"
    # Shares are bound to the session id.
    from app.sharing import decode_share

    for token in data["shares"]:
        sid, _, _ = decode_share(token)
        assert sid == data["session_id"]


def test_full_recovery_flow(client):
    data = create(client, secret="master-key-🔑", t=3, n=5)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:3]}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recovered"] is True
    assert body["key"] == "master-key-🔑"
    assert body["status"] == "recovered"


def test_fewer_than_threshold_not_recovered(client):
    data = create(client, t=3, n=5)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["key"] is None
    assert body["shares_required"] == 1

    # Must resend all t shares together; prior partial submission is tracked.
    info = client.get(f"/api/v1/sessions/{sid}").json()
    assert info["submitted_count"] == 2


def test_bad_share_does_not_leak_secret(client):
    data = create(client, secret="S3cr3t", t=3, n=5)
    sid = data["session_id"]
    from app.sharing import decode_share, encode_share

    # Tamper one share byte.
    s_sid, x, y = decode_share(data["shares"][0])
    tampered = encode_share(s_sid, x, bytes([y[0] ^ 0xFF]) + y[1:])

    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [tampered] + data["shares"][1:3]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["key"] is None
    rejected = {item["index"] for item in body["rejected"]}
    assert x in rejected
    assert body["accepted_indices"] == [2, 3]


def test_completely_fabricated_share_rejected(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    # A structurally valid share for this session but with wrong y bytes.
    fake = _make_share(sid, 1, b"xxxx")
    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [fake, data["shares"][1]]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert body["rejected"][0]["code"] == "integrity_check_failed"


def test_share_from_other_session_rejected(client):
    a = create(client, t=2, n=3)
    b = create(client, t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{a['session_id']}/shares",
        json={"shares": [b["shares"][0], a["shares"][1]]},
    )
    body = r.json()
    assert body["recovered"] is False
    assert len(body["rejected"]) == 1


def test_malformed_share_token(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": ["garbage!!"]}
    )
    assert r.json()["rejected"][0]["code"] == "malformed_share"


def test_recovered_key_returned_only_once(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    first = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert first.json()["key"] is not None
    second = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert second.json()["recovered"] is True
    assert second.json()["key"] is None
    assert second.json()["replay"] is True


def test_revoke_blocks_recovery_and_is_idempotent(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r1 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r1.json()["status"] == "revoked"
    assert r1.json()["revoked"] is True
    r2 = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r2.json()["status"] == "revoked"
    assert r2.json()["replay"] is True

    r = client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "session_revoked"


def test_recovered_session_cannot_be_revoked(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    r = client.post(f"/api/v1/sessions/{sid}/revoke")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "session_not_revocable"


def test_creation_idempotency_key(client):
    body = {
        "secret": "same-secret",
        "encoding": "utf-8",
        "threshold": 2,
        "total": 3,
        "idempotency_key": "abc-key-1",
    }
    r1 = client.post("/api/v1/sessions", json=body)
    r2 = client.post("/api/v1/sessions", json=body)
    assert r1.json()["session_id"] == r2.json()["session_id"]
    assert r1.json()["shares"] is not None
    # Replay must not re-expose shares.
    assert r2.json()["shares"] is None
    assert r2.json()["replay"] is True


def test_idempotency_key_same_via_header(client):
    body = {"secret": "s", "threshold": 2, "total": 3}
    r1 = client.post(
        "/api/v1/sessions", json=body, headers={"Idempotency-Key": "hdr-1"}
    )
    r2 = client.post(
        "/api/v1/sessions", json=body, headers={"Idempotency-Key": "hdr-1"}
    )
    assert r1.json()["session_id"] == r2.json()["session_id"]


def test_idempotency_key_reuse_with_different_payload_conflicts(client):
    base = {"secret": "s", "threshold": 2, "total": 3, "idempotency_key": "k1"}
    client.post("/api/v1/sessions", json=base)
    changed = {**base, "secret": "different"}
    r = client.post("/api/v1/sessions", json=changed)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency_conflict"


def test_submit_idempotent_duplicate_in_request(client):
    data = create(client, t=2, n=3)
    sid = data["session_id"]
    r = client.post(
        f"/api/v1/sessions/{sid}/shares",
        json={"shares": [data["shares"][0], data["shares"][0]]},
    )
    body = r.json()
    assert [i["code"] for i in body["rejected"]] == ["duplicate_index_in_request"]
    assert body["accepted_indices"] == [1]


def test_session_not_found(client):
    assert client.get("/api/v1/sessions/deadbeef").status_code == 404
    assert (
        client.post(
            "/api/v1/sessions/deadbeef/shares", json={"shares": []}
        ).status_code
        in (404, 422)
    )


def test_threshold_validation(client):
    r = client.post(
        "/api/v1/sessions",
        json={"secret": "x", "threshold": 4, "total": 2},
    )
    assert r.status_code == 422


def test_key_size_limit(client):
    r = client.post(
        "/api/v1/sessions",
        json={
            "secret": "A" * (4097),
            "threshold": 2,
            "total": 3,
        },
    )
    assert r.status_code == 422


def test_body_size_limit(client):
    # A single ~2 MB share token must be rejected before parsing.
    r = client.post(
        "/api/v1/sessions/whatever/shares",
        content=json.dumps({"shares": ["A" * 2_000_000]}),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_hex_and_base64_roundtrip(client):
    raw = bytes(range(256))
    # hex
    d = create(client, secret=raw.hex(), encoding="hex", t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{d['session_id']}/shares",
        json={"shares": d["shares"][:2]},
    ).json()
    assert bytes.fromhex(r["key"]) == raw

    # base64
    b64 = base64.b64encode(raw).decode()
    d = create(client, secret=b64, encoding="base64", t=2, n=3)
    r = client.post(
        f"/api/v1/sessions/{d['session_id']}/shares",
        json={"shares": d["shares"][:2]},
    ).json()
    assert base64.b64decode(r["key"]) == raw


def test_database_contains_no_secret_or_share_bytes(client):
    secret = "DO-NOT-PERSIST-ME"
    data = create(client, secret=secret, t=2, n=3)
    sid = data["session_id"]
    client.post(
        f"/api/v1/sessions/{sid}/shares", json={"shares": data["shares"][:2]}
    )
    import sqlite3

    db_path = os.environ["DR_DB_PATH"]
    conn = sqlite3.connect(db_path)
    blob = b"\n".join(
        ("|".join(map(str, row))).encode()
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    )
    for table in ("sessions", "session_shares", "submitted_shares", "idempotency"):
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        text = json.dumps(rows, default=str)
        assert secret not in text
        for token in data["shares"]:
            assert token not in text
    assert blob  # tables exist


def _make_share(sid, x, y):
    from app.sharing import encode_share

    return encode_share(sid, x, y)


class TestRotation:
    def rotate(self, client, sid, shares, new_t=2, new_n=4, **extra):
        body = {"shares": shares, "new_threshold": new_t, "new_total": new_n}
        body.update(extra)
        return client.post(f"/api/v1/sessions/{sid}/rotate", json=body)

    def test_rotate_success_flow(self, client):
        secret = "rotate-me-🔑"
        old = create(client, secret=secret, t=3, n=5)
        old_id = old["session_id"]

        r = self.rotate(client, old_id, old["shares"][:3], new_t=2, new_n=4)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["old_session_id"] == old_id
        assert body["old_status"] == "rotated"
        assert body["status"] == "active"
        assert body["threshold"] == 2 and body["total_shares"] == 4
        assert body["shares_returned"] is True and body["replay"] is False
        assert len(body["shares"]) == 4
        new_id = body["session_id"]
        assert new_id != old_id

        # New shares are bound to the NEW session id.
        from app.sharing import decode_share

        for token in body["shares"]:
            assert decode_share(token)[0] == new_id

        # Old session is rotated and points at its replacement.
        info = client.get(f"/api/v1/sessions/{old_id}").json()
        assert info["status"] == "rotated"
        assert info["replacement_session_id"] == new_id
        assert info["rotated_at"] is not None

        # New session reconstructs the SAME key with the NEW threshold.
        r = client.post(
            f"/api/v1/sessions/{new_id}/shares",
            json={"shares": body["shares"][:2]},
        )
        assert r.json()["recovered"] is True
        assert r.json()["key"] == secret

    def test_rotated_old_session_rejects_recovery(self, client):
        old = create(client, t=3, n=5)
        old_id = old["session_id"]
        new_id = self.rotate(client, old_id, old["shares"][:3]).json()[
            "session_id"
        ]

        r = client.post(
            f"/api/v1/sessions/{old_id}/shares",
            json={"shares": old["shares"][:3]},
        )
        assert r.status_code == 409
        err = r.json()["error"]
        assert err["code"] == "session_rotated"
        assert err["details"]["replacement_session_id"] == new_id

    def test_rotate_with_tampered_share_aborts_without_side_effects(
        self, client
    ):
        old = create(client, secret="still-safe", t=3, n=5)
        old_id = old["session_id"]
        from app.sharing import decode_share, encode_share

        sid, x, y = decode_share(old["shares"][0])
        tampered = encode_share(sid, x, bytes([y[0] ^ 0xFF]) + y[1:])

        r = self.rotate(client, old_id, [tampered] + old["shares"][1:3])
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "share_verification_failed"

        # Failure must not change the old session nor create a new one.
        info = client.get(f"/api/v1/sessions/{old_id}").json()
        assert info["status"] == "active"
        assert info["replacement_session_id"] is None
        assert info["rotated_at"] is None
        # Old session still fully functional afterwards.
        r = client.post(
            f"/api/v1/sessions/{old_id}/shares",
            json={"shares": old["shares"][:3]},
        )
        assert r.json()["key"] == "still-safe"

    def test_rotate_insufficient_shares_aborts(self, client):
        old = create(client, t=3, n=5)
        old_id = old["session_id"]
        r = self.rotate(client, old_id, old["shares"][:2])
        assert r.status_code == 400
        err = r.json()["error"]
        assert err["code"] == "insufficient_shares"
        assert err["details"] == {"required": 3, "provided": 2}
        assert client.get(f"/api/v1/sessions/{old_id}").json()["status"] == (
            "active"
        )

    def test_rotate_idempotent_replay_returns_metadata_only(self, client):
        old = create(client, t=3, n=5)
        old_id = old["session_id"]
        body = {
            "shares": old["shares"][:3],
            "new_threshold": 2,
            "new_total": 4,
            "idempotency_key": "rot-key-1",
        }
        r1 = client.post(f"/api/v1/sessions/{old_id}/rotate", json=body)
        r2 = client.post(f"/api/v1/sessions/{old_id}/rotate", json=body)
        assert r1.status_code == 201 and r2.status_code == 201
        first, second = r1.json(), r2.json()
        assert first["session_id"] == second["session_id"]
        assert first["shares"] is not None
        # Replay exposes metadata only, never the shares again.
        assert second["shares"] is None
        assert second["shares_returned"] is False
        assert second["replay"] is True
        assert second["old_session_id"] == old_id

    def test_rotate_idempotency_key_via_header(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        body = {"shares": old["shares"][:2], "new_threshold": 2, "new_total": 3}
        r1 = client.post(
            f"/api/v1/sessions/{old_id}/rotate",
            json=body,
            headers={"Idempotency-Key": "rot-hdr-1"},
        )
        r2 = client.post(
            f"/api/v1/sessions/{old_id}/rotate",
            json=body,
            headers={"Idempotency-Key": "rot-hdr-1"},
        )
        assert r1.json()["session_id"] == r2.json()["session_id"]
        assert r2.json()["replay"] is True

    def test_rotate_idempotency_conflict_on_different_request(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        body = {
            "shares": old["shares"][:2],
            "new_threshold": 2,
            "new_total": 3,
            "idempotency_key": "rot-key-2",
        }
        assert client.post(
            f"/api/v1/sessions/{old_id}/rotate", json=body
        ).status_code == 201
        changed = {**body, "new_total": 5}
        r = client.post(f"/api/v1/sessions/{old_id}/rotate", json=changed)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "idempotency_conflict"

    def test_rotate_without_key_cannot_be_retried_after_success(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        r1 = self.rotate(client, old_id, old["shares"][:2])
        assert r1.status_code == 201
        # Same request again (no idempotency key): old session is terminal.
        r2 = self.rotate(client, old_id, old["shares"][:2])
        assert r2.status_code == 409
        err = r2.json()["error"]
        assert err["code"] == "session_rotated"
        assert err["details"]["replacement_session_id"] == r1.json()[
            "session_id"
        ]

    def test_rotate_revoked_session_rejected(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        client.post(f"/api/v1/sessions/{old_id}/revoke")
        r = self.rotate(client, old_id, old["shares"][:2])
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "session_revoked"

    def test_rotate_recovered_session_rejected(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        client.post(
            f"/api/v1/sessions/{old_id}/shares",
            json={"shares": old["shares"][:2]},
        )
        r = self.rotate(client, old_id, old["shares"][:2])
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "session_not_rotatable"

    def test_rotated_session_cannot_be_revoked(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        self.rotate(client, old_id, old["shares"][:2])
        r = client.post(f"/api/v1/sessions/{old_id}/revoke")
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "session_not_revocable"

    def test_rotate_not_found(self, client):
        r = self.rotate(client, "deadbeef", ["whatever"])
        assert r.status_code == 404

    def test_rotate_param_validation(self, client):
        old = create(client, t=2, n=3)
        old_id = old["session_id"]
        r = self.rotate(client, old_id, old["shares"][:2], new_t=4, new_n=2)
        assert r.status_code == 422
        r = self.rotate(client, old_id, old["shares"][:2], new_t=1, new_n=2)
        assert r.status_code == 422

    def test_rotation_chain(self, client):
        """A replacement session can itself be rotated again."""
        first = create(client, secret="chain-key", t=2, n=3)
        r1 = self.rotate(client, first["session_id"], first["shares"][:2])
        second = r1.json()
        r2 = self.rotate(client, second["session_id"], second["shares"][:2])
        assert r2.status_code == 201, r2.text
        third = r2.json()
        r = client.post(
            f"/api/v1/sessions/{third['session_id']}/shares",
            json={"shares": third["shares"][:2]},
        )
        assert r.json()["key"] == "chain-key"
        info = client.get(
            f"/api/v1/sessions/{second['session_id']}"
        ).json()
        assert info["status"] == "rotated"
        assert info["replacement_session_id"] == third["session_id"]


class TestRotationDatabase:
    def test_failed_rotation_leaves_no_trace(self, tmp_path):
        """DB-level: a rotation that fails mid-transaction rolls back fully."""
        from app.database import (
            Database,
            IdempotencyConflict,
            RotationStateError,
        )

        db = Database(str(tmp_path / "rot.db"))
        old_id, created = db.create_session(
            "old1",
            threshold=2,
            total_shares=3,
            key_digest="d",
            key_encoding="utf-8",
            key_length=1,
            share_checksums={1: "a", 2: "b", 3: "c"},
            idempotency_key=None,
            request_hash="h0",
        )
        assert created is True

        # Occupy an idempotency key with a different request hash.
        db.create_session(
            "other",
            threshold=2,
            total_shares=3,
            key_digest="d",
            key_encoding="utf-8",
            key_length=1,
            share_checksums={1: "a"},
            idempotency_key="busy-key",
            request_hash="hash-A",
        )

        # Rotation reusing the key with a different hash must fail atomically.
        try:
            db.rotate_session(
                old_id,
                "new1",
                threshold=2,
                total_shares=4,
                key_digest="d",
                key_encoding="utf-8",
                key_length=1,
                share_checksums={1: "x", 2: "y", 3: "z", 4: "w"},
                idempotency_key="busy-key",
                request_hash="hash-B",
            )
            raise AssertionError("expected IdempotencyConflict")
        except IdempotencyConflict:
            pass
        assert db.get_session(old_id)["status"] == "active"
        assert db.get_session("new1") is None

        # Rotating a non-active session raises and writes nothing.
        db.revoke_session(old_id)
        try:
            db.rotate_session(
                old_id,
                "new2",
                threshold=2,
                total_shares=4,
                key_digest="d",
                key_encoding="utf-8",
                key_length=1,
                share_checksums={1: "x", 2: "y", 3: "z", 4: "w"},
                idempotency_key=None,
                request_hash="h",
            )
            raise AssertionError("expected RotationStateError")
        except RotationStateError:
            pass
        assert db.get_session(old_id)["status"] == "revoked"
        assert db.get_session("new2") is None
        db.close()

    def test_successful_rotation_is_atomic_and_links_sessions(self, tmp_path):
        from app.database import Database

        db = Database(str(tmp_path / "rot2.db"))
        db.create_session(
            "old1",
            threshold=3,
            total_shares=5,
            key_digest="kd",
            key_encoding="hex",
            key_length=8,
            share_checksums={i: f"c{i}" for i in range(1, 6)},
            idempotency_key=None,
            request_hash="h0",
        )
        new_id, created = db.rotate_session(
            "old1",
            "new1",
            threshold=2,
            total_shares=4,
            key_digest="kd",
            key_encoding="hex",
            key_length=8,
            share_checksums={i: f"n{i}" for i in range(1, 5)},
            idempotency_key="rk",
            request_hash="rh",
        )
        assert (new_id, created) == ("new1", True)
        old = db.get_session("old1")
        assert old["status"] == "rotated"
        assert old["replacement_session_id"] == "new1"
        assert old["rotated_at"] is not None
        new = db.get_session("new1")
        assert new["status"] == "active"
        assert new["threshold"] == 2 and new["total_shares"] == 4
        assert new["key_digest"] == "kd"  # same key, re-sharded
        assert db.get_share_digest("new1", 4) == "n4"

        # Idempotent replay at the DB level returns the same replacement.
        again = db.rotate_session(
            "old1",
            "new-ignored",
            threshold=2,
            total_shares=4,
            key_digest="kd",
            key_encoding="hex",
            key_length=8,
            share_checksums={1: "z"},
            idempotency_key="rk",
            request_hash="rh",
        )
        assert again == ("new1", False)
        db.close()

    def test_concurrent_rotations_single_winner(self, tmp_path):
        """Racing rotations collapse to one; losers fail without side effects."""
        import threading

        from app.database import Database, RotationStateError

        db = Database(str(tmp_path / "race.db"))
        db.create_session(
            "old",
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
                    db.rotate_session(
                        "old",
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

        winners = [o for o in outcomes if o != "state-conflict"]
        assert len(winners) == 1 and winners[0][1] is True
        assert outcomes.count("state-conflict") == 7
        old = db.get_session("old")
        assert old["status"] == "rotated"
        assert old["replacement_session_id"] == winners[0][0]
        # Exactly one replacement session was persisted -- no orphans.
        for i in range(8):
            expected = 1 if f"new{i}" == winners[0][0] else 0
            assert (db.get_session(f"new{i}") is not None) == bool(expected)
        db.close()

    def test_existing_database_is_migrated(self, tmp_path):
        """A DB created with the pre-rotation schema gains the new columns."""
        import sqlite3

        path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE sessions ("
            "id TEXT PRIMARY KEY, threshold INTEGER NOT NULL, "
            "total_shares INTEGER NOT NULL, key_digest TEXT NOT NULL, "
            "key_encoding TEXT NOT NULL, key_length INTEGER NOT NULL, "
            "status TEXT NOT NULL DEFAULT 'active', recovered_at TEXT, "
            "revoked_at TEXT, created_at TEXT NOT NULL, "
            "recovery_attempts INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO sessions (id, threshold, total_shares, key_digest, "
            "key_encoding, key_length, created_at) "
            "VALUES ('legacy1', 2, 3, 'd', 'utf-8', 1, 'now')"
        )
        conn.commit()
        conn.close()

        from app.database import Database

        db = Database(path)  # must not raise; adds rotated_at etc.
        row = db.get_session("legacy1")
        assert row["status"] == "active"
        assert row["rotated_at"] is None
        assert row["replacement_session_id"] is None
        db.close()


class TestApiKeyAuth:
    @pytest.fixture()
    def authed_client(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DR_DB_PATH", str(tmp_path / "auth.db"))
        monkeypatch.setenv("DR_API_KEY", "secret-token")
        import app.main as main

        importlib.reload(main)
        with TestClient(main.app) as c:
            yield c

    def test_health_open(self, authed_client):
        assert authed_client.get("/health").status_code == 200

    def test_missing_key_rejected(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
        )
        assert r.status_code == 401

    def test_wrong_key_rejected(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
            headers={"X-API-Key": "nope"},
        )
        assert r.status_code == 401

    def test_correct_key_accepted(self, authed_client):
        r = authed_client.post(
            "/api/v1/sessions",
            json={"secret": "x", "threshold": 2, "total": 3},
            headers={"X-API-Key": "secret-token"},
        )
        assert r.status_code == 201


def test_concurrent_idempotent_creates_single_session(client):
    """Parallel requests sharing one idempotency key collapse to one session."""
    import threading
    import uuid

    from app.database import sha256_hex

    database = client.app.state.db
    key = "race-" + uuid.uuid4().hex
    request_hash = sha256_hex(b"req")
    outcomes = []
    barrier = threading.Barrier(8)

    def worker():
        sid = uuid.uuid4().hex
        barrier.wait()
        try:
            outcomes.append(
                database.create_session(
                    sid,
                    threshold=2,
                    total_shares=3,
                    key_digest="d",
                    key_encoding="utf-8",
                    key_length=1,
                    share_checksums={1: "a", 2: "b", 3: "c"},
                    idempotency_key=key,
                    request_hash=request_hash,
                )
            )
        except Exception as exc:  # pragma: no cover - failure path
            outcomes.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not any(isinstance(o, Exception) for o in outcomes), outcomes
    session_ids = {o[0] for o in outcomes}
    assert len(session_ids) == 1
    assert sum(1 for o in outcomes if o[1]) == 1  # exactly one created_now
