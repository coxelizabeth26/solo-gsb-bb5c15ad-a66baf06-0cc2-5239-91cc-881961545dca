"""SQLite persistence layer.

A single connection guarded by a process-level lock is enough for the workload
and makes "check then insert" transactions safe under uvicorn threads.
Checksums (SHA-256) of individual shares and of the key are stored -- never the
key itself and never raw share bytes.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id                      TEXT PRIMARY KEY,
    threshold               INTEGER NOT NULL,
    total_shares            INTEGER NOT NULL,
    key_digest              TEXT NOT NULL,
    key_encoding            TEXT NOT NULL,
    key_length              INTEGER NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active',
    recovered_at            TEXT,
    revoked_at              TEXT,
    rotated_at              TEXT,
    replacement_session_id  TEXT,
    created_at              TEXT NOT NULL,
    recovery_attempts       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS session_shares (
    session_id  TEXT NOT NULL,
    share_index INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    PRIMARY KEY (session_id, share_index),
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

CREATE TABLE IF NOT EXISTS submitted_shares (
    session_id  TEXT NOT NULL,
    share_index INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (session_id, share_index),
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

CREATE TABLE IF NOT EXISTS idempotency (
    idempotency_key  TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    request_hash     TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def share_digest(session_id: str, x: int, y: bytes) -> str:
    """Digest bound to the session so a share cannot be moved between sessions."""
    return sha256_hex(session_id.encode("ascii") + bytes([x]) + b"|" + y)


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after the first release to existing DBs."""
        cols = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(sessions)")
        }
        for column, ddl in (
            ("rotated_at", "ALTER TABLE sessions ADD COLUMN rotated_at TEXT"),
            (
                "replacement_session_id",
                "ALTER TABLE sessions ADD COLUMN replacement_session_id TEXT",
            ),
        ):
            if column not in cols:
                self._conn.execute(ddl)

    @contextmanager
    def _transaction(self):
        """Explicit BEGIN IMMEDIATE/COMMIT/ROLLBACK around multiple writes.

        The connection runs with isolation_level=None (autocommit), so the
        ``with conn:`` context manager alone would NOT roll back earlier
        statements -- each one would commit on its own. Real atomicity for
        multi-statement writes therefore needs an explicit transaction.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- sessions -------------------------------------------------------

    def create_session(
        self,
        session_id: str,
        *,
        threshold: int,
        total_shares: int,
        key_digest: str,
        key_encoding: str,
        key_length: int,
        share_checksums: dict[int, str],
        idempotency_key: str | None,
        request_hash: str,
    ) -> tuple[str, bool]:
        """Insert a session. Returns (session_id, created_now).

        With an idempotency key a repeated request returns the original
        session id with created_now=False (shares must not be re-returned).
        """
        with self._lock, self._transaction():
            if idempotency_key is not None:
                row = self._conn.execute(
                    "SELECT session_id, request_hash FROM idempotency "
                    "WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if row is not None:
                    if row["request_hash"] != request_hash:
                        raise IdempotencyConflict()
                    return row["session_id"], False

            self._conn.execute(
                "INSERT INTO sessions (id, threshold, total_shares, key_digest, "
                "key_encoding, key_length, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
                (
                    session_id,
                    threshold,
                    total_shares,
                    key_digest,
                    key_encoding,
                    key_length,
                    utcnow(),
                ),
            )
            self._conn.executemany(
                "INSERT INTO session_shares (session_id, share_index, digest) "
                "VALUES (?, ?, ?)",
                [
                    (session_id, idx, digest)
                    for idx, digest in sorted(share_checksums.items())
                ],
            )
            if idempotency_key is not None:
                self._conn.execute(
                    "INSERT INTO idempotency (idempotency_key, session_id, "
                    "request_hash, created_at) VALUES (?, ?, ?, ?)",
                    (idempotency_key, session_id, request_hash, utcnow()),
                )
        return session_id, True

    def get_session(self, session_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()

    def get_idempotency_record(self, idempotency_key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT session_id, request_hash FROM idempotency "
                "WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()

    def rotate_session(
        self,
        old_session_id: str,
        new_session_id: str,
        *,
        threshold: int,
        total_shares: int,
        key_digest: str,
        key_encoding: str,
        key_length: int,
        share_checksums: dict[int, str],
        idempotency_key: str | None,
        request_hash: str,
    ) -> tuple[str, bool]:
        """Atomically create the replacement session and rotate the old one.

        Single transaction: mark ``old_session_id`` rotated (only if still
        active), insert the new session with its share checksums, and record
        the idempotency key. Any failure rolls everything back, so a failed
        rotation never changes the old session nor leaves a new one behind.

        Returns (new_session_id, created_now); with a replayed idempotency
        key returns the previously created replacement id and False.
        """
        with self._lock, self._transaction():
            if idempotency_key is not None:
                row = self._conn.execute(
                    "SELECT session_id, request_hash FROM idempotency "
                    "WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if row is not None:
                    if row["request_hash"] != request_hash:
                        raise IdempotencyConflict()
                    return row["session_id"], False

            cur = self._conn.execute(
                "UPDATE sessions SET status = 'rotated', rotated_at = ?, "
                "replacement_session_id = ? "
                "WHERE id = ? AND status = 'active'",
                (utcnow(), new_session_id, old_session_id),
            )
            if cur.rowcount != 1:
                # Concurrent recovery/revoke/rotation won the race; abort so
                # the caller can re-read the state. Nothing was written.
                raise RotationStateError()

            self._conn.execute(
                "INSERT INTO sessions (id, threshold, total_shares, key_digest, "
                "key_encoding, key_length, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
                (
                    new_session_id,
                    threshold,
                    total_shares,
                    key_digest,
                    key_encoding,
                    key_length,
                    utcnow(),
                ),
            )
            self._conn.executemany(
                "INSERT INTO session_shares (session_id, share_index, digest) "
                "VALUES (?, ?, ?)",
                [
                    (new_session_id, idx, digest)
                    for idx, digest in sorted(share_checksums.items())
                ],
            )
            if idempotency_key is not None:
                self._conn.execute(
                    "INSERT INTO idempotency (idempotency_key, session_id, "
                    "request_hash, created_at) VALUES (?, ?, ?, ?)",
                    (idempotency_key, new_session_id, request_hash, utcnow()),
                )
        return new_session_id, True

    def get_share_digest(self, session_id: str, x: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT digest FROM session_shares WHERE session_id = ? "
                "AND share_index = ?",
                (session_id, x),
            ).fetchone()
        return row["digest"] if row else None

    def submitted_indices(self, session_id: str) -> list[int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT share_index FROM submitted_shares WHERE session_id = ? "
                "ORDER BY share_index",
                (session_id,),
            ).fetchall()
        return [r["share_index"] for r in rows]

    def mark_submitted(self, session_id: str, x: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO submitted_shares "
                "(session_id, share_index, created_at) VALUES (?, ?, ?)",
                (session_id, x, utcnow()),
            )

    def bump_attempt(self, session_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE sessions SET recovery_attempts = recovery_attempts + 1 "
                "WHERE id = ?",
                (session_id,),
            )

    def mark_recovered(self, session_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE sessions SET status = 'recovered', recovered_at = ? "
                "WHERE id = ? AND status = 'active'",
                (utcnow(), session_id),
            )

    def revoke_session(self, session_id: str) -> bool:
        """Idempotent revoke. Returns True if revoked by this call."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE sessions SET status = 'revoked', revoked_at = ? "
                "WHERE id = ? AND status = 'active'",
                (utcnow(), session_id),
            )
            return cur.rowcount == 1


class IdempotencyConflict(Exception):
    """An idempotency key was reused with a different request payload."""


class RotationStateError(Exception):
    """The old session left the active state while rotation was committing."""


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)
