"""FastAPI application: Shamir-secret-sharded disaster-recovery key service."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field

from . import sharing
from .database import (
    Database,
    IdempotencyConflict,
    RotationStateError,
    row_to_dict,
    share_digest,
)

DB_PATH = os.environ.get("DR_DB_PATH", os.path.join("data", "sss.db"))
# When set, every /api/v1 call must present it in the X-API-Key header.
API_KEY = os.environ.get("DR_API_KEY") or None

MAX_KEY_BYTES = 4096
MAX_REQUEST_BODY_BYTES = 1024 * 1024  # generous bound: 255 shares of 4 KiB each


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def decode_key(raw: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        data = raw.encode("utf-8")
    elif encoding == "hex":
        try:
            data = bytes.fromhex(raw)
        except ValueError as exc:
            raise HTTPException(422, "key is not valid hexadecimal") from exc
    else:  # base64
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(422, "key is not valid base64") from exc
    if not data:
        raise HTTPException(422, "key must not be empty")
    if len(data) > MAX_KEY_BYTES:
        raise HTTPException(422, f"key must not exceed {MAX_KEY_BYTES} bytes")
    return data


def encode_key(data: bytes, encoding: str) -> str:
    if encoding == "utf-8":
        return data.decode("utf-8")
    if encoding == "hex":
        return data.hex()
    return base64.b64encode(data).decode("ascii")


def error(code: str, message: str, http_status: int, details=None) -> HTTPException:
    return HTTPException(
        status_code=http_status,
        detail={"code": code, "message": message, "details": details},
    )


def verify_share_tokens(
    database: Database, session_id: str, row, tokens: list[str]
) -> tuple[dict[int, bytes], list[dict]]:
    """Integrity-check every submitted share token against stored digests.

    Returns ``(valid, rejected)``: ``valid`` maps share index -> share bytes
    (only fully authenticated shares), ``rejected`` lists ``{"index", "code"}``
    entries. A rejected share never participates in interpolation, so it
    cannot influence (or leak) the recovered key.
    """
    valid: dict[int, bytes] = {}
    rejected: list[dict] = []
    seen: set[int] = set()
    for token in tokens:
        if not isinstance(token, str) or len(token) > 8192:
            rejected.append({"index": 0, "code": "malformed_share"})
            continue
        try:
            token_session, x, y = sharing.decode_share(token)
        except ValueError:
            rejected.append({"index": 0, "code": "malformed_share"})
            continue
        if not hmac.compare_digest(token_session, session_id):
            # Do not reveal which session the share belongs to.
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        if x in seen:
            rejected.append({"index": x, "code": "duplicate_index_in_request"})
            continue
        seen.add(x)

        digest = database.get_share_digest(session_id, x)
        actual = share_digest(session_id, x, y)
        if len(y) != row["key_length"]:
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        if digest is None or not hmac.compare_digest(digest, actual):
            rejected.append({"index": x, "code": "integrity_check_failed"})
            continue
        valid[x] = y
    return valid, rejected


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

class CreateSessionRequest(BaseModel):
    secret: str = Field(..., min_length=1, description="Key to shard")
    encoding: Literal["utf-8", "hex", "base64"] = "utf-8"
    threshold: int = Field(..., ge=2, le=255)
    total: int = Field(..., ge=2, le=255)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)


class SubmitSharesRequest(BaseModel):
    shares: list[str] = Field(..., min_length=1, max_length=255)


class RotateSessionRequest(BaseModel):
    shares: list[str] = Field(
        ..., min_length=1, max_length=255,
        description="Verified shares of the CURRENT session, >= old threshold",
    )
    new_threshold: int = Field(..., ge=2, le=255)
    new_total: int = Field(..., ge=2, le=255)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)


# --------------------------------------------------------------------------
# Lifespan / app
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = Database(DB_PATH)
    try:
        yield
    finally:
        app.state.db.close()


app = FastAPI(
    title="Disaster Recovery Key Sharding API",
    version="1.0.0",
    description="Shard recovery keys with Shamir's threshold scheme and "
    "reconstruct them only from integrity-verified shares.",
    lifespan=lifespan,
)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.headers.get("content-length"):
            try:
                size = int(request.headers["content-length"])
            except ValueError:
                size = 0
            if size > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "payload_too_large",
                            "message": "request body exceeds limit",
                            "details": {"max_bytes": MAX_REQUEST_BODY_BYTES},
                        }
                    },
                )
        return await call_next(request)


app.add_middleware(BodySizeLimitMiddleware)


def db(request: Request) -> Database:
    return request.app.state.db


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY is not None and not (
        x_api_key is not None and hmac.compare_digest(x_api_key, API_KEY)
    ):
        raise error("unauthorized", "missing or invalid API key", 401)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        body = detail
    else:
        body = {"code": "error", "message": str(detail), "details": None}
    return JSONResponse(status_code=exc.status_code, content={"error": body})


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.post(
    "/api/v1/sessions",
    tags=["sessions"],
    status_code=201,
    dependencies=[Depends(require_api_key)],
)
def create_session(
    payload: CreateSessionRequest,
    database: Database = Depends(db),
    idempotency_key: str | None = Header(default=None),
):
    """Create a recovery session. Shares are returned exactly once."""
    if payload.total < payload.threshold:
        raise error(
            "invalid_parameters",
            "total must be greater than or equal to threshold",
            422,
        )

    key = decode_key(payload.secret, payload.encoding)
    key_digest = hashlib.sha256(key).hexdigest()

    idem = payload.idempotency_key or idempotency_key
    request_hash = hashlib.sha256(
        key_digest.encode("ascii")
        + f"|{payload.threshold}|{payload.total}|{payload.encoding}".encode()
    ).hexdigest()

    session_id = uuid.uuid4().hex
    # Split before insert so a malformed key never creates a session row.
    pairs = sharing.split_secret(key, payload.threshold, payload.total)
    checksums = {x: share_digest(session_id, x, y) for x, y in pairs}

    try:
        stored_id, created_now = database.create_session(
            session_id,
            threshold=payload.threshold,
            total_shares=payload.total,
            key_digest=key_digest,
            key_encoding=payload.encoding,
            key_length=len(key),
            share_checksums=checksums,
            idempotency_key=idem,
            request_hash=request_hash,
        )
    except IdempotencyConflict:
        raise error(
            "idempotency_conflict",
            "idempotency key was already used with a different request",
            409,
        )

    if not created_now:
        # Replay: shares were issued in the original call and must never be
        # returned again. Return the session metadata instead.
        row = database.get_session(stored_id)
        return {
            "session_id": stored_id,
            "status": row["status"],
            "threshold": row["threshold"],
            "total_shares": row["total_shares"],
            "shares": None,
            "shares_returned": False,
            "replay": True,
            "message": "session already created; shares were returned once "
            "in the original response and cannot be retrieved again",
        }

    # Map computed shares to the actual stored id (they are the same id here).
    tokens = [sharing.encode_share(session_id, x, y) for x, y in pairs]
    return {
        "session_id": session_id,
        "status": "active",
        "threshold": payload.threshold,
        "total_shares": payload.total,
        "shares": tokens,
        "share_checksums": [
            {"index": x, "digest": checksums[x]} for x, _ in pairs
        ],
        "shares_returned": True,
        "replay": False,
        "message": "store these shares securely; they are shown only once",
    }


@app.get(
    "/api/v1/sessions/{session_id}",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def get_session(session_id: str, database: Database = Depends(db)):
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    data = row_to_dict(row)
    submitted = database.submitted_indices(session_id)
    return {
        "session_id": data["id"],
        "status": data["status"],
        "threshold": data["threshold"],
        "total_shares": data["total_shares"],
        "key_digest": data["key_digest"],
        "submitted_share_indices": submitted,
        "submitted_count": len(submitted),
        "recovery_attempts": data["recovery_attempts"],
        "created_at": data["created_at"],
        "recovered_at": data["recovered_at"],
        "revoked_at": data["revoked_at"],
        "rotated_at": data["rotated_at"],
        "replacement_session_id": data["replacement_session_id"],
    }


@app.post(
    "/api/v1/sessions/{session_id}/shares",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def submit_shares(
    session_id: str,
    payload: SubmitSharesRequest,
    database: Database = Depends(db),
):
    """Verify every share's integrity, then reconstruct if threshold is met.

    A bad share is reported as rejected and never participates in
    interpolation, so it cannot influence (or leak) the recovered key.
    """
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    if row["status"] == "revoked":
        raise error("session_revoked", "session has been revoked", 409)
    if row["status"] == "rotated":
        raise error(
            "session_rotated",
            "session has been rotated; recovery is permanently disabled, "
            "use the replacement session",
            409,
            details={"replacement_session_id": row["replacement_session_id"]},
        )
    if row["status"] == "recovered":
        return {
            "session_id": session_id,
            "status": "recovered",
            "recovered": True,
            "key": None,
            "replay": True,
            "message": "key was already returned once and is not shown again",
            "accepted_indices": [],
            "rejected": [],
        }

    threshold = row["threshold"]
    valid, rejected = verify_share_tokens(database, session_id, row, payload.shares)

    if rejected:
        database.bump_attempt(session_id)

    for x in valid:
        database.mark_submitted(session_id, x)

    submitted_indices = database.submitted_indices(session_id)

    if len(valid) < threshold:
        return {
            "session_id": session_id,
            "status": "active",
            "recovered": False,
            "key": None,
            "replay": False,
            "accepted_indices": sorted(valid),
            "rejected": rejected,
            "submitted_count": len(submitted_indices),
            "shares_required": threshold - len(valid),
            "message": "not yet enough verified shares; resend all required "
            "shares together in a single request",
        }

    # Every point in `valid` is individually authenticated against the stored
    # digest, so interpolation operates only on genuine shares.
    chosen = sorted(valid.items())[:threshold]
    recovered = sharing.reconstruct_secret(
        [(x, y) for x, y in chosen]
    )
    recovered_digest = hashlib.sha256(recovered).hexdigest()
    if not hmac.compare_digest(recovered_digest, row["key_digest"]):
        # Defence in depth: cannot happen with t valid shares, but never
        # return a value whose checksum does not match.
        database.bump_attempt(session_id)
        raise error(
            "recovery_failed",
            "reconstructed key failed checksum verification",
            400,
        )

    database.mark_recovered(session_id)
    encoding = row["key_encoding"]
    try:
        key_text = encode_key(recovered, encoding)
    except UnicodeDecodeError:
        # Key bytes were not originally UTF-8 text (encoding stored wrongly);
        # fall back to hex so no data is lost.
        key_text = recovered.hex()
        encoding = "hex"

    return {
        "session_id": session_id,
        "status": "recovered",
        "recovered": True,
        "key": key_text,
        "key_encoding": encoding,
        "key_digest": recovered_digest,
        "replay": False,
        "accepted_indices": sorted(valid),
        "rejected": rejected,
        "message": "key is shown exactly once; store it securely",
    }


@app.post(
    "/api/v1/sessions/{session_id}/revoke",
    tags=["sessions"],
    dependencies=[Depends(require_api_key)],
)
def revoke_session(session_id: str, database: Database = Depends(db)):
    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    if row["status"] == "recovered":
        raise error(
            "session_not_revocable",
            "a recovered session cannot be revoked",
            409,
        )
    if row["status"] == "rotated":
        raise error(
            "session_not_revocable",
            "a rotated session is already terminal and cannot be revoked",
            409,
        )
    changed = database.revoke_session(session_id)
    row = database.get_session(session_id)
    return {
        "session_id": session_id,
        "status": row["status"],
        "revoked": row["status"] == "revoked",
        "revoked_at": row["revoked_at"],
        "replay": not changed,
    }


def _rotation_replay_response(old_session_id: str, new_row) -> dict:
    """Metadata-only answer for an idempotent rotation replay (no shares)."""
    return {
        "old_session_id": old_session_id,
        "old_status": "rotated",
        "session_id": new_row["id"],
        "status": new_row["status"],
        "threshold": new_row["threshold"],
        "total_shares": new_row["total_shares"],
        "shares": None,
        "shares_returned": False,
        "replay": True,
        "message": "rotation already performed; the new shares were returned "
        "once in the original response and cannot be retrieved again",
    }


@app.post(
    "/api/v1/sessions/{session_id}/rotate",
    tags=["sessions"],
    status_code=201,
    dependencies=[Depends(require_api_key)],
)
def rotate_session(
    session_id: str,
    payload: RotateSessionRequest,
    database: Database = Depends(db),
    idempotency_key: str | None = Header(default=None),
):
    """Re-shard the key of an active session under a new (threshold, total).

    The caller proves possession of the key by submitting at least the old
    threshold of integrity-verified shares. In a single transaction the old
    session is marked ``rotated`` (recovery permanently disabled) and the
    replacement session is created; its shares are returned exactly once.
    A failed rotation changes nothing.
    """
    if payload.new_total < payload.new_threshold:
        raise error(
            "invalid_parameters",
            "new_total must be greater than or equal to new_threshold",
            422,
        )

    idem = payload.idempotency_key or idempotency_key
    shares_hash = hashlib.sha256(
        "\n".join(payload.shares).encode("utf-8")
    ).hexdigest()
    request_hash = hashlib.sha256(
        f"rotate|{session_id}|{payload.new_threshold}|{payload.new_total}"
        f"|{shares_hash}".encode("ascii")
    ).hexdigest()

    # Idempotent replay: same key + same request -> metadata of the
    # replacement session only; same key + different request -> conflict.
    # (Re-checked inside the write transaction to close the race.)
    if idem is not None:
        existing = database.get_idempotency_record(idem)
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise error(
                    "idempotency_conflict",
                    "idempotency key was already used with a different request",
                    409,
                )
            new_row = database.get_session(existing["session_id"])
            return _rotation_replay_response(session_id, new_row)

    row = database.get_session(session_id)
    if row is None:
        raise error("session_not_found", "recovery session does not exist", 404)
    if row["status"] == "revoked":
        raise error("session_revoked", "session has been revoked", 409)
    if row["status"] == "rotated":
        raise error(
            "session_rotated",
            "session was already rotated",
            409,
            details={"replacement_session_id": row["replacement_session_id"]},
        )
    if row["status"] != "active":
        raise error(
            "session_not_rotatable",
            f"a {row['status']} session cannot be rotated",
            409,
        )

    # Every submitted share must pass integrity verification, and there must
    # be at least the old threshold of them. Any failure here is checked
    # before a single write, so the old session is left untouched.
    valid, rejected = verify_share_tokens(
        database, session_id, row, payload.shares
    )
    if rejected:
        raise error(
            "share_verification_failed",
            "every submitted share must pass integrity verification; "
            "rotation aborted and no state was changed",
            400,
            details={"rejected": rejected},
        )
    if len(valid) < row["threshold"]:
        raise error(
            "insufficient_shares",
            "fewer verified shares than the current threshold; "
            "rotation aborted and no state was changed",
            400,
            details={
                "required": row["threshold"],
                "provided": len(valid),
            },
        )

    # All points are individually authenticated, so interpolation only ever
    # runs on genuine shares of this session.
    chosen = sorted(valid.items())[: row["threshold"]]
    key = sharing.reconstruct_secret([(x, y) for x, y in chosen])
    if not hmac.compare_digest(
        hashlib.sha256(key).hexdigest(), row["key_digest"]
    ):
        # Defence in depth: cannot happen with t valid shares, but never
        # rotate on a value whose checksum does not match.
        raise error(
            "rotation_verification_failed",
            "reconstructed key failed checksum verification; "
            "rotation aborted and no state was changed",
            400,
        )

    new_session_id = uuid.uuid4().hex
    # Split before the transaction so a failure here cannot touch state.
    pairs = sharing.split_secret(key, payload.new_threshold, payload.new_total)
    checksums = {x: share_digest(new_session_id, x, y) for x, y in pairs}

    try:
        stored_id, created_now = database.rotate_session(
            session_id,
            new_session_id,
            threshold=payload.new_threshold,
            total_shares=payload.new_total,
            key_digest=row["key_digest"],
            key_encoding=row["key_encoding"],
            key_length=row["key_length"],
            share_checksums=checksums,
            idempotency_key=idem,
            request_hash=request_hash,
        )
    except IdempotencyConflict:
        raise error(
            "idempotency_conflict",
            "idempotency key was already used with a different request",
            409,
        )
    except RotationStateError:
        raise error(
            "session_not_rotatable",
            "session state changed concurrently; rotation aborted and no "
            "state was changed",
            409,
        )

    if not created_now:
        # Concurrent request with the same idempotency key committed first.
        new_row = database.get_session(stored_id)
        return _rotation_replay_response(session_id, new_row)

    tokens = [sharing.encode_share(new_session_id, x, y) for x, y in pairs]
    return {
        "old_session_id": session_id,
        "old_status": "rotated",
        "session_id": new_session_id,
        "status": "active",
        "threshold": payload.new_threshold,
        "total_shares": payload.new_total,
        "shares": tokens,
        "share_checksums": [
            {"index": x, "digest": checksums[x]} for x, _ in pairs
        ],
        "shares_returned": True,
        "replay": False,
        "message": "old session is now rotated and rejects all recovery; "
        "store the new shares securely, they are shown only once",
    }
