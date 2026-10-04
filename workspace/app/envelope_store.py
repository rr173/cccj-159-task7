"""设计签名封装服务的 SQLite 与分块对象存储。"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


SCHEMA = """
CREATE TABLE IF NOT EXISTS envelope_session (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('OPEN','READY','SEALED','PUBLISHED','ABORTED')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    prepared_at TEXT,
    sealed_at TEXT,
    parent_envelope_id TEXT,
    required_roles_json TEXT NOT NULL DEFAULT '[]',
    release_metadata_json TEXT NOT NULL DEFAULT '{}',
    content_hash TEXT,
    envelope_id TEXT,
    prepare_attempt INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_content ON envelope_session(content_hash);
CREATE INDEX IF NOT EXISTS idx_session_state ON envelope_session(state);

CREATE TABLE IF NOT EXISTS session_artifact (
    session_id TEXT NOT NULL,
    slot TEXT NOT NULL,
    kind TEXT NOT NULL,
    position INTEGER NOT NULL,
    upload_id TEXT,
    blob_id TEXT,
    size INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(session_id, slot)
);

CREATE TABLE IF NOT EXISTS upload (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    slot TEXT NOT NULL,
    kind TEXT NOT NULL,
    chunk_size INTEGER NOT NULL,
    total_size INTEGER,
    state TEXT NOT NULL CHECK(state IN ('UPLOADING','READY','ABORTED')),
    blob_id TEXT,
    content_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(session_id, slot)
);

CREATE TABLE IF NOT EXISTS upload_chunk (
    upload_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY(upload_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS blob (
    id TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelope (
    id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS envelope_leaf (
    envelope_id TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    leaf_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    PRIMARY KEY(envelope_id, leaf_index)
);

CREATE TABLE IF NOT EXISTS envelope_signature (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    signer TEXT NOT NULL,
    role TEXT NOT NULL,
    signature TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(envelope_id, kid)
);

CREATE TABLE IF NOT EXISTS signer_key_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kid TEXT NOT NULL,
    event TEXT NOT NULL,
    signer TEXT,
    role TEXT,
    public_key TEXT,
    at TEXT NOT NULL,
    root_kid TEXT NOT NULL,
    signature TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_signer_event_kid ON signer_key_event(kid, seq);

CREATE TABLE IF NOT EXISTS root_key (
    kid TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    private_seed TEXT,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE','ROTATED','REVOKED')),
    created_at TEXT NOT NULL,
    activated_at TEXT NOT NULL,
    rotated_at TEXT,
    replaced_by_kid TEXT
);

CREATE TABLE IF NOT EXISTS root_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    root_kid TEXT NOT NULL,
    public_key TEXT,
    at TEXT NOT NULL,
    signer_kid TEXT NOT NULL,
    signature TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS publication (
    name TEXT PRIMARY KEY,
    envelope_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PUBLISHING','PUBLISHED')),
    published_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    release_path TEXT,
    release_hash TEXT
);

CREATE TABLE IF NOT EXISTS envelope_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    entity TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_envelope_audit_entity ON envelope_audit(entity, seq);

CREATE TABLE IF NOT EXISTS envelope_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


class EnvelopeStore:
    def __init__(self, db_path: str = ":memory:", blob_dir: str | None = None, seed: bool = True):
        self.db_path = db_path
        if db_path == ":memory:":
            default_root = Path.cwd() / ".envelope-blobs"
        else:
            default_root = Path(db_path).resolve().parent / "blobs"
        self.blob_dir = Path(blob_dir) if blob_dir else default_root
        (self.blob_dir / "tmp").mkdir(parents=True, exist_ok=True)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        self.conn.executescript(SCHEMA)
        if seed:
            self._ensure_root()

    class _Tx:
        def __init__(self, conn, lock):
            self.conn = conn
            self.lock = lock

        def __enter__(self):
            self.lock.acquire()
            self.conn.execute("BEGIN IMMEDIATE")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.conn.execute("COMMIT")
            else:
                self.conn.execute("ROLLBACK")
            self.lock.release()
            return False

    def tx(self):
        return self._Tx(self.conn, self.lock)

    def q_one(self, sql: str, args=()):
        return self.conn.execute(sql, args).fetchone()

    def q_all(self, sql: str, args=()):
        return self.conn.execute(sql, args).fetchall()

    def blob_path(self, blob_id: str) -> Path:
        return self.blob_dir / blob_id[:2] / blob_id[2:4] / blob_id

    def tmp_path(self, name: str) -> Path:
        p = self.blob_dir / "tmp" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_blob(self, blob_id: str, data: bytes) -> str:
        p = self.blob_path(blob_id)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.tmp_path(f"{blob_id}.{os.getpid()}.tmp")
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        return str(p)

    def append_chunk_file(self, upload_id: str, index: int, data: bytes) -> tuple[str, str]:
        import hashlib
        chunk_hash = hashlib.sha256(data).hexdigest()
        p = self.blob_path(chunk_hash)
        if not p.exists():
            self.write_blob(chunk_hash, data)
        return chunk_hash, str(p)

    def read_blob(self, blob_id: str) -> bytes:
        return self.blob_path(blob_id).read_bytes()

    def audit(self, action: str, entity=None, actor=None, result="OK", reason=None, detail=None):
        with self.tx() as c:
            c.execute(
                "INSERT INTO envelope_audit(at,actor,action,entity,result,reason,detail_json)"
                " VALUES(?,?,?,?,?,?,?)",
                (utcnow(), actor, action, entity, result, reason,
                 json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)))

    def _ensure_root(self):
        from . import ed25519
        row = self.q_one("SELECT kid FROM root_key WHERE status='ACTIVE'")
        if row:
            return row["kid"]
        import hashlib
        import secrets
        seed = secrets.token_bytes(32)
        pub = ed25519.public_key(seed)
        kid = "root-" + hashlib.sha256(pub).hexdigest()[:16]
        now = utcnow()
        genesis = {
            "schema": "design-envelope-root/1", "event": "GENESIS", "kid": kid,
            "version": 1, "public_key": pub.hex(), "at": now,
        }
        sig = ed25519.sign(seed, canonical_bytes(genesis)).hex()
        with self.tx() as c:
            c.execute(
                "INSERT INTO root_key(kid,version,public_key,private_seed,status,created_at,"
                "activated_at) VALUES(?,?,?,?,?,?,?)",
                (kid, 1, pub.hex(), seed.hex(), "ACTIVE", now, now))
            c.execute(
                "INSERT INTO root_event(event,root_kid,public_key,at,signer_kid,signature,"
                "detail_json) VALUES('GENESIS',?,?,?,?,?,?)",
                (kid, pub.hex(), now, kid, sig, "{}"))
        return kid

    def active_root(self):
        return self.q_one("SELECT * FROM root_key WHERE status='ACTIVE'")

    def reset(self):
        with self.tx() as c:
            for t in ["envelope_audit", "publication", "root_event", "root_key",
                      "signer_key_event", "envelope_signature", "envelope_leaf", "envelope",
                      "upload_chunk", "upload", "session_artifact", "envelope_session",
                      "envelope_meta"]:
                c.execute(f"DELETE FROM {t}")
        self._ensure_root()


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()
