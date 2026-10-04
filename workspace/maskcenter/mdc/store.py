"""持久化层：SQLite schema、连接管理与内容寻址存储（CAS）。

零第三方依赖，仅用标准库。所有业务状态都在这一个库文件里，
进程异常退出后重启即从表内状态恢复未完成的打包/资源裁决。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1


def utcnow() -> str:
    """单调可字典序比较的 ISO-8601 UTC 时间。"""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


SCHEMA = """
-- ---------------------------------------------------------------- 人员
CREATE TABLE IF NOT EXISTS person (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    roles     TEXT NOT NULL DEFAULT '[]'   -- ["ME","STEWARD","DISPATCHER"]
);

-- ---------------------------------------------------------------- 构件登记（逻辑名唯一）
CREATE TABLE IF NOT EXISTS artifact (
    sha256      TEXT PRIMARY KEY,           -- 内容寻址；同内容天然去重
    logical_name TEXT NOT NULL COLLATE BINARY,
    kind        TEXT NOT NULL,              -- GDS / OASIS / LAYERMAP / RECIPE / OTHER
    size        INTEGER NOT NULL,
    imported_at TEXT NOT NULL,
    imported_by TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'ACTIVE'  -- ACTIVE / QUARANTINED / REJECTED
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifact_name ON artifact(logical_name) WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS artifact_alias (
    logical_name TEXT NOT NULL COLLATE BINARY,
    sha256       TEXT NOT NULL,
    PRIMARY KEY(logical_name, sha256)
);

-- 同名异物隔离区（唯一索引允许同 (name,sha256) 重复导入折叠为一条）
CREATE TABLE IF NOT EXISTS quarantine (
    id          TEXT PRIMARY KEY,
    logical_name TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    existing_sha TEXT,
    kind        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    blob_path   TEXT NOT NULL,              -- CAS 中实际落盘位置
    detected_by TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'PENDING', -- PENDING / ACCEPTED_AS_ALIAS / REJECTED
    resolved_by TEXT,
    resolved_at TEXT,
    UNIQUE(logical_name, sha256)
);

-- ---------------------------------------------------------------- 导入发行（chip release）
CREATE TABLE IF NOT EXISTS release (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,          -- chip release 名
    status          TEXT NOT NULL,          -- VALID / INVALID
    delivery_no     TEXT,                   -- MS-xxxx（VALID 才有，稳定）
    canonical_hash  TEXT NOT NULL,          -- 规范化指纹（稳定交付编号的基础）
    die_width_um    REAL,
    die_height_um   REAL,
    scribe_um       REAL,
    corner          TEXT,
    fab             TEXT,
    foundry_recipe_id TEXT,
    layer_count     INTEGER NOT NULL DEFAULT 0,
    findings_json   TEXT NOT NULL DEFAULT '[]',
    spec_json       TEXT NOT NULL DEFAULT '{}',
    imported_by     TEXT NOT NULL,
    imported_at     TEXT NOT NULL,
    UNIQUE(canonical_hash)
);

CREATE TABLE IF NOT EXISTS release_artifact (
    release_id  TEXT NOT NULL,
    role        TEXT NOT NULL,              -- GDS / OASIS / LAYERMAP / RECIPE / MASK:<name>
    logical_name TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY(release_id, role)
);

-- ---------------------------------------------------------------- Mask set 与谱系
CREATE TABLE IF NOT EXISTS mask_set (
    id              TEXT PRIMARY KEY,
    delivery_no     TEXT NOT NULL UNIQUE,
    release_id      TEXT NOT NULL,
    lineage_id      TEXT NOT NULL,
    kind            TEXT NOT NULL,          -- MASTER / REVISION / DELTA
    seq             INTEGER NOT NULL,       -- lineage 内节点序号
    base_set_id      TEXT,                  -- REVISION/DELTA 的父节点
    delta_of_set_id  TEXT,                  -- DELTA 的原永久封存节点
    canonical_hash  TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL DEFAULT '',
    order_json      TEXT NOT NULL DEFAULT '[]',  -- mask 名曝光先后次序
    layers_json     TEXT NOT NULL DEFAULT '[]',  -- 规格快照
    findings_json   TEXT NOT NULL DEFAULT '[]',
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE/SUPERSEDED/SEALED
    sealed_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_set_lineage ON mask_set(lineage_id, seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_lineage_active
    ON mask_set(lineage_id) WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS set_member (
    set_id     TEXT NOT NULL,
    mask_name  TEXT NOT NULL,
    role_type  TEXT NOT NULL,              -- MASTER / CORRECTED / DERIVED
    layer      TEXT,                       -- "L100.0" 等
    sha256     TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    PRIMARY KEY(set_id, mask_name)
);

CREATE TABLE IF NOT EXISTS set_edge (
    set_id  TEXT NOT NULL,
    src     TEXT NOT NULL,                 -- 前置 mask
    dst     TEXT NOT NULL,                 -- 后继 mask
    reason  TEXT NOT NULL,
    PRIMARY KEY(set_id, src, dst)
);

-- ---------------------------------------------------------------- 双角色替换（曝光前）
CREATE TABLE IF NOT EXISTS replacement (
    id            TEXT PRIMARY KEY,
    set_id        TEXT NOT NULL,
    mask_name     TEXT NOT NULL,
    new_sha       TEXT NOT NULL,
    new_name      TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    requested_at  TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'PENDING', -- PENDING/EXECUTED/REJECTED/CANCELLED
    new_set_id    TEXT,
    decided_at    TEXT,
    reason        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS replacement_approval (
    replacement_id TEXT NOT NULL,
    person_id      TEXT NOT NULL,
    role           TEXT NOT NULL,          -- ME / STEWARD
    at             TEXT NOT NULL,
    PRIMARY KEY(replacement_id, role)
);

-- ---------------------------------------------------------------- Delta 与返工
CREATE TABLE IF NOT EXISTS rework_plan (
    id           TEXT PRIMARY KEY,
    lot_id       TEXT NOT NULL,
    delta_set_id TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'OPEN' -- OPEN / CLOSED
);

-- ---------------------------------------------------------------- 曝光机
CREATE TABLE IF NOT EXISTS tool (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposure_window (
    id          TEXT PRIMARY KEY,
    tool_id     TEXT NOT NULL,
    set_id      TEXT NOT NULL,
    lot_id      TEXT,
    mask_name   TEXT NOT NULL,              -- 该窗口负责曝光的 mask（受先后次序约束）
    start_ts    TEXT NOT NULL,   -- ISO-8601 UTC，字典序即时间序
    end_ts      TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'RESERVED', -- RESERVED / EXPOSED / CANCELLED
    op_id       TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    exposed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_window_tool_time ON exposure_window(tool_id, start_ts, end_ts);
-- 重叠判定在应用层事务内执行（SQLite 触发器不便于绑定参数且跨索引表达区间相交）。

CREATE TABLE IF NOT EXISTS lot (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    set_id       TEXT,                     -- 当前绑定 mask set，最多一个
    state        TEXT NOT NULL DEFAULT 'CREATED', -- CREATED/BOUND/EXPOSED
    bound_at     TEXT,
    exposed_at   TEXT,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- ---------------------------------------------------------------- 幂等操作与资源裁决
CREATE TABLE IF NOT EXISTS operation (
    id          TEXT PRIMARY KEY,          -- 调用方提供的原操作编号
    kind        TEXT NOT NULL,
    identity    TEXT NOT NULL DEFAULT '',  -- 同一编号的作用域（人员）
    payload_hash TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'PENDING', -- PENDING/COMMITTED/FAILED/EXPIRED
    response_json TEXT,
    error_code  TEXT,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    committed_at TEXT,
    UNIQUE(id)
);

-- 资源仲裁：两名调度员抢占同一时间段时唯一赢家；每个输家各记一行
CREATE TABLE IF NOT EXISTS arbitration (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_key TEXT NOT NULL,            -- tool:<id>
    start_ts     TEXT NOT NULL,
    end_ts       TEXT NOT NULL,
    winner_op_id TEXT NOT NULL,
    loser_op_id  TEXT NOT NULL,
    decided_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arb_resource ON arbitration(resource_key, start_ts, end_ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_arb_loser ON arbitration(loser_op_id);

-- ---------------------------------------------------------------- 导出交付包
CREATE TABLE IF NOT EXISTS package (
    id           TEXT PRIMARY KEY,
    set_id       TEXT NOT NULL,
    file_path    TEXT,
    sha256       TEXT,
    status       TEXT NOT NULL DEFAULT 'BUILDING', -- BUILDING/READY/FAILED
    op_id        TEXT,
    error        TEXT,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    finished_at  TEXT
);

-- ---------------------------------------------------------------- 审计
CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    actor  TEXT,
    action TEXT NOT NULL,
    target TEXT,
    op_id  TEXT,
    detail TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""

# 预置账号（自然人）。自然人身份以 person.id 为准，
# 一人可兼多职，但 ME 与 STEWARD 两签必须是不同自然人。
SEED_PEOPLE = [
    ("u_mei",    "梅颖（制造工程师）", ["ME"]),
    ("u_tao",    "陶然（版图负责人）", ["STEWARD"]),
    ("u_disp1",  "调度员·晨", ["DISPATCHER"]),
    ("u_disp2",  "调度员·岳", ["DISPATCHER"]),
    ("u_admin",  "中心管理员", ["ADMIN"]),
]


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.cas_dir = self.root / "blobs"
        self.pkg_dir = self.root / "packages"
        self.cas_dir.mkdir(exist_ok=True)
        self.pkg_dir.mkdir(exist_ok=True)
        self.db_path = self.root / "maskcenter.db"
        self.lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------ 连接
    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _init_db(self):
        with self.lock:
            conn = self.connect()
            try:
                # executescript 会自行处理事务；DDL 全部 IF NOT EXISTS，可安全重入
                conn.executescript(SCHEMA)
                conn.execute(
                    "INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),))
                for pid, name, roles in SEED_PEOPLE:
                    conn.execute(
                        "INSERT OR IGNORE INTO person(id,name,roles) VALUES(?,?,?)",
                        (pid, name, json.dumps(roles, ensure_ascii=False)))
            finally:
                conn.close()

    class _Tx:
        def __init__(self, store: "Store"):
            self.store = store
            self.conn = None

        def __enter__(self):
            self.conn = self.store.connect()
            self.conn.execute("BEGIN IMMEDIATE")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type is None:
                    self.conn.execute("COMMIT")
                else:
                    self.conn.execute("ROLLBACK")
            finally:
                self.conn.close()
            return False

    def tx(self):
        """写事务：BEGIN IMMEDIATE 保证两名调度员串行裁决。"""
        return self._Tx(self)

    # ------------------------------------------------------------ 查询
    def q_one(self, sql, args=()):
        conn = self.connect()
        try:
            return conn.execute(sql, args).fetchone()
        finally:
            conn.close()

    def q_all(self, sql, args=()):
        conn = self.connect()
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()

    # ------------------------------------------------------------ CAS
    @staticmethod
    def cas_relpath(sha: str) -> str:
        return os.path.join(sha[:2], sha[2:4], sha)

    def cas_path(self, sha: str) -> Path:
        return self.cas_dir / self.cas_relpath(sha)

    def put_blob(self, data: bytes, declared_sha: str | None = None) -> tuple[str, int]:
        """内容寻址写入；重复 sha 不复制实体。"""
        sha = hashlib.sha256(data).hexdigest()
        if declared_sha and declared_sha.lower() != sha:
            raise CasError("DIGEST_MISMATCH",
                           f"摘要不符：声明 {declared_sha}，实际 {sha}")
        p = self.cas_path(sha)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, p)
        return sha, len(data)

    def get_blob(self, sha: str) -> bytes:
        p = self.cas_path(sha)
        if not p.exists():
            raise CasError("BLOB_MISSING", f"内容对象缺失：{sha}")
        return p.read_bytes()

    def verify_blob(self, sha: str) -> bool:
        p = self.cas_path(sha)
        if not p.exists():
            return False
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest() == sha.lower()

    def new_package_path(self, pkg_id: str) -> Path:
        d = self.pkg_dir / pkg_id[:2]
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{pkg_id}.tar"

    # ------------------------------------------------------------ 审计
    def audit(self, c, actor, action, target=None, op_id=None, detail=None):
        c.execute(
            "INSERT INTO audit_log(at,actor,action,target,op_id,detail) VALUES(?,?,?,?,?,?)",
            (utcnow(), actor, action, target, op_id,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)))


class CasError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
