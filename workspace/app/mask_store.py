"""光罩投片交付中心：SQLite 持久化层 + 内容寻址 blob 存储。

零第三方依赖。所有多步业务写操作通过 ``with store.tx() as c``（BEGIN IMMEDIATE）
在单个事务内裁决，配合单把进程锁，保证抢占资源时只有唯一赢家。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


SCHEMA = r"""
-- 内容寻址实体：任何资料（GDS/OASIS/层映射/recipe/die/scribe/角）落盘一次
CREATE TABLE IF NOT EXISTS mask_blob (
    id          TEXT PRIMARY KEY,          -- sha256 hex
    size        INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);

-- 构件：逻辑文件，身份=(release_id, slot, layer_no?)；同名异物按 (name,kind) 隔离
CREATE TABLE IF NOT EXISTS mask_artifact (
    id              TEXT PRIMARY KEY,
    release_id      TEXT NOT NULL,
    kind            TEXT NOT NULL,         -- layout/layermap/recipe/die/scribe/corner
    slot            TEXT NOT NULL,         -- L<n>/layermap/recipe/die/scribe/CORNER_<name>
    name            TEXT NOT NULL,         -- 文件名
    blob_id         TEXT NOT NULL,
    size            INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    declared_sha256 TEXT,                  -- 导入清单声明的摘要（可能为空）
    parse_status    TEXT NOT NULL DEFAULT 'OK',  -- OK / PARSE_ERROR
    parse_detail    TEXT NOT NULL DEFAULT '',
    detail_json     TEXT NOT NULL DEFAULT '{}',  -- 解析结果：layer_no/recipe_id/corners...
    version         INTEGER NOT NULL DEFAULT 1,  -- 同槽位版本（替换/返工新版本）
    created_at      TEXT NOT NULL,
    UNIQUE(release_id, slot, version)
);
CREATE INDEX IF NOT EXISTS idx_artifact_release ON mask_artifact(release_id);
-- 同名异物隔离是应用层检测（跨发行同名允许，同发行同名不同内容必须隔离）

-- 同名异物隔离区
CREATE TABLE IF NOT EXISTS mask_quarantine (
    id              TEXT PRIMARY KEY,
    release_id      TEXT NOT NULL,
    artifact_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL,
    existing_blob   TEXT NOT NULL,
    incoming_blob   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING/RESOLVED
    resolution      TEXT,                              -- REJECT_INCOMING/ACCEPT_NEW_RELEASE
    note            TEXT,
    created_at      TEXT NOT NULL,
    resolved_at     TEXT,
    resolved_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_status ON mask_quarantine(status);

-- 芯片发行：导入会话（COLLECTING 收料 → FINALIZED 规范化得到稳定交付编号）
CREATE TABLE IF NOT EXISTS mask_release (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,        -- 发行名（如 chip-A）
    status              TEXT NOT NULL DEFAULT 'COLLECTING',
    declared_digests_json TEXT NOT NULL DEFAULT '{}',
    normalized_fingerprint TEXT,              -- 规范化指纹
    delivery_no         TEXT,                 -- 稳定交付编号 MS-xxxx
    finalized_at        TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
-- 稳定交付编号允许多个重复导入发行共享（去重）；指纹唯一只锚定首个规范发行
CREATE INDEX IF NOT EXISTS idx_release_delivery
    ON mask_release(delivery_no) WHERE delivery_no IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_release_fingerprint
    ON mask_release(normalized_fingerprint) WHERE normalized_fingerprint IS NOT NULL;

-- 每次导入（按 op_id 幂等；重复导入完整资料不复制实体）
CREATE TABLE IF NOT EXISTS mask_import (
    id              TEXT PRIMARY KEY,
    op_id           TEXT NOT NULL UNIQUE,
    release_id      TEXT NOT NULL,
    status          TEXT NOT NULL,           -- OPEN / FINALIZED / REJECTED
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

-- 核验结论
CREATE TABLE IF NOT EXISTS mask_verification (
    id          TEXT PRIMARY KEY,
    release_id  TEXT NOT NULL,
    stage       TEXT NOT NULL,               -- UPLOAD / FINALIZE / EXPORT
    verdict     TEXT NOT NULL,               -- PASS / FAIL
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verification_release ON mask_verification(release_id);

CREATE TABLE IF NOT EXISTS mask_finding (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    verification_id TEXT NOT NULL,
    release_id      TEXT NOT NULL,
    code            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'ERROR',  -- ERROR / WARN
    artifact_id     TEXT,
    slot            TEXT,
    component       TEXT,                    -- 精确定位：构件 slot / 名称
    message         TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_release ON mask_finding(release_id);

-- mask set（一次发行可有主版/修正版/派生/返工 delta 谱系）
CREATE TABLE IF NOT EXISTS mask_set (
    id          TEXT PRIMARY KEY,
    release_id  TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,               -- MASTER/REVISION/DELTA
    created_at  TEXT NOT NULL,
    created_by  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_set_release ON mask_set(release_id);

-- 谱系节点：MASTER / REVISION（替换构件产生）/ DERIVED（派生层）/ DELTA（曝光后返工）
CREATE TABLE IF NOT EXISTS mask_node (
    id          TEXT PRIMARY KEY,
    mask_set_id TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL CHECK(kind IN ('MASTER','REVISION','DERIVED','DELTA')),
    label       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE / SUPERSEDED / SEALED
    reason      TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    sealed_at   TEXT,
    UNIQUE(mask_set_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_node_set ON mask_node(mask_set_id);

-- 节点与构件槽位（layer_no 可空；delta 节点只含变更槽位）
CREATE TABLE IF NOT EXISTS mask_node_slot (
    node_id     TEXT NOT NULL,
    slot        TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    layer_no    INTEGER,
    PRIMARY KEY(node_id, slot)
);

-- 节点先后次序：父槽位未曝光/未排程前，派生/修正不能越过
CREATE TABLE IF NOT EXISTS mask_node_edge (
    parent_node_id  TEXT NOT NULL,
    child_node_id   TEXT NOT NULL,
    PRIMARY KEY(parent_node_id, child_node_id)
);

-- 曝光机
CREATE TABLE IF NOT EXISTS mask_machine (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1
);

-- wafer lot：同一 lot 只能绑定一个当前 mask set 节点
CREATE TABLE IF NOT EXISTS mask_lot (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    mask_set_id     TEXT,
    current_node_id TEXT,
    bound_at        TEXT,
    status          TEXT NOT NULL DEFAULT 'CREATED', -- CREATED/SCHEDULED/EXPOSING/EXPOSED
    created_at      TEXT,
    started_at      TEXT,
    completed_at    TEXT
);

-- 曝光窗口（每台曝光机时间段半开区间排他）
CREATE TABLE IF NOT EXISTS mask_window (
    id          TEXT PRIMARY KEY,
    op_id       TEXT UNIQUE,
    machine_id  TEXT NOT NULL,
    lot_id      TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    slot        TEXT NOT NULL,
    start_ts    TEXT NOT NULL,
    end_ts      TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'PLANNED',  -- PLANNED/CANCELLED/EXPOSED
    exposed_at  TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_window_machine_time
    ON mask_window(machine_id, start_ts, end_ts);
-- 数据库层兜底机器时间排他：有效窗口的时间区间不能重叠。
-- 用每台机器上「右开区间最大不重叠起点数」难以用普通约束表达，
-- 因此排他性由应用在单写事务内判定；这里仅保留普通索引供其走索引。
CREATE INDEX IF NOT EXISTS idx_window_lot ON mask_window(lot_id);
CREATE INDEX IF NOT EXISTS idx_window_node ON mask_window(node_id);

-- 调度裁决（两名调度员同时抢占同一资源时的唯一赢家记录，崩溃可恢复）
CREATE TABLE IF NOT EXISTS mask_arbitration (
    id          TEXT PRIMARY KEY,
    op_id       TEXT,
    resource    TEXT NOT NULL,               -- machine:<id> / lot:<id>
    contender   TEXT NOT NULL,               -- 调度员
    decision    TEXT NOT NULL,               -- WIN / LOSE
    reason      TEXT,
    window_id   TEXT,
    decided_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arb_resource ON mask_arbitration(resource, decided_at);

-- 未曝光双角色批准替换：制造工程师(ME) + 版图负责人(LO)，必须不同自然人
CREATE TABLE IF NOT EXISTS mask_replacement (
    id              TEXT PRIMARY KEY,
    mask_set_id     TEXT NOT NULL,
    node_id         TEXT NOT NULL,           -- 被替换的节点
    slot            TEXT NOT NULL,
    old_artifact_id TEXT NOT NULL,
    new_artifact_id TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING/APPROVED/DONE/REJECTED
    me_user         TEXT,
    lo_user         TEXT,
    me_at           TEXT,
    lo_at           TEXT,
    new_node_id     TEXT,
    reason          TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_repl_status ON mask_replacement(status);

-- 曝光后返工计划（delta set）
CREATE TABLE IF NOT EXISTS mask_rework (
    id          TEXT PRIMARY KEY,
    lot_id      TEXT NOT NULL,
    sealed_node_id TEXT NOT NULL,
    delta_set_id TEXT,
    delta_node_id TEXT,
    reason      TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'PLANNED',  -- PLANNED/READY
    created_at  TEXT NOT NULL
);

-- 导出给晶圆厂的只读交付包（可崩溃恢复）
CREATE TABLE IF NOT EXISTS mask_export (
    id          TEXT PRIMARY KEY,
    op_id       TEXT UNIQUE,
    node_id     TEXT NOT NULL,
    target_dir  TEXT NOT NULL,
    zip_path    TEXT,
    state       TEXT NOT NULL,               -- QUEUED/PACKAGING/DONE/FAILED
    manifest_json TEXT,
    package_sha256 TEXT,
    error       TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    finished_at TEXT
);

-- 操作日志（只追加）
CREATE TABLE IF NOT EXISTS mask_audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    entity      TEXT,
    result      TEXT NOT NULL DEFAULT 'OK',  -- OK / DENIED
    reason      TEXT,
    op_id       TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_mask_audit_entity ON mask_audit(entity, seq);
CREATE INDEX IF NOT EXISTS idx_mask_audit_op ON mask_audit(op_id);

-- 通用幂等操作登记（已完成操作的稳定结果）
CREATE TABLE IF NOT EXISTS mask_op (
    op_id       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    request_fp  TEXT NOT NULL,
    status      TEXT NOT NULL,               -- DONE / REJECTED
    response_json TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
"""

SLOT_KIND = {
    "layermap": "layermap",
    "recipe": "recipe",
    "die": "die",
    "scribe": "scribe",
}
REQUIRED_META_SLOTS = ("layermap", "recipe", "die", "scribe")
OP_TTL_SECONDS = 24 * 3600

SEED_USERS = {
    "u_mei":   {"name": "周敏", "roles": ["MANUFACTURING_ENGINEER"]},
    "u_lo":    {"name": "李岸", "roles": ["LAYOUT_OWNER"]},
    "u_both":  {"name": "赵兼", "roles": ["MANUFACTURING_ENGINEER", "LAYOUT_OWNER"]},
    "u_disp1": {"name": "调度员甲", "roles": ["DISPATCHER"]},
    "u_disp2": {"name": "调度员乙", "roles": ["DISPATCHER"]},
    "u_op":    {"name": "导入操作员", "roles": ["OPERATOR"]},
}

SEED_MACHINES = [
    ("EXP-01", "一号曝光机"),
    ("EXP-02", "二号曝光机"),
]


class MaskStore:
    def __init__(self, db_path: str = ":memory:", blob_dir: str | None = None, seed: bool = True):
        self.db_path = db_path
        if db_path == ":memory:":
            default_root = Path.cwd() / ".mask-blobs"
        else:
            default_root = Path(db_path).resolve().parent / "mask-blobs"
        self.blob_dir = Path(blob_dir) if blob_dir else default_root
        (self.blob_dir / "tmp").mkdir(parents=True, exist_ok=True)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        self.conn.executescript(SCHEMA)
        if seed:
            self._seed()

    class _Tx:
        def __init__(self, conn, lock):
            self.conn, self.lock = conn, lock

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

    class _UsingTx:
        """已有游标则复用（嵌套调用），否则新开 BEGIN IMMEDIATE 事务。"""
        def __init__(self, conn, lock, c):
            self.conn, self.lock, self.c, self.owned = conn, lock, c, c is None

        def __enter__(self):
            if self.owned:
                self.lock.acquire()
                self.conn.execute("BEGIN IMMEDIATE")
            return self.c if self.c is not None else self.conn

        def __exit__(self, exc_type, exc, tb):
            if self.owned:
                if exc_type is None:
                    self.conn.execute("COMMIT")
                else:
                    self.conn.execute("ROLLBACK")
                self.lock.release()
            return False

    def using_tx(self, c=None):
        return self._UsingTx(self.conn, self.lock, c)

    def q_one(self, sql: str, args=()):
        return self.conn.execute(sql, args).fetchone()

    def q_all(self, sql: str, args=()):
        return self.conn.execute(sql, args).fetchall()

    # ---- 内容寻址 blob ----
    def blob_path(self, blob_id: str) -> Path:
        return self.blob_dir / blob_id[:2] / blob_id[2:4] / blob_id

    def tmp_path(self, name: str) -> Path:
        p = self.blob_dir / "tmp" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_blob(self, blob_id: str, data: bytes) -> str:
        """原子写入内容寻址 blob；已存在则直接复用（重复导入不复制实体）。"""
        p = self.blob_path(blob_id)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.tmp_path(f"{blob_id}.{os.getpid()}.{threading.get_ident()}.tmp")
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        return str(p)

    def read_blob(self, blob_id: str) -> bytes:
        return self.blob_path(blob_id).read_bytes()

    def ensure_blob_row(self, c, blob_id: str, size: int):
        c.execute("INSERT OR IGNORE INTO mask_blob(id,size,created_at) VALUES(?,?,?)",
                  (blob_id, size, utcnow()))

    # ---- 审计 ----
    def audit(self, c, action: str, entity=None, actor=None, result="OK", reason=None,
              op_id=None, detail=None):
        c.execute(
            "INSERT INTO mask_audit(at,actor,action,entity,result,reason,op_id,detail_json)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (utcnow(), actor, action, entity, result, reason, op_id,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)))

    def _seed(self):
        with self.tx() as c:
            for mid, name in SEED_MACHINES:
                c.execute("INSERT OR IGNORE INTO mask_machine(id,name) VALUES(?,?)", (mid, name))

    def reset(self):
        with self.tx() as c:
            for t in ["mask_audit", "mask_op", "mask_export", "mask_rework",
                      "mask_replacement", "mask_arbitration", "mask_window", "mask_lot",
                      "mask_node_edge", "mask_node_slot", "mask_node", "mask_set",
                      "mask_finding", "mask_verification", "mask_import", "mask_quarantine",
                      "mask_artifact", "mask_release"]:
                c.execute(f"DELETE FROM {t}")
            for mid, name in SEED_MACHINES:
                c.execute("INSERT OR IGNORE INTO mask_machine(id,name) VALUES(?,?)", (mid, name))


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()
