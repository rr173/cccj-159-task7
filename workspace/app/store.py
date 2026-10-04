"""SQLite 持久化层：schema、连接管理、初始基线与检查目录。

只依赖标准库。所有写操作通过 with store.tx() 事务块执行，
Service 层负责把完整业务事务包进单个事务中。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    id              TEXT PRIMARY KEY,
    revision        INTEGER NOT NULL UNIQUE,
    parent_id       TEXT,
    created_at      TEXT NOT NULL,
    eco_id          TEXT,
    snapshot_json   TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    published_by    TEXT NOT NULL,
    trust_generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS trunk (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    base_id         TEXT NOT NULL,
    base_revision   INTEGER NOT NULL,
    working_constraints_json TEXT NOT NULL,
    constraints_version    INTEGER NOT NULL DEFAULT 1
);

-- 事故隔离裁决（两阶段：REGISTERED/PENDING 落盘后，可在重启时恢复 ISOLATED）
CREATE TABLE IF NOT EXISTS quarantine_incident (
    id                  TEXT PRIMARY KEY,
    baseline_id         TEXT NOT NULL,
    batch_no            TEXT NOT NULL,
    reason              TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    registered_by       TEXT NOT NULL,
    status              TEXT NOT NULL,          -- PENDING / ISOLATED / RESTORED
    generation          INTEGER,
    trusted_ancestor_id TEXT,
    guard_revision      INTEGER,
    failpoint           TEXT,
    created_at          TEXT NOT NULL,
    isolated_at         TEXT,
    restored_at         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_quarantine_request
ON quarantine_incident(request_fingerprint)
WHERE status IN ('PENDING','ISOLATED','RESTORED');

CREATE TABLE IF NOT EXISTS quarantine_request (
    request_key     TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_baseline (
    incident_id     TEXT NOT NULL,
    baseline_id     TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    relation        TEXT NOT NULL,              -- HIT / DESCENDANT
    trust_status    TEXT NOT NULL,              -- UNTRUSTED / RESTORED
    marked_at       TEXT NOT NULL,
    restored_at     TEXT,
    PRIMARY KEY(incident_id, baseline_id)
);
CREATE INDEX IF NOT EXISTS idx_qb_baseline ON quarantine_baseline(baseline_id, trust_status);

CREATE TABLE IF NOT EXISTS quarantine_eco (
    incident_id     TEXT NOT NULL,
    eco_id          TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    previous_status TEXT NOT NULL,
    action          TEXT NOT NULL,              -- REBASE_REQUIRED / RELEASE_CANCELLED
    marked_at       TEXT NOT NULL,
    restored_at     TEXT,
    PRIMARY KEY(incident_id, eco_id)
);
CREATE INDEX IF NOT EXISTS idx_qe_eco ON quarantine_eco(eco_id);

CREATE TABLE IF NOT EXISTS quarantine_confirmation (
    incident_id     TEXT NOT NULL,
    role            TEXT NOT NULL,
    user            TEXT NOT NULL,
    note            TEXT,
    at              TEXT NOT NULL,
    PRIMARY KEY(incident_id, role)
);

CREATE TABLE IF NOT EXISTS quarantine_journal (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT NOT NULL,
    event           TEXT NOT NULL,
    actor           TEXT,
    at              TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_qj_incident ON quarantine_journal(incident_id, seq);

CREATE TABLE IF NOT EXISTS eco (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    owner           TEXT NOT NULL,
    status          TEXT NOT NULL,
    affected_modules_json TEXT NOT NULL DEFAULT '[]',
    edits_json      TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    submitted_at    TEXT,
    frozen_at       TEXT,
    parent_baseline_id TEXT,
    base_revision_at_freeze INTEGER,
    constraints_version_at_freeze INTEGER,
    snapshot_json   TEXT,
    fingerprint     TEXT,
    freeze_epoch    INTEGER NOT NULL DEFAULT 0,
    merge_of_json   TEXT,
    impact_snapshot_id TEXT,
    impact_input_json  TEXT,
    trust_generation INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS check_run (
    id              TEXT PRIMARY KEY,
    eco_id          TEXT NOT NULL,
    check_type      TEXT NOT NULL,
    attempt         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL,            -- PENDING/PASS/FAIL/BLOCKED/SUPERSEDED
    required        INTEGER NOT NULL,
    depends_on_json TEXT NOT NULL,
    expected_fp     TEXT,
    result_fp       TEXT,
    result_json     TEXT,
    submitted_at    TEXT,
    runner_id       TEXT
);
CREATE INDEX IF NOT EXISTS idx_checkrun_eco ON check_run(eco_id);

CREATE TABLE IF NOT EXISTS signoff (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    eco_id          TEXT NOT NULL,
    role            TEXT NOT NULL,
    user            TEXT NOT NULL,             -- 实际签字的自然人（代理人签则为代理人本人）
    epoch           INTEGER NOT NULL,
    overall_fp      TEXT NOT NULL,
    at              TEXT NOT NULL,
    signoff_kind    TEXT NOT NULL DEFAULT 'DIRECT',  -- DIRECT / DELEGATE
    delegation_id   INTEGER,                   -- DELEGATE 时指向 signoff_delegation.id
    auth_chain_json TEXT NOT NULL DEFAULT '{}', -- 签核动作发生时的身份/代理链快照
    voided_at       TEXT,                      -- 纪元/基线变化失效时刻（记录保留供审计）
    voided_reason   TEXT,
    UNIQUE(eco_id, role, epoch)
);

-- 临时代理签核授权：管理员为两种签核角色指定临时自然人及其有效时间窗
CREATE TABLE IF NOT EXISTS signoff_delegation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    role            TEXT NOT NULL,            -- TIMING_LEAD / METHODOLOGY_LEAD
    delegate_user   TEXT NOT NULL,            -- 被授权临时代理签核的自然人
    principal_user  TEXT,                     -- 被代理的角色负责人（可空，仅用于展示来源）
    granted_by      TEXT NOT NULL,            -- 配置该代理的管理员
    granted_at      TEXT NOT NULL,
    valid_from      TEXT NOT NULL,            -- 生效时间（UTC ISO-8601）
    valid_until     TEXT NOT NULL,            -- 失效时间（UTC ISO-8601，半开区间）
    status          TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE / REVOKED
    revoked_at      TEXT,
    revoked_by      TEXT,
    note            TEXT
);
-- 同一代理配置（角色+代理人+完全相同的时间窗）至多存在一条有效记录：
-- 重复提交不得生成重复有效记录（应用层幂等返回既有记录，索引做最终防线）
CREATE UNIQUE INDEX IF NOT EXISTS ux_delegation_active_once
ON signoff_delegation(role, delegate_user, valid_from, valid_until)
WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS module_lock (
    module          TEXT PRIMARY KEY,
    eco_id          TEXT NOT NULL,
    acquired_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS queue_entry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    eco_id          TEXT NOT NULL,
    blocker_eco_id  TEXT NOT NULL,
    module          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    resolved_at     TEXT,
    resolution      TEXT                      -- AUTO_PROMOTE / ABORT / MERGED
);

CREATE TABLE IF NOT EXISTS adjudication (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_eco_id   TEXT NOT NULL,
    target_eco_id   TEXT NOT NULL,
    decision        TEXT NOT NULL,            -- MERGE
    merged_modules_json TEXT NOT NULL,
    merged_edits_json TEXT NOT NULL,
    by              TEXT NOT NULL,
    at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS release (
    eco_id          TEXT PRIMARY KEY,
    state           TEXT NOT NULL,            -- RELEASING / PUBLISHED / CANCELLED
    new_baseline_id TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    failpoint       TEXT
);

CREATE TABLE IF NOT EXISTS release_journal (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    eco_id          TEXT NOT NULL,
    event           TEXT NOT NULL,
    at              TEXT NOT NULL,
    detail_json     TEXT
);

CREATE TABLE IF NOT EXISTS constraint_event (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    base_id         TEXT NOT NULL,
    version         INTEGER NOT NULL,
    delta_json      TEXT NOT NULL,
    by              TEXT NOT NULL,
    at              TEXT NOT NULL,
    note            TEXT
);

CREATE TABLE IF NOT EXISTS rejected_result (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT,
    eco_id          TEXT,
    check_type      TEXT,
    reason          TEXT NOT NULL,
    detail_json     TEXT,
    received_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    actor           TEXT,
    action          TEXT NOT NULL,
    entity          TEXT,
    at              TEXT NOT NULL,
    detail_json     TEXT
);

-- ===== 版本化电路拓扑与影响闭包 =====
CREATE TABLE IF NOT EXISTS impact_topology (
    version         INTEGER PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    graph_json      TEXT NOT NULL,
    status          TEXT NOT NULL,             -- CURRENT / SUPERSEDED
    note            TEXT,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS impact_current (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    version         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS impact_request (
    id                  TEXT PRIMARY KEY,       -- scope:input_fp:topology_version
    scope               TEXT NOT NULL,
    input_fingerprint   TEXT NOT NULL,
    topology_version    INTEGER NOT NULL,
    created_by          TEXT,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_impact_request_scope
ON impact_request(scope,input_fingerprint);

-- 闭包快照不可变。revision=1 为自动结论；人工排除追加新 revision，旧行改 SUPERSEDED。
CREATE TABLE IF NOT EXISTS impact_snapshot (
    id                      TEXT PRIMARY KEY,
    request_id              TEXT NOT NULL,
    scope                   TEXT NOT NULL,
    revision                INTEGER NOT NULL,
    parent_snapshot_id      TEXT,
    topology_version        INTEGER NOT NULL,
    topology_fingerprint    TEXT NOT NULL,
    input_fingerprint       TEXT NOT NULL,
    exclusion_fingerprint   TEXT NOT NULL,
    result_fingerprint      TEXT NOT NULL,
    status                  TEXT NOT NULL,        -- CURRENT / SUPERSEDED / TOPOLOGY_SUPERSEDED
    result_json             TEXT NOT NULL,
    created_by              TEXT,
    created_at              TEXT NOT NULL,
    UNIQUE(request_id, revision),
    UNIQUE(request_id, exclusion_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_impact_scope_status
ON impact_snapshot(scope,input_fingerprint,status);

CREATE TABLE IF NOT EXISTS impact_latest (
    scope               TEXT NOT NULL,
    input_fingerprint   TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    topology_version    INTEGER NOT NULL,
    PRIMARY KEY(scope,input_fingerprint)
);

CREATE TABLE IF NOT EXISTS impact_override (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id         TEXT NOT NULL,
    parent_snapshot_id  TEXT NOT NULL,
    scope               TEXT NOT NULL,
    node_id             TEXT NOT NULL,
    reason              TEXT NOT NULL,
    by                  TEXT NOT NULL,
    created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_impact_override_snapshot ON impact_override(snapshot_id);

-- ===== 验证执行租约协调（与 ECO 服务配套的租约层）=====
-- 每个 check_run 至多一条当前租约行（run_id UNIQUE）；gen 为租约代次，
-- 每次接管 +1，用于拒绝旧持有者的迟到结果/续租。token 以 HMAC 派生（服务密钥
-- 存 lease_meta），库内仅留 SHA-256 摘要，凭据不可伪造也不会因落盘泄露明文。
CREATE TABLE IF NOT EXISTS check_lease (
    run_id          TEXT PRIMARY KEY,
    eco_id          TEXT NOT NULL,
    check_type      TEXT NOT NULL,
    gen             INTEGER NOT NULL DEFAULT 1,
    runner_id       TEXT NOT NULL,
    state           TEXT NOT NULL,            -- HELD/COMPLETED/RELEASED/EXPIRED/INVALIDATED
    token_hash      TEXT NOT NULL,
    acquired_at     TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    renewed_count   INTEGER NOT NULL DEFAULT 0,
    completed_at    TEXT,
    completion_verdict TEXT,
    detail_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_lease_eco ON check_lease(eco_id);
CREATE INDEX IF NOT EXISTS idx_lease_state ON check_lease(state);

-- 领取请求幂等键：相同 key 重放返回首次的租约授权（含原始 gen/凭据），
-- 全局唯一索引是并发下“重复领取至多生效一次”的最终防线。
CREATE TABLE IF NOT EXISTS lease_claim (
    idempotency_key TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    runner_id       TEXT NOT NULL,
    claimed_at      TEXT NOT NULL,
    grant_json      TEXT NOT NULL             -- 首次授权响应快照（含 token 明文，仅此处分发）
);

-- 租约生命周期/接管历史（可查询审计）
CREATE TABLE IF NOT EXISTS lease_event (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT,
    eco_id          TEXT,
    check_type      TEXT,
    gen             INTEGER,
    event           TEXT NOT NULL,            -- CLAIM/RENEW/COMPLETE/RELEASE/EXPIRE/TAKEOVER/INVALIDATE/REJECT
    actor           TEXT,
    at              TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_lease_event_run ON lease_event(run_id, seq);

-- 租约层自身的键值元数据（HMAC 密钥在首次启动时生成并落盘，重启后旧凭据仍可校验）
CREATE TABLE IF NOT EXISTS lease_meta (
    k               TEXT PRIMARY KEY,
    v               TEXT NOT NULL
);
"""


SEED_MODULES = {
    "core": {
        "netlist": "MODULE core; INPUT clk rst; CELL FF q0/q1 D=core.d; NET clk_buf=clk; ENDMODULE",
        "version": 1,
    },
    "alu": {
        "netlist": "MODULE alu; INPUT a b; CELL ADD u_add(a,b,s); CELL MUX u_mux; ENDMODULE",
        "version": 1,
    },
    "l2c": {
        "netlist": "MODULE l2c; CELL RAMB u_tag(DEPTH=256); NET hit = tag_cmp; ENDMODULE",
        "version": 1,
    },
    "noc": {
        "netlist": "MODULE noc; CELL ROUTER r0/r1; LINK r0.east=r1.west; ENDMODULE",
        "version": 1,
    },
    "dbg": {
        "netlist": "MODULE dbg; CELL DEBUG_APB u_dbg_apb; ENDMODULE",
        "version": 1,
    },
}

SEED_CONSTRAINTS = {
    "clk_period_ns": 1.20,
    "clk_uncertainty_ns": 0.05,
    "max_dynamic_power_mw": 480,
    "max_leakage_power_mw": 35,
    "corner": "ss_0p81v_m40c",
    "target_fmax_ghz": 0.95,
}


# 检查目录：type -> (中文名, 是否必需, 依赖, 指纹作用域)
# 作用域决定该检查的输入指纹覆盖哪些冻结物：
#   netlist   = 模块网表
#   sdc       = 约束
#   modules   = 受影响模块清单
CHECKS: dict[str, dict] = {
    "TIMING_STA":    {"label": "静态时序分析 STA", "required": True,
                      "depends_on": [],          "scopes": ["netlist", "sdc", "modules"]},
    "POWER_ANALYSIS": {"label": "功耗分析",        "required": True,
                      "depends_on": [],          "scopes": ["netlist", "sdc", "modules"]},
    "FORMAL_EQUIV":  {"label": "形式等价验证",    "required": True,
                      "depends_on": [],          "scopes": ["netlist", "modules"]},
    "LAYOUT_DRC":    {"label": "版图设计规则检查", "required": True,
                      "depends_on": ["TIMING_STA", "POWER_ANALYSIS"],
                      "scopes": ["netlist", "modules"]},
    "LINT_INFO":     {"label": "Lint 信息检查(非必需)", "required": False,
                      "depends_on": [],          "scopes": ["netlist", "modules"]},
    # 以下检查默认不是所有 ECO 必需；当影响闭包生成对应 check_type 时，该 ECO 的 check_run
    # 会动态标记 required=1，从而进入审核/发布门禁。
    "CDC_VERIFY":              {"label": "跨时钟域 CDC 复验", "required": False,
                                "depends_on": [], "scopes": ["netlist", "modules"]},
    "INTERFACE_CONTRACT_CHECK": {"label": "接口契约复验", "required": False,
                                 "depends_on": [], "scopes": ["netlist", "modules"]},
    "CONSTRAINT_REFERENCE_CHECK": {"label": "约束引用复验", "required": False,
                                   "depends_on": [], "scopes": ["netlist", "sdc", "modules"]},
    "CLOCK_TREE_REVIEW":       {"label": "时钟树传播复验", "required": False,
                                "depends_on": [], "scopes": ["netlist", "sdc", "modules"]},
}


class Store:
    def __init__(self, path: str = ":memory:", seed: bool = True):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + 单把互斥锁，保证 release 等多步操作可串行化
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        self.conn.executescript(SCHEMA)
        self._migrate()
        if seed:
            self._seed()

    def _migrate(self):
        """对既有落盘库补齐代理签核新增列（CREATE TABLE IF NOT EXISTS 不会改老表）。"""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(signoff)")}
        baseline_cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(baseline)")}
        with self.tx() as c:
            if "trust_generation" not in baseline_cols:
                c.execute("ALTER TABLE baseline ADD COLUMN trust_generation INTEGER NOT NULL DEFAULT 0")
            if "signoff_kind" not in cols:
                c.execute("ALTER TABLE signoff ADD COLUMN signoff_kind TEXT NOT NULL DEFAULT 'DIRECT'")
            if "delegation_id" not in cols:
                c.execute("ALTER TABLE signoff ADD COLUMN delegation_id INTEGER")
            if "auth_chain_json" not in cols:
                c.execute("ALTER TABLE signoff ADD COLUMN auth_chain_json TEXT NOT NULL DEFAULT '{}'")
            if "voided_at" not in cols:
                c.execute("ALTER TABLE signoff ADD COLUMN voided_at TEXT")
            if "voided_reason" not in cols:
                c.execute("ALTER TABLE signoff ADD COLUMN voided_reason TEXT")
            eco_cols = {r["name"] for r in c.execute("PRAGMA table_info(eco)")}
            if "impact_snapshot_id" not in eco_cols:
                c.execute("ALTER TABLE eco ADD COLUMN impact_snapshot_id TEXT")
            if "impact_input_json" not in eco_cols:
                c.execute("ALTER TABLE eco ADD COLUMN impact_input_json TEXT")
            if "trust_generation" not in eco_cols:
                c.execute("ALTER TABLE eco ADD COLUMN trust_generation INTEGER NOT NULL DEFAULT 0")

    # ---- 事务辅助 ----
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
        cur = self.conn.execute(sql, args)
        return cur.fetchone()

    def q_all(self, sql: str, args=()):
        return self.conn.execute(sql, args).fetchall()

    # ---- 初始数据 ----
    def _seed(self):
        self._seed_impact_topology()
        if self.q_one("SELECT 1 FROM baseline WHERE revision = 0"):
            return
        from .service import build_snapshot, snapshot_fingerprint
        snap = build_snapshot(SEED_MODULES, SEED_CONSTRAINTS,
                              sorted(SEED_MODULES), note="R0 初始冻结网表/约束/验证矩阵")
        fp = snapshot_fingerprint(snap)
        now = utcnow()
        with self.tx() as c:
            c.execute(
                "INSERT INTO baseline(id,revision,parent_id,created_at,eco_id,snapshot_json,"
                "fingerprint,published_by) VALUES('B-R0',0,NULL,?,?,?,?,?)",
                (now, None, json.dumps(snap, ensure_ascii=False), fp, "system"),
            )
            c.execute(
                "INSERT INTO trunk(id,base_id,base_revision,working_constraints_json,"
                "constraints_version) VALUES(1,'B-R0',0,?,1)",
                (json.dumps(SEED_CONSTRAINTS, ensure_ascii=False, sort_keys=True),),
            )

    def _seed_impact_topology(self):
        if self.q_one("SELECT 1 FROM impact_current WHERE id=1"):
            return
        from .impact import ImpactService, SEED_TOPOLOGY
        ImpactService(self).publish_topology(
            SEED_TOPOLOGY, "system", "初始模块实例关系、时钟域、约束引用与强制策略")

    def reset(self):
        with self.tx() as c:
            for t in ["audit_log", "rejected_result", "release_journal", "release",
                      "adjudication", "queue_entry", "module_lock", "signoff_delegation",
                      "signoff", "check_run", "eco", "constraint_event", "trunk", "baseline",
                      "lease_event", "lease_claim", "check_lease",
                      "quarantine_journal", "quarantine_confirmation", "quarantine_eco",
                      "quarantine_baseline", "quarantine_request", "quarantine_incident",
                      "impact_override",
                      "impact_latest", "impact_snapshot", "impact_request",
                      "impact_current", "impact_topology"]:
                c.execute(f"DELETE FROM {t}")
        self._seed()
