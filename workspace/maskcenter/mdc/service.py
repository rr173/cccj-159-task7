"""光罩投片交付中心：领域服务（被 HTTP / CLI 复用的唯一裁决者）。

门禁一览（每一项都是显式拒收 + 审计留痕）：
  DIGEST_TAMPERED / ARTIFACT_QUARANTINED / MISSING_MASK_FILE / DEPENDENCY_INVERSION …（导入器）
  WINDOW_OVERLAP          同曝光机时间段重叠 → 仲裁产生唯一赢家
  OP_EXPIRED / OP_PAYLOAD_CONFLICT / OP_PENDING
  LOT_ALREADY_BOUND / LOT_WINDOWS_PENDING / LOT_NOT_BOUND / LOT_EXPOSED
  SET_SEALED_INPLACE      已开始曝光后原节点永久封存，禁止原地改写
  UNAUTHORIZED            越权（角色/自然人不符）
  APPROVAL_SAME_PERSON    两签必须是不同自然人
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tarfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

from .domain import (DomainError, canonical_bytes, canonical_hash,
                     delivery_number, parse_layer_inventory, scan_gds_layers,
                     LayoutScanError)
from .importer import Importer, ROLE_RANK
from .store import Store, utcnow

DEFAULT_TTL_SECONDS = 300


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


class Service:
    def __init__(self, store: Store, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.s = store
        self.importer = Importer(store)
        self.ttl = int(ttl_seconds)
        self.recover_on_startup()

    # ================================================================ 身份
    def require_person(self, person_id: str) -> dict:
        if not person_id:
            raise DomainError("UNAUTHORIZED", "缺少 X-Person-Id 操作者身份", 401)
        row = self.s.q_one("SELECT * FROM person WHERE id=?", (person_id,))
        if not row:
            raise DomainError("UNAUTHORIZED", f"未知自然人：{person_id}", 401)
        return {"id": row["id"], "name": row["name"],
                "roles": json.loads(row["roles"])}

    def require_role(self, person_id: str, role: str) -> dict:
        p = self.require_person(person_id)
        if role not in p["roles"]:
            raise DomainError("UNAUTHORIZED",
                              f"{p['name']} 不具备 {role} 角色", 403,
                              {"person": person_id, "required_role": role})
        return p

    def create_person(self, actor: str, person_id: str, name: str, roles: list[str]):
        self.require_role(actor, "ADMIN")
        valid = {"ME", "STEWARD", "DISPATCHER", "ADMIN"}
        if not set(roles) <= valid:
            raise DomainError("INVALID_ROLES", f"角色必须是 {sorted(valid)} 的子集", 400)
        if self.s.q_one("SELECT 1 FROM person WHERE id=?", (person_id,)):
            raise DomainError("PERSON_EXISTS", f"{person_id} 已存在", 409)
        with self.s.tx() as c:
            c.execute("INSERT INTO person(id,name,roles) VALUES(?,?,?)",
                      (person_id, name, json.dumps(sorted(roles))))
            self.s.audit(c, actor, "person.create", person_id, detail={"roles": roles})
        return {"id": person_id, "name": name, "roles": sorted(roles)}

    def list_people(self):
        return [{"id": r["id"], "name": r["name"], "roles": json.loads(r["roles"])}
                for r in self.s.q_all("SELECT * FROM person ORDER BY id")]

    # ================================================================ 内容/CAS
    def _put_blob_checked(self, data: bytes, declared_sha: str | None):
        from .store import CasError
        try:
            return self.s.put_blob(data, declared_sha)
        except CasError as e:
            raise DomainError(e.code, e.message, 422)

    def put_content(self, actor_id: str, logical_name: str, kind: str,
                    data: bytes, declared_sha: str | None = None) -> dict:
        actor = self.require_person(actor_id)
        if not logical_name:
            raise DomainError("INVALID_NAME", "logical_name 必填", 400)
        if kind not in ("GDS", "OASIS", "LAYERMAP", "RECIPE", "OTHER"):
            raise DomainError("INVALID_KIND", "kind 非法", 400)
        sha, size = self._put_blob_checked(data, declared_sha)
        with self.s.tx() as c:
            existing = c.execute("SELECT * FROM artifact WHERE sha256=?", (sha,)).fetchone()
            if existing:
                if existing["logical_name"] != logical_name:
                    c.execute("INSERT OR IGNORE INTO artifact_alias(logical_name,sha256)"
                              " VALUES(?,?)", (logical_name, sha))
                self.s.audit(c, actor["id"], "content.dedup", sha,
                             detail={"logical_name": existing["logical_name"]})
                return {"sha256": sha, "size": size, "logical_name": existing["logical_name"],
                        "dedup": True, "quarantined": False}

            active = c.execute(
                "SELECT sha256 FROM artifact WHERE logical_name=? AND status='ACTIVE'",
                (logical_name,)).fetchone()
            if active and active["sha256"] != sha:
                # 同名异物：blob 已在 CAS 保留，但不建立正式构件，隔离等待处置
                qid = "QRN-" + secrets.token_hex(5)
                c.execute(
                    "INSERT INTO quarantine(id,logical_name,sha256,existing_sha,kind,size,"
                    "reason,blob_path,detected_by,detected_at,status)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (qid, logical_name, sha, active["sha256"], kind, size,
                     "NAME_COLLISION", self.s.cas_relpath(sha),
                     actor["id"], utcnow(), "PENDING"))
                c.execute("INSERT OR IGNORE INTO artifact_alias(logical_name,sha256)"
                          " VALUES(?,?)", (logical_name, sha))
                self.s.audit(c, actor["id"], "content.quarantine", qid,
                             detail={"logical_name": logical_name, "sha256": sha})
                return {"sha256": sha, "size": size, "logical_name": logical_name,
                        "dedup": False, "quarantined": True, "quarantine_id": qid}

            c.execute(
                "INSERT INTO artifact(sha256,logical_name,kind,size,imported_at,imported_by,"
                "status) VALUES(?,?,?,?,?,?, 'ACTIVE')",
                (sha, logical_name, kind, size, utcnow(), actor["id"]))
            c.execute("INSERT OR IGNORE INTO artifact_alias(logical_name,sha256)"
                      " VALUES(?,?)", (logical_name, sha))
            self.s.audit(c, actor["id"], "content.register", sha,
                         detail={"logical_name": logical_name, "kind": kind})
            return {"sha256": sha, "size": size, "logical_name": logical_name,
                    "dedup": False, "quarantined": False}

    def list_artifacts(self):
        rows = self.s.q_all("SELECT * FROM artifact ORDER BY logical_name")
        out = [dict(r) for r in rows]
        for a in out:
            a["verified"] = self.s.verify_blob(a["sha256"])
        return out

    def artifact_relations(self, sha: str | None = None, name: str | None = None):
        where, arg = "1=1", None
        if sha:
            where, arg = "a.sha256=?", sha
        elif name:
            where, arg = "a.logical_name=?", name
        else:
            raise DomainError("BAD_REQUEST", "需要 sha256 或 logical_name", 400)
        row = self.s.q_one(f"SELECT * FROM artifact a WHERE {where}", (arg,))
        if not row:
            raise DomainError("NOT_FOUND", "构件不存在", 404)
        ra = self.s.q_all(
            "SELECT ra.release_id,r.name AS release_name,r.delivery_no,ra.role,r.status"
            " FROM release_artifact ra JOIN release r ON r.id=ra.release_id"
            " WHERE ra.sha256=?", (row["sha256"],))
        ms = self.s.q_all(
            "SELECT m.set_id,s.delivery_no,m.mask_name,m.role_type,s.status"
            " FROM set_member m JOIN mask_set s ON s.id=m.set_id WHERE m.sha256=?",
            (row["sha256"],))
        aliases = [r["logical_name"] for r in self.s.q_all(
            "SELECT logical_name FROM artifact_alias WHERE sha256=?", (row["sha256"],))]
        return {"artifact": dict(row), "aliases": aliases,
                "releases": [dict(r) for r in ra],
                "mask_set_memberships": [dict(r) for r in ms]}

    # ================================================================ 隔离处置
    def list_quarantine(self, status: str | None = None):
        sql = "SELECT * FROM quarantine"
        args: tuple = ()
        if status:
            sql += " WHERE status=?"
            args = (status,)
        sql += " ORDER BY detected_at DESC"
        return [dict(r) for r in self.s.q_all(sql, args)]

    def resolve_quarantine(self, actor: str, qid: str, decision: str,
                           new_name: str | None = None):
        self.require_role(actor, "ADMIN")
        if decision not in ("ACCEPT_AS_ALIAS", "REJECT"):
            raise DomainError("BAD_REQUEST", "decision 必须是 ACCEPT_AS_ALIAS/REJECT", 400)
        with self.s.tx() as c:
            q = c.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
            if not q:
                raise DomainError("NOT_FOUND", "隔离项不存在", 404)
            if q["status"] != "PENDING":
                raise DomainError("QUARANTINE_DECIDED",
                                  f"隔离项已处置为 {q['status']}", 409)
            if decision == "ACCEPT_AS_ALIAS":
                target = new_name.strip() if new_name else q["logical_name"]
                conflict = c.execute(
                    "SELECT 1 FROM artifact WHERE logical_name=? AND status='ACTIVE'",
                    (target,)).fetchone()
                if conflict:
                    raise DomainError("NAME_COLLISION",
                                      f"逻辑名 {target} 仍有活动构件，请给出唯一名", 409)
                c.execute("INSERT OR IGNORE INTO artifact(sha256,logical_name,kind,size,"
                          "imported_at,imported_by,status) VALUES(?,?,?,?,?,?, 'ACTIVE')",
                          (q["sha256"], target, q["kind"], q["size"], utcnow(), actor))
                c.execute("INSERT OR IGNORE INTO artifact_alias(logical_name,sha256)"
                          " VALUES(?,?)", (target, q["sha256"]))
                # 若是发行名冲突，放行该发行
                rel = c.execute(
                    "SELECT id FROM release WHERE canonical_hash=? AND status='QUARANTINED'",
                    (q["sha256"],)).fetchone()
                if rel:
                    self._adopt_quarantined_release(c, rel["id"], actor)
                new_status, name_used = "ACCEPTED_AS_ALIAS", target
            else:
                new_status, name_used = "REJECTED", None
            c.execute("UPDATE quarantine SET status=?,resolved_by=?,resolved_at=? WHERE id=?",
                      (new_status, actor, utcnow(), qid))
            self.s.audit(c, actor, "quarantine.resolve", qid,
                         detail={"decision": decision, "name": name_used})
            return {"id": qid, "status": new_status, "logical_name": name_used}

    def _adopt_quarantined_release(self, c, release_id, actor):
        release = c.execute("SELECT * FROM release WHERE id=?", (release_id,)).fetchone()
        recipe_sha = c.execute("SELECT sha256 FROM release_artifact WHERE release_id=? AND role='RECIPE'",
                               (release_id,)).fetchone()["sha256"]
        recipe = json.loads(self.s.get_blob(recipe_sha))
        build = json.loads(release["spec_json"])
        set_row = self._insert_set(c, release_id, build, recipe, "MASTER", None, None,
                                   f"{release['name']} 主版", actor)
        c.execute("UPDATE release SET status='VALID',delivery_no=? WHERE id=?",
                  (set_row["delivery_no"], release_id))

    # ================================================================ 导入
    def import_release(self, packet: dict, actor_id: str) -> dict:
        actor = self.require_person(actor_id)
        return self.importer.run(packet, actor["id"])

    def make_demo_packet(self, actor_id: str, suffix: str = "") -> dict:
        """演示/自检：合成一份完整合法资料（GDS 真二进制 + 层映射 + recipe）。"""
        from .domain import build_gds_for_test
        actor = self.require_person(actor_id)
        tag = suffix or secrets.token_hex(2)
        layers = [(100, 0), (101, 0), (200, 0)]
        gds = build_gds_for_test(layers)
        g = self.put_content(actor_id, f"DEMO{tag}.gds", "GDS", gds)
        lm = {
            "mappings": [
                {"layout_layer": "L100.0", "mask": "M_MAIN"},
                {"layout_layer": "L101.0", "mask": "M_OPC"},
                {"layout_layer": "L200.0", "mask": "M_IL"},
            ]}
        l = self.put_content(actor_id, f"DEMO{tag}.layers.json", "LAYERMAP",
                             canonical_bytes(lm))
        recipe = {
            "recipe_id": "FAB12-RCP-7", "fab": "FAB12",
            "corners": ["TT_0p90_25C", "SS_0p81_125C"],
            "masks": [
                {"name": "M_MAIN", "role_type": "MASTER", "layer": "L100.0",
                 "depends_on": []},
                {"name": "M_OPC", "role_type": "CORRECTED", "layer": "L101.0",
                 "depends_on": ["M_MAIN"]},
                {"name": "M_IL", "role_type": "DERIVED", "layer": "L200.0",
                 "depends_on": ["M_OPC"]},
            ]}
        r = self.put_content(actor_id, "FAB12-RCP-7.json", "RECIPE",
                             canonical_bytes(recipe))
        # mask 构件：演示中直接复用同一份 GDS（扫描含全部层，替换层校验也成立）
        m1 = self.put_content(actor_id, f"m_main{tag}.gds", "GDS", gds)
        m2 = self.put_content(actor_id, f"m_opc{tag}.gds", "GDS", gds)
        m3 = self.put_content(actor_id, f"m_il{tag}.gds", "GDS", gds)
        return {"packet": {
            "release_name": f"DEMO-RX-{tag}", "corner": "TT_0p90_25C",
            "fab": "FAB12", "foundry_recipe_id": "FAB12-RCP-7",
            "die": {"width_um": 5000, "height_um": 3000}, "scribe_um": 80,
            "entries": [
                {"role": "GDS", "logical_name": g["logical_name"], "sha256": g["sha256"]},
                {"role": "LAYERMAP", "logical_name": l["logical_name"], "sha256": l["sha256"]},
                {"role": "RECIPE", "logical_name": r["logical_name"], "sha256": r["sha256"]},
                {"role": "MASK:M_MAIN", "logical_name": m1["logical_name"],
                 "sha256": m1["sha256"]},
                {"role": "MASK:M_OPC", "logical_name": m2["logical_name"],
                 "sha256": m2["sha256"]},
                {"role": "MASK:M_IL", "logical_name": m3["logical_name"],
                 "sha256": m3["sha256"]},
            ]}}

    def get_release(self, release_id: str):
        r = self.s.q_one("SELECT * FROM release WHERE id=?", (release_id,))
        if not r:
            raise DomainError("NOT_FOUND", "发行不存在", 404)
        arts = self.s.q_all(
            "SELECT * FROM release_artifact WHERE release_id=? ORDER BY role", (release_id,))
        return {**dict(r),
                "findings_json": json.loads(r["findings_json"] or "[]"),
                "spec_json": json.loads(r["spec_json"] or "{}"),
                "artifacts": [dict(a) for a in arts]}

    def list_releases(self):
        return [
            {k: r[k] for k in ("id", "name", "status", "delivery_no", "imported_at")}
            for r in self.s.q_all(
                "SELECT id,name,status,delivery_no,imported_at FROM release"
                " ORDER BY imported_at DESC")]

    def get_set(self, set_id_or_dno: str):
        s = self._load_set(set_id_or_dno)
        return self._set_dict(s)

    def list_sets(self, lineage_id: str | None = None):
        sql = "SELECT * FROM mask_set"
        args: tuple = ()
        if lineage_id:
            sql += " WHERE lineage_id=?"
            args = (lineage_id,)
        sql += " ORDER BY lineage_id, seq"
        return [{k: r[k] for k in
                 ("id", "delivery_no", "kind", "seq", "status", "lineage_id",
                  "base_set_id", "delta_of_set_id", "title", "sealed_at")}
                for r in self.s.q_all(sql, args)]

    def _load_set(self, key: str):
        s = self.s.q_one("SELECT * FROM mask_set WHERE id=? OR delivery_no=?", (key, key))
        if not s:
            raise DomainError("NOT_FOUND", f"mask set 不存在：{key}", 404)
        return s

    def _set_dict(self, s):
        d = dict(s)
        d["order"] = json.loads(d.pop("order_json"))
        d["layers"] = json.loads(d.pop("layers_json"))
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
        d["members"] = [dict(r) for r in self.s.q_all(
            "SELECT * FROM set_member WHERE set_id=? ORDER BY mask_name", (s["id"],))]
        d["edges"] = [dict(r) for r in self.s.q_all(
            "SELECT src,dst,reason FROM set_edge WHERE set_id=?", (s["id"],))]
        return d

    # ================================================================ 幂等操作
    def idempotent(self, op_id: str | None, kind: str, payload: dict,
                   fn: Callable[[], Any], *, actor: str | None = None) -> dict:
        """以原操作编号安全重试的执行包装。

        - 同编号已提交 → 回放首次响应（replayed:true）
        - 同编号但载荷不同 → OP_PAYLOAD_CONFLICT
        - 同编号仍在裁决/已过期 → OP_PENDING / OP_EXPIRED
        """
        now = utcnow()
        ph = canonical_hash(payload)
        generated = False
        if not op_id:
            op_id = "OP-" + secrets.token_hex(8)
            generated = True
        identity = actor or ""
        with self.s.tx() as c:
            row = c.execute("SELECT * FROM operation WHERE id=?",
                            (op_id,)).fetchone()
            if row:
                return self._replay_op(row, ph)
            expires = (parse_ts(now) + timedelta(seconds=self.ttl)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z")
            c.execute(
                "INSERT INTO operation(id,kind,identity,payload_hash,status,created_at,"
                "expires_at) VALUES(?,?,?,?, 'PENDING',?,?)",
                (op_id, kind, identity, ph, now, expires))
        try:
            result = fn()
        except DomainError as e:
            # 失败也持久化：同编号重试安全地回放同一结论（幂等），
            # 由调用方决定是否接受"过期操作编号"（EXPIRED 状态单独拒绝）。
            with self.s.tx() as c:
                c.execute("UPDATE operation SET status='FAILED',error_code=?,"
                          "response_json=?,committed_at=? WHERE id=?",
                          (e.code,
                           json.dumps({"code": e.code, "message": e.message,
                                       "detail": e.detail}, ensure_ascii=False,
                                      sort_keys=True),
                           utcnow(), op_id))
                self.s.audit(c, identity, f"op.{kind}.fail", op_id,
                             detail={"error": e.code})
            e.op_id = op_id  # type: ignore[attr-defined]
            raise
        except Exception:
            with self.s.tx() as c:
                c.execute("UPDATE operation SET status='FAILED',error_code=? WHERE id=?",
                          ("INTERNAL", op_id))
            raise
        payload_resp = dict(result) if isinstance(result, dict) else {"value": result}
        payload_resp.setdefault("op_id", op_id)
        with self.s.tx() as c:
            c.execute("UPDATE operation SET status='COMMITTED',response_json=?,committed_at=?"
                      " WHERE id=?",
                      (json.dumps(payload_resp, ensure_ascii=False, sort_keys=True),
                       utcnow(), op_id))
        payload_resp["replayed"] = False
        payload_resp["op_generated"] = generated
        return payload_resp

    def _replay_op(self, row, ph: str) -> dict:
        # 过期操作编号优先明确拒绝（无论载荷是否一致）
        expired = (row["status"] == "EXPIRED" or
                   (row["status"] in ("PENDING", "FAILED")
                    and row["expires_at"] < utcnow()))
        if expired:
            raise DomainError("OP_EXPIRED", "操作编号已过期，请使用新编号", 410,
                              {"op_id": row["id"], "last_status": row["status"],
                               "error_code": row["error_code"]})
        if row["payload_hash"] != ph:
            raise DomainError("OP_PAYLOAD_CONFLICT",
                              "同一操作编号携带了不同载荷", 409,
                              {"op_id": row["id"], "first_kind": row["kind"]})
        if row["status"] == "COMMITTED":
            resp = json.loads(row["response_json"])
            resp["replayed"] = True
            return resp
        if row["status"] == "PENDING":
            raise DomainError("OP_PENDING",
                              "该操作编号仍在裁决中，请用相同编号重试", 409,
                              {"op_id": row["id"]})
        if row["status"] == "FAILED":
            # 未过期：安全重试 → 回放首次裁决结论（抢占输家仍得到同一唯一赢家）
            saved = json.loads(row["response_json"] or "{}")
            raise DomainError(saved.get("code", row["error_code"] or "OP_FAILED"),
                              saved.get("message", "操作此前已失败"), 409,
                              {**saved.get("detail", {}), "op_id": row["id"],
                               "replayed": True})
        raise DomainError("OP_EXPIRED",
                          f"操作编号处于 {row['status']} 终态，请使用新编号", 410,
                          {"op_id": row["id"], "error_code": row["error_code"]})

    # ================================================================ 曝光机 / 窗口
    def create_tool(self, actor: str, name: str):
        self.require_role(actor, "DISPATCHER")
        tid = "TOOL-" + secrets.token_hex(4)
        with self.s.tx() as c:
            if c.execute("SELECT 1 FROM tool WHERE name=?", (name,)).fetchone():
                raise DomainError("TOOL_EXISTS", f"曝光机 {name} 已存在", 409)
            c.execute("INSERT INTO tool(id,name,created_by,created_at) VALUES(?,?,?,?)",
                      (tid, name, actor, utcnow()))
            self.s.audit(c, actor, "tool.create", tid, detail={"name": name})
        return {"id": tid, "name": name}

    def list_tools(self):
        return [dict(r) for r in self.s.q_all("SELECT * FROM tool ORDER BY name")]

    def reserve_window(self, actor_id: str, tool_id: str, set_key: str, mask_name: str,
                       start_ts: str, end_ts: str, lot_id: str | None = None,
                       op_id: str | None = None) -> dict:
        actor = self.require_role(actor_id, "DISPATCHER")
        payload = {"tool_id": tool_id, "set": set_key, "mask": mask_name,
                   "start": start_ts, "end": end_ts, "lot_id": lot_id}

        def action():
            s = self._load_set(set_key)
            if s["status"] == "SEALED":
                # 封存节点本身不再接受新窗口；已保留窗口可继续执行
                raise DomainError("SET_SEALED_INPLACE",
                                  "mask set 已开始曝光并永久封存，只能创建 delta set",
                                  409, {"set": s["delivery_no"]})
            if s["status"] == "SUPERSEDED":
                raise DomainError("SET_SUPERSEDED",
                                  "该节点已被替换版取代，窗口请预订到当前节点", 409)
            tool = self.s.q_one("SELECT * FROM tool WHERE id=?", (tool_id,))
            if not tool:
                raise DomainError("TOOL_NOT_FOUND", "曝光机不存在", 404)
            order = json.loads(s["order_json"])
            if mask_name not in order:
                raise DomainError("MASK_NOT_IN_SET",
                                  f"{s['delivery_no']} 不含 mask {mask_name}", 400)
            self._validate_time_range(start_ts, end_ts)
            if lot_id is not None:
                self._check_lot_bindable_to_set(lot_id, s)

            with self.s.tx() as c:
                # 同曝光机时间段排他：与任何未取消窗口区间相交即冲突。
                # 仲裁结论必须持久化，因此先提交裁决，再在事务外抛出拒收。
                clash = c.execute(
                    "SELECT * FROM exposure_window WHERE tool_id=? AND state!='CANCELLED'"
                    " AND start_ts < ? AND end_ts > ? ORDER BY created_at, id LIMIT 1",
                    (tool_id, end_ts, start_ts)).fetchone()
                if clash:
                    winner = clash["op_id"] or f"WIN:{clash['id']}"
                    loser = op_id or f"LOSE:{mask_name}:{secrets.token_hex(4)}"
                    c.execute(
                        "INSERT INTO arbitration(resource_key,start_ts,end_ts,winner_op_id,"
                        "loser_op_id,decided_at) VALUES(?,?,?,?,?,?)",
                        (f"tool:{tool_id}", clash["start_ts"], clash["end_ts"],
                         winner, loser, utcnow()))
                    self.s.audit(c, actor["id"], "window.arbitration_lost", clash["id"],
                                 op_id=op_id,
                                 detail={"tool": tool_id, "winner_window": clash["id"],
                                         "winner_op": winner,
                                         "requested": [start_ts, end_ts]})
                    rejected = DomainError(
                        "WINDOW_OVERLAP",
                        f"与窗口 {clash['id']} 时间段重叠，仲裁输家，"
                        "请改用其它时间段并以新操作编号重试；赢家操作编号可用于对账",
                        409, {"winner_window_id": clash["id"], "tool_id": tool_id,
                              "winner_op_id": winner,
                              "winner_start": clash["start_ts"],
                              "winner_end": clash["end_ts"]})
                else:
                    wid = "WIN-" + secrets.token_hex(6)
                    c.execute(
                        "INSERT INTO exposure_window(id,tool_id,set_id,lot_id,mask_name,"
                        "start_ts,end_ts,state,op_id,created_by,created_at)"
                        " VALUES(?,?,?,?,?,?,?, 'RESERVED',?,?,?)",
                        (wid, tool_id, s["id"], lot_id, mask_name, start_ts, end_ts,
                         op_id, actor["id"], utcnow()))
                    self.s.audit(c, actor["id"], "window.reserve", wid, op_id=op_id,
                                 detail={"tool": tool_id, "set": s["delivery_no"],
                                         "mask": mask_name, "lot": lot_id})
                    result = {"window_id": wid, "tool_id": tool_id, "set_id": s["id"],
                              "delivery_no": s["delivery_no"], "mask_name": mask_name,
                              "lot_id": lot_id, "start_ts": start_ts, "end_ts": end_ts,
                              "state": "RESERVED"}
            if clash:
                raise rejected
            return result
        return self.idempotent(op_id, "reserve_window", payload, action, actor=actor["id"])

    @staticmethod
    def _validate_time_range(start_ts, end_ts):
        try:
            st, et = parse_ts(start_ts), parse_ts(end_ts)
        except (ValueError, AttributeError):
            raise DomainError("BAD_TIMESTAMP", "时间必须是 ISO-8601（如 2026-10-10T08:00:00Z）",
                              400)
        if not (st < et):
            raise DomainError("BAD_TIMESTAMP", "start_ts 必须早于 end_ts", 400)

    def list_windows(self, tool_id: str | None = None, set_id: str | None = None,
                     state: str | None = None):
        where, args = [], []
        for col, val in (("tool_id", tool_id), ("set_id", set_id), ("state", state)):
            if val:
                where.append(f"{col}=?")
                args.append(val)
        sql = "SELECT * FROM exposure_window"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY start_ts"
        return [dict(r) for r in self.s.q_all(sql, tuple(args))]

    def cancel_window(self, actor: str, window_id: str, op_id: str | None = None):
        self.require_role(actor, "DISPATCHER")
        payload = {"window_id": window_id}

        def action():
            with self.s.tx() as c:
                w = c.execute("SELECT * FROM exposure_window WHERE id=?", (window_id,)).fetchone()
                if not w:
                    raise DomainError("NOT_FOUND", "窗口不存在", 404)
                if w["state"] == "EXPOSED":
                    raise DomainError("WINDOW_EXPOSED", "已曝光窗口不可取消", 409)
                if w["state"] == "CANCELLED":
                    return {"window_id": window_id, "state": "CANCELLED", "noop": True}
                c.execute("UPDATE exposure_window SET state='CANCELLED' WHERE id=?",
                          (window_id,))
                self.s.audit(c, actor, "window.cancel", window_id, op_id=op_id)
                return {"window_id": window_id, "state": "CANCELLED"}
        return self.idempotent(op_id, "cancel_window", payload, action, actor=actor)

    # ================================================================ Lot
    def create_lot(self, actor: str, display_name: str):
        self.require_role(actor, "DISPATCHER")
        lot_id = "LOT-" + secrets.token_hex(5)
        with self.s.tx() as c:
            if c.execute("SELECT 1 FROM lot WHERE display_name=?", (display_name,)).fetchone():
                raise DomainError("LOT_EXISTS", f"lot {display_name} 已存在", 409)
            c.execute(
                "INSERT INTO lot(id,display_name,state,created_by,created_at)"
                " VALUES(?,?, 'CREATED',?,?)",
                (lot_id, display_name, actor, utcnow()))
            self.s.audit(c, actor, "lot.create", lot_id, detail={"name": display_name})
        return {"id": lot_id, "display_name": display_name, "state": "CREATED"}

    def list_lots(self):
        return [dict(r) for r in self.s.q_all("SELECT * FROM lot ORDER BY created_at")]

    def _is_delta_for_lot(self, s, lot_id):
        lot = self.s.q_one("SELECT * FROM lot WHERE id=?", (lot_id,))
        return bool(lot and lot["set_id"] and s["kind"] == "DELTA" and
                    self.s.q_one(
                        "SELECT 1 FROM mask_set WHERE id=? AND lineage_id="
                        "(SELECT lineage_id FROM mask_set WHERE id=?)",
                        (s["id"], lot["set_id"])))

    def _check_lot_bindable_to_set(self, lot_id, s):
        lot = self.s.q_one("SELECT * FROM lot WHERE id=?", (lot_id,))
        if not lot:
            raise DomainError("LOT_NOT_FOUND", f"lot 不存在：{lot_id}", 404)
        if lot["state"] == "EXPOSED":
            # 已开工 lot 只能通过 delta set + 返工计划
            delta = self.s.q_one(
                "SELECT 1 FROM mask_set WHERE id=? AND kind='DELTA' AND lineage_id="
                "(SELECT lineage_id FROM mask_set WHERE id=?)",
                (s["id"], lot["set_id"]))
            if not delta:
                raise DomainError("LOT_EXPOSED",
                                  "lot 已开始曝光，只能绑定同谱系 delta set（返工计划）", 409)

    def bind_lot(self, actor_id: str, lot_id: str, set_key: str,
                 op_id: str | None = None) -> dict:
        """同一 lot 只能绑定一个当前 mask set。"""
        actor = self.require_role(actor_id, "DISPATCHER")
        payload = {"lot_id": lot_id, "set": set_key}

        def action():
            s = self._load_set(set_key)
            if s["status"] == "SUPERSEDED":
                raise DomainError("SET_SUPERSEDED",
                                  "不能绑定已被取代的节点", 409)
            if s["status"] == "SEALED" and not self._is_delta_for_lot(s, lot_id):
                raise DomainError("SET_SEALED_INPLACE",
                                  "已封存节点不能新绑定；返工请使用该谱系的 delta set",
                                  409)
            self._check_lot_bindable_to_set(lot_id, s)
            with self.s.tx() as c:
                lot = c.execute("SELECT * FROM lot WHERE id=?", (lot_id,)).fetchone()
                if lot["state"] != "EXPOSED":
                    pending = c.execute(
                        "SELECT COUNT(1) AS n FROM exposure_window WHERE lot_id=?"
                        " AND state='RESERVED'", (lot_id,)).fetchone()["n"]
                    if pending:
                        raise DomainError("LOT_WINDOWS_PENDING",
                                          f"lot 尚有 {pending} 个已保留窗口，请先取消", 409)
                    if lot["set_id"] and lot["set_id"] != s["id"]:
                        # 同一 lot 切换当前 mask set：先解绑（尚未曝光，允许）
                        c.execute(
                            "UPDATE lot SET set_id=NULL,state='CREATED',bound_at=NULL WHERE id=?",
                            (lot_id,))
                c.execute("UPDATE lot SET set_id=?,state='BOUND',bound_at=? WHERE id=?",
                          (s["id"], utcnow(), lot_id))
                self.s.audit(c, actor["id"], "lot.bind", lot_id, op_id=op_id,
                             detail={"set": s["delivery_no"]})
                return {"lot_id": lot_id, "set_id": s["id"],
                        "delivery_no": s["delivery_no"], "state": "BOUND"}
        return self.idempotent(op_id, "bind_lot", payload, action, actor=actor["id"])

    # ================================================================ 曝光
    def expose(self, actor_id: str, window_id: str, op_id: str | None = None) -> dict:
        """执行曝光：校验 lot 绑定、主版→修正版→派生层的先后次序；
        任一 lot 一旦开始曝光，原 mask set 节点永久封存。"""
        actor = self.require_role(actor_id, "DISPATCHER")
        payload = {"window_id": window_id}

        def action():
            with self.s.tx() as c:
                w = c.execute("SELECT * FROM exposure_window WHERE id=?",
                              (window_id,)).fetchone()
                if not w:
                    raise DomainError("NOT_FOUND", "窗口不存在", 404)
                if w["state"] == "EXPOSED":
                    return {"window_id": window_id, "state": "EXPOSED", "noop": True,
                            "set_status": s["status"], "first_exposure": False}
                if w["state"] == "CANCELLED":
                    raise DomainError("WINDOW_CANCELLED", "窗口已取消，不能曝光", 409)
                s = c.execute("SELECT * FROM mask_set WHERE id=?", (w["set_id"],)).fetchone()
                if s["status"] == "SUPERSEDED":
                    raise DomainError("SET_SUPERSEDED",
                                      "节点已被替换，请对替换版重新排程后曝光", 409)
                lot = c.execute("SELECT * FROM lot WHERE id=?", (w["lot_id"],)).fetchone() \
                    if w["lot_id"] else None
                if not lot or lot["set_id"] != s["id"]:
                    raise DomainError("LOT_NOT_BOUND",
                                      "窗口的 lot 未绑定到该 mask set", 409,
                                      {"window_lot": w["lot_id"], "set": s["delivery_no"]})
                # 先后次序：该 mask 的每个前置 mask 在同一 lot 上至少有一次曝光
                deps = [r["src"] for r in c.execute(
                    "SELECT src FROM set_edge WHERE set_id=? AND dst=?",
                    (s["id"], w["mask_name"]))]
                for dep in deps:
                    done = c.execute(
                        "SELECT 1 FROM exposure_window WHERE set_id=? AND lot_id=?"
                        " AND mask_name=? AND state='EXPOSED' LIMIT 1",
                        (s["id"], lot["id"], dep)).fetchone()
                    if not done:
                        raise DomainError("DEPENDENCY_NOT_EXPOSED",
                                          f"前置 mask {dep} 尚未曝光，依赖倒置", 409,
                                          {"mask": w["mask_name"], "requires": deps})
                c.execute("UPDATE exposure_window SET state='EXPOSED',exposed_at=? WHERE id=?",
                          (utcnow(), window_id))
                first_exposure = s["status"] != "SEALED"
                if first_exposure:
                    c.execute("UPDATE mask_set SET status='SEALED',sealed_at=? WHERE id=?",
                              (utcnow(), s["id"]))
                    self.s.audit(c, actor["id"], "set.sealed", s["id"], op_id=op_id,
                                 detail={"delivery_no": s["delivery_no"],
                                         "window": window_id, "lot": lot["id"]})
                c.execute("UPDATE lot SET state='EXPOSED',exposed_at=? WHERE id=?",
                          (utcnow(), lot["id"]))
                self.s.audit(c, actor["id"], "window.expose", window_id, op_id=op_id,
                             detail={"set": s["delivery_no"], "mask": w["mask_name"],
                                     "lot": lot["id"]})
                return {"window_id": window_id, "state": "EXPOSED",
                        "set_status": "SEALED", "first_exposure": first_exposure}
        return self.idempotent(op_id, "expose", payload, action, actor=actor["id"])

    # ================================================================ 曝光前双签替换
    def request_replacement(self, actor_id: str, set_key: str, mask_name: str,
                            new_sha: str, reason: str = "",
                            op_id: str | None = None) -> dict:
        actor = self.require_person(actor_id)
        if "ME" not in actor["roles"] and "STEWARD" not in actor["roles"]:
            raise DomainError("UNAUTHORIZED", "只有制造工程师/版图负责人可申请替换", 403)
        payload = {"set": set_key, "mask": mask_name, "new_sha": new_sha,
                   "reason": reason, "by": actor["id"]}

        def action():
            s = self._load_set(set_key)
            if s["status"] == "SEALED":
                raise DomainError("SET_SEALED_INPLACE",
                                  "已开始曝光：原节点永久封存，只能创建 delta set", 409)
            if s["status"] == "SUPERSEDED":
                raise DomainError("SET_SUPERSEDED", "节点已被替换，请对当前节点操作", 409)
            member = self.s.q_one("SELECT * FROM set_member WHERE set_id=? AND mask_name=?",
                                  (s["id"], mask_name))
            if not member:
                raise DomainError("MASK_NOT_IN_SET", f"{mask_name} 不属于该 set", 404)
            art = self.s.q_one("SELECT * FROM artifact WHERE sha256=?", (new_sha,))
            if not art or art["status"] != "ACTIVE":
                raise DomainError("ARTIFACT_NOT_REGISTERED",
                                  "替换构件未登记或仍在隔离", 409)
            if not self.s.verify_blob(new_sha):
                raise DomainError("DIGEST_TAMPERED", "替换构件摘要校验失败", 409)
            # 构件适用性：新 GDS 必须能扫出该 mask 对应的层
            self._check_replacement_layer(art, json.loads(s["layers_json"]), mask_name)
            with self.s.tx() as c:
                rid = "RPL-" + secrets.token_hex(6)
                c.execute(
                    "INSERT INTO replacement(id,set_id,mask_name,new_sha,new_name,"
                    "requested_by,requested_at,status,reason) VALUES(?,?,?,?,?,?,?, 'PENDING',?)",
                    (rid, s["id"], mask_name, new_sha, art["logical_name"],
                     actor["id"], utcnow(), reason))
                self.s.audit(c, actor["id"], "replacement.request", rid, op_id=op_id,
                             detail={"set": s["delivery_no"], "mask": mask_name})
                return {"replacement_id": rid, "status": "PENDING",
                        "requires": ["ME", "STEWARD"]}
        return self.idempotent(op_id, "replacement.request", payload, action,
                               actor=actor["id"])

    def _check_replacement_layer(self, art, layers_spec, mask_name):
        spec = next((m for m in layers_spec if m["name"] == mask_name), None)
        if not spec or art["kind"] != "GDS":
            return  # 非 GDS 构件交由 recipe/层映射在构建包时再校验
        try:
            found = set(scan_gds_layers(self.s.get_blob(art["sha256"])))
        except LayoutScanError as ex:
            raise DomainError("GDS_PARSE_ERROR", f"替换构件解析失败：{ex}", 409)
        if spec["layer"] not in found:
            raise DomainError("MASK_LAYER_MISMATCH",
                              f"替换构件缺少该 mask 所需层 {spec['layer']}（实测 {sorted(found)}）",
                              409)

    def approve_replacement(self, actor_id: str, replacement_id: str,
                            op_id: str | None = None) -> dict:
        """两人批准：制造工程师与版图负责人，且不能是同一自然人。
        第二签到达时执行替换，产生新谱系节点并重算下游排程。"""
        actor = self.require_person(actor_id)
        payload = {"replacement_id": replacement_id, "by": actor["id"]}

        def action():
            with self.s.tx() as c:
                r = c.execute("SELECT * FROM replacement WHERE id=?",
                              (replacement_id,)).fetchone()
                if not r:
                    raise DomainError("NOT_FOUND", "替换申请不存在", 404)
                if r["status"] != "PENDING":
                    raise DomainError("REPLACEMENT_DECIDED",
                                      f"替换已 {r['status']}", 409)
                s = c.execute("SELECT * FROM mask_set WHERE id=?", (r["set_id"],)).fetchone()
                if s["status"] == "SEALED":
                    raise DomainError("SET_SEALED_INPLACE",
                                      "已开始曝光，原节点永久封存，不能再替换；请创建 delta set",
                                      409)
                if s["status"] == "SUPERSEDED":
                    raise DomainError("SET_SUPERSEDED", "节点已被替换", 409)
                # 角色：第二签必须补另一个角色
                prior = c.execute(
                    "SELECT person_id,role FROM replacement_approval WHERE replacement_id=?",
                    (replacement_id,)).fetchall()
                my_role = "ME" if "ME" in actor["roles"] else (
                    "STEWARD" if "STEWARD" in actor["roles"] else None)
                if my_role is None:
                    raise DomainError("UNAUTHORIZED",
                                      "只有制造工程师（ME）或版图负责人（STEWARD）可批准", 403)
                if any(p["person_id"] == actor["id"] for p in prior):
                    raise DomainError("APPROVAL_DUPLICATE",
                                      "同一自然人不能重复批准", 409)
                if any(p["role"] == my_role for p in prior):
                    raise DomainError("APPROVAL_ROLE_FILLED",
                                      f"{my_role} 角色已由他人批准", 409)
                c.execute("INSERT INTO replacement_approval(replacement_id,person_id,role,at)"
                          " VALUES(?,?,?,?)",
                          (replacement_id, actor["id"], my_role, utcnow()))
                self.s.audit(c, actor["id"], "replacement.approve", replacement_id,
                             op_id=op_id, detail={"role": my_role})
                if len(prior) + 1 < 2:
                    return {"replacement_id": replacement_id, "status": "PENDING",
                            "approvals": [p["role"] for p in prior] + [my_role],
                            "requires": ["ME", "STEWARD"]}

                # 第二签：执行替换 → 新谱系节点
                new_set = self._build_revision(c, s, r["mask_name"], r["new_sha"],
                                               r["new_name"], r["requested_by"])
                migrated = self._migrate_windows(c, old_set_id=s["id"],
                                                 new_set_id=new_set["id"])
                # 下游排程重算的一部分：绑定旧节点的 lot 一并指向新节点
                c.execute("UPDATE lot SET set_id=? WHERE set_id=?",
                          (new_set["id"], s["id"]))
                c.execute("UPDATE replacement SET status='EXECUTED',decided_at=?,"
                          "new_set_id=? WHERE id=?",
                          (utcnow(), new_set["id"], replacement_id))
                self.s.audit(c, actor["id"], "replacement.execute", replacement_id,
                             op_id=op_id,
                             detail={"old_set": s["delivery_no"],
                                     "new_set": new_set["delivery_no"],
                                     "migrated_windows": migrated,
                                     "approvers": [p["person_id"] for p in prior] +
                                                  [actor["id"]]})
                return {"replacement_id": replacement_id, "status": "EXECUTED",
                        "new_set_id": new_set["id"],
                        "new_delivery_no": new_set["delivery_no"],
                        "migrated_windows": migrated}

        def guarded_action():
            # 先在事务外做"同一自然人两签"检查（依据库内已批准记录）
            r = self.s.q_one("SELECT * FROM replacement WHERE id=?", (replacement_id,))
            if not r:
                raise DomainError("NOT_FOUND", "替换申请不存在", 404)
            approvers = {row["person_id"] for row in self.s.q_all(
                "SELECT person_id FROM replacement_approval WHERE replacement_id=?",
                (replacement_id,))}
            if actor["id"] in approvers:
                raise DomainError("APPROVAL_SAME_PERSON",
                                  "批准者不能是同一自然人（制造工程师与版图负责人必须不同）",
                                  409)
            return action()

        return self.idempotent(op_id, "replacement.approve", payload, guarded_action,
                               actor=actor["id"])

    def reject_replacement(self, actor_id: str, replacement_id: str,
                           op_id: str | None = None):
        actor = self.require_person(actor_id)
        if "ME" not in actor["roles"] and "STEWARD" not in actor["roles"]:
            raise DomainError("UNAUTHORIZED", "只有 ME/STEWARD 可驳回替换", 403)
        payload = {"replacement_id": replacement_id, "by": actor["id"]}

        def action():
            with self.s.tx() as c:
                r = c.execute("SELECT * FROM replacement WHERE id=?",
                              (replacement_id,)).fetchone()
                if not r:
                    raise DomainError("NOT_FOUND", "替换申请不存在", 404)
                if r["status"] != "PENDING":
                    raise DomainError("REPLACEMENT_DECIDED", f"替换已 {r['status']}", 409)
                c.execute("UPDATE replacement SET status='REJECTED',decided_at=? WHERE id=?",
                          (utcnow(), replacement_id))
                self.s.audit(c, actor["id"], "replacement.reject", replacement_id,
                             op_id=op_id)
                return {"replacement_id": replacement_id, "status": "REJECTED"}
        return self.idempotent(op_id, "replacement.reject", payload, action,
                               actor=actor["id"])

    def list_replacements(self, status: str | None = None):
        sql = ("SELECT r.*, GROUP_CONCAT(a.role || ':' || a.person_id) AS approvers "
               "FROM replacement r LEFT JOIN replacement_approval a "
               "ON a.replacement_id=r.id GROUP BY r.id ORDER BY r.requested_at DESC")
        rows = self.s.q_all(sql)
        out = []
        for r in rows:
            d = dict(r)
            d["approvers"] = [x for x in (d["approvers"] or "").split(",") if x]
            if status and d["status"] != status:
                continue
            out.append(d)
        return out

    def _insert_set(self, c, release_id, build, recipe, kind, base_set_id,
                    delta_of_set_id, title, actor, members_override=None,
                    edges_override=None, order_override=None, release_canonical=None):
        masks = {m["name"]: m for m in recipe["masks"]}
        if order_override is None:
            order = self._topo_sorted(masks)
        else:
            order = order_override
        if kind == "MASTER":
            # 主版交付编号直接由发行规范化指纹派生（导入器与隔离放行路径保持一致）
            rc = release_canonical or c.execute(
                "SELECT canonical_hash FROM release WHERE id=?", (release_id,)).fetchone()[0]
            ch = rc
        else:
            member_fp = sorted(
                ({"mask": n,
                  "sha": (members_override[n]["sha256"] if members_override else None)}
                 for n in order), key=lambda x: x["mask"])
            ch = canonical_hash({"release": release_id, "kind": kind,
                                 "base": base_set_id, "delta_of": delta_of_set_id,
                                 "members": list(member_fp)})
        dno = delivery_number(ch)
        lineage_row = c.execute(
            "SELECT lineage_id, MAX(seq) AS mx FROM mask_set WHERE lineage_id="
            "(SELECT lineage_id FROM mask_set WHERE id=?)",
            (base_set_id or delta_of_set_id,)).fetchone() if (base_set_id or
                                                              delta_of_set_id) else None
        if lineage_row and lineage_row["lineage_id"]:
            lineage_id, seq = lineage_row["lineage_id"], lineage_row["mx"] + 1
        else:
            lineage_id, seq = "LIN-" + secrets.token_hex(5), 1
        set_id = "ST-" + secrets.token_hex(6)
        layers_spec = [masks[n] for n in order if n in masks]
        # 先以非 ACTIVE 态插入，避开"每谱系唯一 ACTIVE"的部分唯一索引；
        # 由调用方在谱系切换完成后把新节点置为 ACTIVE（见 _build_revision/create_delta）。
        initial_status = "ACTIVE" if kind == "MASTER" else "PENDING"
        c.execute(
            "INSERT INTO mask_set(id,delivery_no,release_id,lineage_id,kind,seq,base_set_id,"
            "delta_of_set_id,canonical_hash,title,order_json,layers_json,created_by,"
            "created_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (set_id, dno, release_id, lineage_id, kind, seq, base_set_id, delta_of_set_id,
             ch, title, json.dumps(order, ensure_ascii=False),
             json.dumps(layers_spec, ensure_ascii=False, sort_keys=True),
             actor, utcnow(), initial_status))
        if members_override is None:
            for n in order:
                m = masks[n]
                row = c.execute(
                    "SELECT logical_name,sha256 FROM release_artifact WHERE release_id=?"
                    " AND role=?", (release_id, f"MASK:{n}")).fetchone()
                c.execute(
                    "INSERT INTO set_member(set_id,mask_name,role_type,layer,sha256,logical_name)"
                    " VALUES(?,?,?,?,?,?)",
                    (set_id, n, m["role_type"], m["layer"], row["sha256"],
                     row["logical_name"]))
        else:
            for n in order:
                m = members_override[n]
                c.execute(
                    "INSERT INTO set_member(set_id,mask_name,role_type,layer,sha256,logical_name)"
                    " VALUES(?,?,?,?,?,?)",
                    (set_id, n, m["role_type"], m["layer"], m["sha256"],
                     m["logical_name"]))
        edges = edges_override if edges_override is not None else [
            (dep, n, "recipe.depends_on") for n in order for dep in masks[n]["depends_on"]
            if dep in masks]
        for (src, dst, reason) in edges:
            c.execute("INSERT INTO set_edge(set_id,src,dst,reason) VALUES(?,?,?,?)",
                      (set_id, src, dst, reason))
        return {"id": set_id, "delivery_no": dno}

    @staticmethod
    def _topo_sorted(masks):
        indeg = {n: 0 for n in masks}
        dependents = {n: [] for n in masks}
        for n, m in masks.items():
            for d in m["depends_on"]:
                if d in masks:
                    indeg[n] += 1
                    dependents[d].append(n)
        ready = sorted([n for n, d in indeg.items() if d == 0],
                       key=lambda n: (ROLE_RANK[masks[n]["role_type"]], n))
        order = []
        while ready:
            n = ready.pop(0)
            order.append(n)
            for child in dependents[n]:
                indeg[child] -= 1
                if indeg[child] == 0:
                    ready.append(child)
            ready.sort(key=lambda x: (ROLE_RANK[masks[x]["role_type"]], x))
        return order

    def _build_revision(self, c, s, mask_name, new_sha, new_name, actor):
        """替换单个构件 → REVISION 新谱系节点；旧 ACTIVE 节点 SUPERSEDED。"""
        release = c.execute("SELECT * FROM release WHERE id=?", (s["release_id"],)).fetchone()
        recipe_sha = c.execute(
            "SELECT sha256 FROM release_artifact WHERE release_id=? AND role='RECIPE'",
            (s["release_id"],)).fetchone()["sha256"]
        recipe = json.loads(self.s.get_blob(recipe_sha))
        order = json.loads(s["order_json"])
        members = {}
        for n in order:
            old = c.execute("SELECT * FROM set_member WHERE set_id=? AND mask_name=?",
                            (s["id"], n)).fetchone()
            if n == mask_name:
                members[n] = {"role_type": old["role_type"], "layer": old["layer"],
                              "sha256": new_sha, "logical_name": new_name}
            else:
                members[n] = dict(old)
        title = f"{release['name']} 修正版（{mask_name} 替换）"
        new_set = self._insert_set(c, s["release_id"], json.loads(release["spec_json"]),
                                   recipe, "REVISION", s["id"], None, title, actor,
                                   members_override=members,
                                   order_override=order)
        # 谱系中只能有一个 ACTIVE 节点：旧节点 SUPERSEDED 后再激活新节点
        c.execute("UPDATE mask_set SET status='SUPERSEDED' WHERE id=? AND status='ACTIVE'",
                  (s["id"],))
        c.execute("UPDATE mask_set SET status='ACTIVE' WHERE id=?",
                  (new_set["id"],))
        return new_set

    def _migrate_windows(self, c, *, old_set_id, new_set_id) -> list[str]:
        """重算下游排程：未曝光的 RESERVED 窗口迁移到新节点；已取消/已曝光的不动。"""
        rows = c.execute(
            "SELECT id FROM exposure_window WHERE set_id=? AND state='RESERVED'",
            (old_set_id,)).fetchall()
        ids = [r["id"] for r in rows]
        if ids:
            c.execute("UPDATE exposure_window SET set_id=? WHERE set_id=? AND state='RESERVED'",
                      (new_set_id, old_set_id))
        return ids

    # ================================================================ Delta / 返工
    def create_delta(self, actor_id: str, sealed_set_key: str,
                     changes: list[dict], note: str = "",
                     op_id: str | None = None) -> dict:
        """曝光后：原节点永久封存，只能创建 delta set（只含变化层）+ 返工计划。"""
        actor = self.require_role(actor_id, "ME")
        if not isinstance(changes, list) or not changes:
            raise DomainError("BAD_REQUEST", "changes 必须是非空数组", 400)
        payload = {"set": sealed_set_key,
                   "changes": sorted(changes, key=lambda x: x.get("mask_name", "")),
                   "note": note}

        def action():
            base = self._load_set(sealed_set_key)
            if base["status"] != "SEALED":
                raise DomainError("SET_NOT_SEALED",
                                  "delta set 只能基于已开始曝光并封存的节点", 409)
            order = json.loads(base["order_json"])
            members = {r["mask_name"]: dict(r) for r in self.s.q_all(
                "SELECT * FROM set_member WHERE set_id=?", (base["id"],))}
            touched = []
            for ch in payload["changes"]:
                mn, sha = ch.get("mask_name"), ch.get("new_sha")
                if mn not in members:
                    raise DomainError("MASK_NOT_IN_SET", f"{mn} 不属于该 set", 400)
                art = self.s.q_one("SELECT * FROM artifact WHERE sha256=?", (sha,))
                if not art or art["status"] != "ACTIVE":
                    raise DomainError("ARTIFACT_NOT_REGISTERED",
                                      f"{mn} 的替换构件未登记或在隔离", 409)
                if not self.s.verify_blob(sha):
                    raise DomainError("DIGEST_TAMPERED", f"{mn} 替换构件摘要校验失败", 409)
                touched.append(mn)
                members[mn] = {"role_type": members[mn]["role_type"],
                               "layer": members[mn]["layer"],
                               "sha256": sha, "logical_name": art["logical_name"]}
            release = self.s.q_one("SELECT * FROM release WHERE id=?", (base["release_id"],))
            recipe_sha = self.s.q_one(
                "SELECT sha256 FROM release_artifact WHERE release_id=? AND role='RECIPE'",
                (base["release_id"],))["sha256"]
            recipe = json.loads(self.s.get_blob(recipe_sha))
            title = f"Delta（{release['name']}：{','.join(sorted(set(touched)))}）"
            with self.s.tx() as c:
                new_set = self._insert_set(
                    c, base["release_id"], {}, recipe, "DELTA", None, base["id"],
                    title, actor["id"], members_override=members, order_override=order)
                # base 保持 SEALED（不转 SUPERSEDED）；delta 作为新 ACTIVE 节点
                c.execute("UPDATE mask_set SET status='ACTIVE' WHERE id=?",
                          (new_set["id"],))
                self.s.audit(c, actor["id"], "delta.create", new_set["id"],
                             op_id=op_id, detail={"base": base["delivery_no"],
                                                  "masks": sorted(set(touched))})
                return {"delta_set_id": new_set["id"],
                        "delivery_no": new_set["delivery_no"],
                        "base_delivery_no": base["delivery_no"],
                        "changed_masks": sorted(set(touched)),
                        "note": note}
        return self.idempotent(op_id, "delta.create", payload, action, actor=actor["id"])

    def create_rework_plan(self, actor_id: str, lot_id: str, delta_set_key: str,
                           note: str = "", op_id: str | None = None):
        actor = self.require_role(actor_id, "ME")
        payload = {"lot_id": lot_id, "delta": delta_set_key, "note": note}

        def action():
            lot = self.s.q_one("SELECT * FROM lot WHERE id=?", (lot_id,))
            if not lot:
                raise DomainError("LOT_NOT_FOUND", "lot 不存在", 404)
            if lot["state"] != "EXPOSED":
                raise DomainError("LOT_NOT_EXPOSED",
                                  "返工计划只面向已开始曝光的 lot", 409)
            dset = self._load_set(delta_set_key)
            if dset["kind"] != "DELTA":
                raise DomainError("NOT_A_DELTA", "必须绑定 DELTA set", 409)
            base_lin = self.s.q_one(
                "SELECT lineage_id FROM mask_set WHERE id=?", (lot["set_id"],))
            if not base_lin or base_lin["lineage_id"] != dset["lineage_id"]:
                raise DomainError("DELTA_LINEAGE_MISMATCH",
                                  "delta set 与 lot 当前谱系不符", 409)
            with self.s.tx() as c:
                pid = "RWK-" + secrets.token_hex(5)
                c.execute(
                    "INSERT INTO rework_plan(id,lot_id,delta_set_id,created_by,created_at,note)"
                    " VALUES(?,?,?,?,?,?)",
                    (pid, lot_id, dset["id"], actor["id"], utcnow(), note))
                self.s.audit(c, actor["id"], "rework.create", pid, op_id=op_id,
                             detail={"lot": lot_id, "delta": dset["delivery_no"]})
                return {"rework_plan_id": pid, "lot_id": lot_id,
                        "delta_set_id": dset["id"], "status": "OPEN"}
        return self.idempotent(op_id, "rework.create", payload, action, actor=actor["id"])

    def list_rework_plans(self):
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM rework_plan ORDER BY created_at DESC")]

    # ================================================================ 打包导出
    def build_package(self, actor_id: str, set_key: str,
                      op_id: str | None = None) -> dict:
        """导出给晶圆厂的只读交付包。幂等：同 set+op 重复调用复用结果；
        崩溃重启后 resume_unfinished() 继续 BUILDING 的包。"""
        actor = self.require_person(actor_id)
        payload = {"set": set_key}

        def action():
            s = self._load_set(set_key)
            with self.s.tx() as c:
                existing = c.execute(
                    "SELECT * FROM package WHERE set_id=? AND status='READY' LIMIT 1",
                    (s["id"],)).fetchone()
                if existing:
                    return {"package_id": existing["id"], "path": existing["file_path"],
                            "sha256": existing["sha256"], "state": "READY",
                            "reused": True}
                row = c.execute(
                    "SELECT * FROM package WHERE set_id=? AND status='BUILDING' LIMIT 1",
                    (s["id"],)).fetchone()
                if row:
                    pkg_id = row["id"]
                    path = row["file_path"] or str(self.s.new_package_path(pkg_id))
                else:
                    pkg_id = "PKG-" + secrets.token_hex(6)
                    path = str(self.s.new_package_path(pkg_id))
                    c.execute(
                        "INSERT INTO package(id,set_id,file_path,status,op_id,created_by,"
                        "created_at) VALUES(?,?,?, 'BUILDING',?,?,?)",
                        (pkg_id, s["id"], path, op_id, actor["id"], utcnow()))
                self.s.audit(c, actor["id"], "package.build_start", pkg_id,
                             op_id=op_id, detail={"set": s["delivery_no"]})
            # 包文件构建在事务外（IO 长操作）；状态行已落盘 → 崩溃后可续
            try:
                sha = self._write_tarball(s, Path(path))
            except Exception as ex:  # 构建失败也持久化，可追溯
                with self.s.tx() as c:
                    c.execute("UPDATE package SET status='FAILED',error=?,finished_at=?"
                              " WHERE id=?", (str(ex), utcnow(), pkg_id))
                    self.s.audit(c, actor["id"], "package.fail", pkg_id,
                                 detail={"error": str(ex)})
                raise DomainError("PACKAGE_BUILD_FAILED", str(ex), 500)
            with self.s.tx() as c:
                c.execute("UPDATE package SET status='READY',sha256=?,finished_at=? WHERE id=?",
                          (sha, utcnow(), pkg_id))
                self.s.audit(c, actor["id"], "package.ready", pkg_id, op_id=op_id,
                             detail={"sha256": sha})
            return {"package_id": pkg_id, "path": path, "sha256": sha, "state": "READY"}
        return self.idempotent(op_id, "package.build", payload, action, actor=actor["id"])

    def _write_tarball(self, s, path: Path) -> str:
        members = self.s.q_all("SELECT * FROM set_member WHERE set_id=? ORDER BY mask_name",
                               (s["id"],))
        order = json.loads(s["order_json"])
        layers = json.loads(s["layers_json"])
        release = self.s.q_one("SELECT * FROM release WHERE id=?", (s["release_id"],))
        manifest = {
            "delivery_no": s["delivery_no"],
            "mask_set_id": s["id"],
            "kind": s["kind"],
            "release_name": release["name"],
            "die": {"width_um": release["die_width_um"],
                    "height_um": release["die_height_um"]},
            "scribe_um": release["scribe_um"],
            "corner": release["corner"],
            "fab": release["fab"],
            "foundry_recipe_id": release["foundry_recipe_id"],
            "exposure_order": order,
            "read_only": True,
            "masks": [{"mask_name": m["mask_name"], "role_type": m["role_type"],
                       "layer": m["layer"], "file": m["logical_name"],
                       "sha256": m["sha256"]} for m in members],
        }
        edges = self.s.q_all("SELECT src,dst FROM set_edge WHERE set_id=?", (s["id"],))
        manifest["dependencies"] = [[e["src"], e["dst"]] for e in edges]
        # 清单自摘要 = 除自身字段外所有内容的规范化哈希（无循环引用）
        manifest["manifest_sha256"] = hashlib.sha256(
            canonical_bytes({k: v for k, v in manifest.items()
                             if k != "manifest_sha256"})).hexdigest()
        manifest_bytes = canonical_bytes(manifest)

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tar.tmp")
        # 未压缩 tar：所有 TarInfo 字段固定（mtime=0、mode=0444、无 owner），
        # 同内容永远字节一致 → 重打包/崩溃续建得到相同交付摘要。
        with tarfile.open(tmp, "w") as tar:
            info = tarfile.TarInfo("MANIFEST.json")
            info.size = len(manifest_bytes)
            info.mode = 0o444
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, BytesIO(manifest_bytes))
            for m in members:
                data = self.s.get_blob(m["sha256"])  # 缺失即 BLOB_MISSING → FAILED
                filehash = hashlib.sha256(data).hexdigest()
                if filehash != m["sha256"]:
                    raise DomainError("DIGEST_TAMPERED",
                                      f"构件 {m['mask_name']} 摘要被篡改，打包中止",
                                      409)
                arc = f"masks/{m['mask_name']}/{m['logical_name']}"
                ti = tarfile.TarInfo(arc)
                ti.size = len(data)
                ti.mode = 0o444
                ti.mtime = 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                tar.addfile(ti, BytesIO(data))
        os.replace(tmp, path)
        os.chmod(path, 0o444)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def list_packages(self):
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM package ORDER BY created_at DESC")]

    def get_package_file(self, pkg_id: str) -> tuple[Path, dict]:
        row = self.s.q_one("SELECT * FROM package WHERE id=?", (pkg_id,))
        if not row:
            raise DomainError("NOT_FOUND", "交付包不存在", 404)
        if row["status"] != "READY":
            raise DomainError("PACKAGE_NOT_READY", f"交付包状态 {row['status']}", 409)
        p = Path(row["file_path"])
        if not p.exists():
            raise DomainError("PACKAGE_FILE_MISSING",
                              "交付包文件缺失，需重新构建", 410)
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != row["sha256"]:
            raise DomainError("PACKAGE_TAMPERED",
                              "交付包文件与登记摘要不一致（疑似篡改）", 409)
        return p, dict(row)

    # ================================================================ 审计
    def list_audit(self, limit: int = 200, target: str | None = None,
                   op_id: str | None = None):
        sql = "SELECT * FROM audit_log"
        where, args = [], []
        if target:
            where.append("target=?")
            args.append(target)
        if op_id:
            where.append("op_id=?")
            args.append(op_id)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        out = []
        for r in self.s.q_all(sql, tuple(args)):
            d = dict(r)
            d["detail"] = json.loads(d["detail"] or "{}")
            out.append(d)
        return out

    # ================================================================ 启动恢复
    def recover_on_startup(self):
        """进程异常退出后：
        1) BUILDING 交付包 → 依据持久状态继续构建；
        2) PENDING 且未过期的操作 → 视为裁决中断，过期作废，不自动重放副作用；
        3) 窗口/仲裁全部已在各自事务中落盘，天然一致。
        """
        with self.s.tx() as c:
            pending_ops = c.execute(
                "SELECT id FROM operation WHERE status='PENDING'").fetchall()
            expired = []
            now = utcnow()
            for op in pending_ops:
                row = c.execute("SELECT expires_at FROM operation WHERE id=?",
                                (op["id"],)).fetchone()
                if row["expires_at"] < now:
                    expired.append(op["id"])
                    c.execute("UPDATE operation SET status='EXPIRED' WHERE id=?", (op["id"],))
            building = list(c.execute(
                "SELECT id,set_id FROM package WHERE status='BUILDING'").fetchall())
        # 续建交付包（崩溃点可能在写 tar 中途 → 覆盖重写，幂等）
        for b in building:
            try:
                s = self.s.q_one("SELECT * FROM mask_set WHERE id=?", (b["set_id"],))
                if s:
                    p = Path(self.s.q_one("SELECT file_path FROM package WHERE id=?",
                                          (b["id"],))["file_path"])
                    sha = self._write_tarball(s, p)
                    with self.s.tx() as c:
                        c.execute("UPDATE package SET status='READY',sha256=?,finished_at=?"
                                  " WHERE id=?", (sha, utcnow(), b["id"]))
                        self.s.audit(c, "system", "package.resume", b["id"],
                                     detail={"after_crash": True})
            except Exception as ex:
                with self.s.tx() as c:
                    c.execute("UPDATE package SET status='FAILED',error=?,finished_at=?"
                              " WHERE id=?", (str(ex), utcnow(), b["id"]))
        if expired or building:
            with self.s.tx() as c:
                self.s.audit(c, "system", "startup.recover", None,
                             detail={"expired_ops": expired,
                                     "resumed_packages": [b["id"] for b in building]})
        return {"expired_operations": expired,
                "resumed_packages": [b["id"] for b in building]}
