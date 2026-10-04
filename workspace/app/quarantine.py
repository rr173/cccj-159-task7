"""已发行芯片版本的事故隔离与恢复裁决。

隔离以已发布基线为根，沿 baseline.parent_id 计算全部后代，并在同一个
``BEGIN IMMEDIATE`` 事务内完成：谱系标为不可信、trunk 回退到最近可信祖先、
未发行 ECO 回退/取消、旧检查与签核作废。注册先落 PENDING 日志，再执行隔离；
服务重启后可从该日志恢复未完成裁决。
"""
from __future__ import annotations

import json

from .service import ECOError, canon, fp_json
from .store import Store, utcnow

ROLE_QUALITY = "QUALITY_LEAD"
ROLE_RELEASE = "RELEASE_MANAGER"
RESTORE_ROLES = [ROLE_QUALITY, ROLE_RELEASE]
ROLE_LABELS = {ROLE_QUALITY: "质量负责人", ROLE_RELEASE: "发布负责人"}

ACTIVE_STATUSES = ("FROZEN", "REBASE_REQUIRED", "QUEUED", "RELEASING")
TERMINAL_STATUSES = ("RELEASED", "MERGED", "ABORTED")


class QuarantineService:
    def __init__(self, store: Store, now_fn=utcnow):
        self.s = store
        self._now_fn = now_fn

    def _now_str(self) -> str:
        return utcnow()

    def _journal(self, c, incident_id, event, actor=None, detail=None):
        c.execute(
            "INSERT INTO quarantine_journal(incident_id,event,actor,at,detail_json) "
            "VALUES(?,?,?,?,?)",
            (incident_id, event, actor, self._now_str(),
             json.dumps(detail or {}, ensure_ascii=False)))

    def _audit(self, c, action, entity, actor, detail=None):
        c.execute("INSERT INTO audit_log(actor,action,entity,at,detail_json) VALUES(?,?,?,?,?)",
                  (actor, action, entity, self._now_str(),
                   json.dumps(detail or {}, ensure_ascii=False)))

    def _next_incident_id(self, c) -> str:
        n = c.execute("SELECT COUNT(*) k FROM quarantine_incident").fetchone()["k"]
        return f"Q-{n + 1:04d}"

    def _baseline(self, c, baseline_id):
        row = c.execute("SELECT * FROM baseline WHERE id=?", (baseline_id,)).fetchone()
        if not row:
            raise ECOError("BASELINE_NOT_FOUND", f"基线 {baseline_id} 不存在", 404)
        return row

    def _children_map(self, c):
        children = {}
        for r in c.execute("SELECT id,parent_id FROM baseline").fetchall():
            children.setdefault(r["parent_id"], []).append(r["id"])
        return children

    def _descendants(self, c, root_id):
        """返回 {baseline_id: HIT|DESCENDANT}，按基线版本顺序遍历谱系。"""
        out = {root_id: "HIT"}
        children = self._children_map(c)
        stack = [root_id]
        while stack:
            parent = stack.pop()
            for child in children.get(parent, []):
                if child not in out:
                    out[child] = "DESCENDANT"
                    stack.append(child)
        return out

    def _nearest_trusted_ancestor(self, c, root_id):
        """沿命中版本的父链找到第一条没有活动隔离标记的基线（不含命中版本本身）。"""
        root = self._baseline(c, root_id)
        cur = root["parent_id"]
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            active = c.execute(
                "SELECT 1 FROM quarantine_baseline WHERE baseline_id=? "
                "AND trust_status='UNTRUSTED' LIMIT 1", (cur,)).fetchone()
            if not active:
                row = self._baseline(c, cur)
                return row
            row = c.execute("SELECT parent_id FROM baseline WHERE id=?", (cur,)).fetchone()
            cur = row["parent_id"]
        raise ECOError("NO_TRUSTED_ANCESTOR", "命中谱系没有可信祖先，无法隔离", 409)

    def _active_overlap(self, c, baseline_ids, exclude_incident=None):
        q = ("SELECT qb.*, qi.status incident_status FROM quarantine_baseline qb "
             "JOIN quarantine_incident qi ON qi.id=qb.incident_id "
             "WHERE qb.trust_status='UNTRUSTED' AND qb.baseline_id IN (%s)"
             % ",".join("?" * len(baseline_ids)))
        args = list(baseline_ids)
        for r in c.execute(q, args).fetchall():
            if r["incident_id"] != exclude_incident:
                return dict(r)
        return None

    def _pending_overlap(self, c, baseline_ids, exclude_incident=None):
        roots = [self._baseline(c, bid) for bid in baseline_ids]
        for inc in c.execute("SELECT * FROM quarantine_incident WHERE status='PENDING'").fetchall():
            if inc["id"] == exclude_incident:
                continue
            root = self._baseline(c, inc["baseline_id"])
            # 当前实现是单 trunk 线性版本号；根版本不新于受影响版本即代表其在同一祖先链上。
            if any(root["revision"] <= b["revision"] for b in roots):
                return dict(inc)
        return None

    def _current_generation(self, c):
        row = c.execute("SELECT COALESCE(MAX(generation),0) g FROM quarantine_incident").fetchone()
        return int(row["g"] or 0)

    def _evidence(self, evidence):
        if evidence is None or evidence == "" or evidence == [] or evidence == {}:
            raise ECOError("EVIDENCE_REQUIRED", "登记事故必须提供证据（URL、编号或结构化材料）", 400)
        if isinstance(evidence, str):
            evidence = [{"type": "text", "ref": evidence}]
        else:
            evidence = [
                {"type": "text", "ref": item} if isinstance(item, str) else item
                for item in evidence
            ]
        if not isinstance(evidence, list):
            evidence = [evidence]
        for item in evidence:
            if not isinstance(item, dict) or not item:
                raise ECOError("BAD_EVIDENCE", "每条证据必须是非空对象，或非空字符串", 400)
        return evidence

    # ===== 登记与两阶段隔离 =====
    def register(self, by, baseline_id, batch_no, reason, evidence, *,
                 incident_id=None, idempotency_key=None, failpoint=None,
                 role=ROLE_QUALITY):
        if role != ROLE_QUALITY:
            raise ECOError("FORBIDDEN_ROLE",
                           "只有质量负责人（QUALITY_LEAD）可以登记故障事故", 403)
        if not by:
            raise ECOError("BAD_REQUEST", "by 必填", 400)
        if not batch_no:
            raise ECOError("BATCH_REQUIRED", "故障批次 batch_no 必填", 400)
        if not reason:
            raise ECOError("REASON_REQUIRED", "故障原因 reason 必填", 400)
        evidence = self._evidence(evidence)
        request_fp = fp_json({
            "baseline_id": baseline_id, "batch_no": batch_no,
            "reason": reason, "evidence": evidence,
        })
        request_key = idempotency_key or f"request:{request_fp}"
        pending_retry = None

        with self.s.tx() as c:
            self._baseline(c, baseline_id)
            existing_req = c.execute(
                "SELECT * FROM quarantine_request WHERE request_key=?", (request_key,)).fetchone()
            if existing_req:
                inc = c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                                (existing_req["incident_id"],)).fetchone()
                if inc["status"] == "PENDING":
                    pending_retry = inc["id"]
                else:
                    return self._incident_dict(c, inc, replayed=True,
                                               changed=False, completed_existing=False)
            if incident_id:
                taken = c.execute("SELECT id FROM quarantine_incident WHERE id=?",
                                  (incident_id,)).fetchone()
                if taken:
                    raise ECOError("INCIDENT_ID_TAKEN", f"事故编号 {incident_id} 已存在", 409)
            same_fp = c.execute(
                "SELECT * FROM quarantine_incident WHERE request_fingerprint=?",
                (request_fp,)).fetchone()
            if same_fp:
                c.execute("INSERT OR IGNORE INTO quarantine_request(request_key,incident_id,created_at)"
                          " VALUES(?,?,?)", (request_key, same_fp["id"], self._now_str()))
                if same_fp["status"] == "PENDING":
                    pending_retry = same_fp["id"]
                else:
                    return self._incident_dict(c, same_fp, replayed=True,
                                               changed=False, completed_existing=False)

            if not pending_retry:
                affected = self._descendants(c, baseline_id)
                overlap = self._active_overlap(c, list(affected))
                if overlap:
                    raise ECOError("LINEAGE_ALREADY_QUARANTINED",
                                   "该版本或后代已有活动事故隔离，不得重复迁移状态", 409,
                                   {"existing_incident": overlap["incident_id"],
                                    "baseline": overlap["baseline_id"]})
                pending = self._pending_overlap(c, list(affected))
                if pending:
                    raise ECOError("QUARANTINE_PENDING",
                                   "同一谱系已有隔离裁决处于中断/待恢复状态", 409,
                                   {"pending_incident": pending["id"]})

                inc_id = incident_id or self._next_incident_id(c)
                c.execute(
                    "INSERT INTO quarantine_incident(id,baseline_id,batch_no,reason,evidence_json,"
                    "request_fingerprint,registered_by,status,failpoint,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (inc_id, baseline_id, batch_no, reason,
                     json.dumps(evidence, ensure_ascii=False), request_fp, by, "PENDING",
                     failpoint, self._now_str()))
                c.execute("INSERT INTO quarantine_request(request_key,incident_id,created_at) "
                          "VALUES(?,?,?)", (request_key, inc_id, self._now_str()))
                self._journal(c, inc_id, "REGISTERED", by,
                              {"baseline_id": baseline_id, "batch_no": batch_no,
                               "failpoint": failpoint})
                self._audit(c, "quarantine.register", inc_id, by,
                            {"baseline_id": baseline_id, "batch_no": batch_no})

        if pending_retry:
            d = self.finish_isolation(pending_retry, by)
            d["replayed"] = True
            return d
        # 阶段 1 已落盘。此处模拟进程崩溃：阶段 2 由 retry/recover() 完成。
        if failpoint == "AFTER_REGISTER":
            raise ECOError("QUARANTINE_INTERRUPTED",
                           "事故隔离已登记并落盘，阶段2尚未执行；可重试或等待启动恢复", 500,
                           {"incident_id": inc_id,
                            "resume": f"/api/quarantine/incidents/{inc_id}/recover"})
        return self.finish_isolation(inc_id, by)

    def _supersede_eco(self, c, eco_id, reason):
        c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE eco_id=? AND status!='SUPERSEDED'",
                  (eco_id,))
        c.execute("UPDATE signoff SET voided_at=?,voided_reason=? WHERE eco_id=? AND voided_at IS NULL",
                  (self._now_str(), reason, eco_id))
        c.execute(
            "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,received_at)"
            " VALUES(?,?,?,?,?,?)",
            (None, eco_id, None, "QUARANTINED_BASELINE",
             json.dumps({"reason": reason}, ensure_ascii=False), self._now_str()))

    def _invalidate_leases(self, c, eco_id, incident_id, generation):
        for lease in c.execute(
                "SELECT * FROM check_lease WHERE eco_id=? AND state='HELD'", (eco_id,)).fetchall():
            c.execute("UPDATE check_lease SET state='INVALIDATED' WHERE run_id=? AND state='HELD'",
                      (lease["run_id"],))
            c.execute(
                "INSERT INTO lease_event(run_id,eco_id,check_type,gen,event,actor,at,detail_json)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (lease["run_id"], eco_id, lease["check_type"], lease["gen"], "INVALIDATE",
                 "quarantine", self._now_str(),
                 json.dumps({"reason": "incident quarantine", "incident_id": incident_id,
                             "generation": generation}, ensure_ascii=False)))

    def finish_isolation(self, incident_id, by="system"):
        with self.s.tx() as c:
            inc = c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                            (incident_id,)).fetchone()
            if not inc:
                raise ECOError("INCIDENT_NOT_FOUND", f"事故 {incident_id} 不存在", 404)
            if inc["status"] == "ISOLATED":
                return self._incident_dict(c, inc, replayed=True, changed=False,
                                           completed_existing=True)
            if inc["status"] != "PENDING":
                raise ECOError("INCIDENT_NOT_PENDING",
                               f"事故状态 {inc['status']} 不能执行隔离", 409)

            root = self._baseline(c, inc["baseline_id"])
            affected = self._descendants(c, root["id"])
            overlap = self._active_overlap(c, list(affected), exclude_incident=incident_id)
            if overlap:
                raise ECOError("LINEAGE_ALREADY_QUARANTINED",
                               "恢复隔离时发现同一谱系已有其他活动隔离", 409,
                               {"existing_incident": overlap["incident_id"]})
            pending = self._pending_overlap(c, list(affected), exclude_incident=incident_id)
            if pending:
                raise ECOError("QUARANTINE_PENDING",
                               "同一谱系存在其他待恢复隔离，必须先串行恢复", 409,
                               {"pending_incident": pending["id"]})

            ancestor = self._nearest_trusted_ancestor(c, root["id"])
            generation = self._current_generation(c) + 1
            guard_revision = c.execute("SELECT COALESCE(MAX(revision),0) r FROM baseline").fetchone()["r"]
            now = self._now_str()

            for bid, relation in sorted(affected.items(), key=lambda x: self._baseline(c, x[0])["revision"]):
                c.execute(
                    "INSERT INTO quarantine_baseline(incident_id,baseline_id,generation,relation,"
                    "trust_status,marked_at) VALUES(?,?,?,?,?,?)",
                    (incident_id, bid, generation, relation, "UNTRUSTED", now))
                c.execute("UPDATE baseline SET trust_generation=? WHERE id=?", (generation, bid))

            # trunk 回退到最近可信祖先；工作约束保留，但任何未发行 ECO 必须按新信任代次重冻。
            c.execute("UPDATE trunk SET base_id=?,base_revision=? WHERE id=1",
                      (ancestor["id"], ancestor["revision"]))

            marked_ecos = []
            for eco in c.execute(
                    "SELECT * FROM eco WHERE status IN (%s)"
                    % ",".join("?" * len(ACTIVE_STATUSES)), ACTIVE_STATUSES).fetchall():
                parent_affected = eco["parent_baseline_id"] in affected
                previous = eco["status"]
                action = "RELEASE_CANCELLED" if previous == "RELEASING" else "REBASE_REQUIRED"
                if previous == "RELEASING":
                    c.execute("UPDATE release SET state='CANCELLED',finished_at=? WHERE eco_id=? AND state='RELEASING'",
                              (now, eco["id"]))
                    c.execute(
                        "INSERT INTO release_journal(eco_id,event,at,detail_json) VALUES(?,?,?,?)",
                        (eco["id"], "QUARANTINE_CANCELLED", now,
                         json.dumps({"incident_id": incident_id, "generation": generation},
                                    ensure_ascii=False)))
                    c.execute("DELETE FROM module_lock WHERE eco_id=?", (eco["id"],))
                    c.execute(
                        "UPDATE queue_entry SET resolved_at=?,resolution='QUARANTINED' "
                        "WHERE (eco_id=? OR blocker_eco_id=?) AND resolved_at IS NULL",
                        (now, eco["id"], eco["id"]))
                elif previous == "QUEUED":
                    c.execute(
                        "UPDATE queue_entry SET resolved_at=?,resolution='QUARANTINED' "
                        "WHERE (eco_id=? OR blocker_eco_id=?) AND resolved_at IS NULL",
                        (now, eco["id"], eco["id"]))
                self._supersede_eco(
                    c, eco["id"],
                    "incident quarantine: new trust generation; parent_affected=%s"
                    % parent_affected)
                self._invalidate_leases(c, eco["id"], incident_id, generation)
                c.execute(
                    "UPDATE eco SET status='REBASE_REQUIRED',trust_generation=? WHERE id=?",
                    (generation, eco["id"]))
                c.execute(
                    "INSERT INTO quarantine_eco(incident_id,eco_id,generation,previous_status,"
                    "action,marked_at) VALUES(?,?,?,?,?,?)",
                    (incident_id, eco["id"], generation, previous, action, now))
                marked_ecos.append({"eco_id": eco["id"], "previous_status": previous,
                                    "action": action, "parent_affected": parent_affected})

            c.execute(
                "UPDATE quarantine_incident SET status='ISOLATED',generation=?,"
                "trusted_ancestor_id=?,guard_revision=?,isolated_at=? WHERE id=?",
                (generation, ancestor["id"], guard_revision, now, incident_id))
            self._journal(c, incident_id, "ISOLATED", by,
                          {"generation": generation, "root": root["id"],
                           "affected_baselines": sorted(affected),
                           "trusted_ancestor": ancestor["id"],
                           "marked_ecos": marked_ecos, "guard_revision": guard_revision})
            self._audit(c, "quarantine.isolate", incident_id, by,
                        {"generation": generation, "root": root["id"],
                         "affected": sorted(affected), "ancestor": ancestor["id"],
                         "ecos": marked_ecos})
            return self._incident_dict(
                c, c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                             (incident_id,)).fetchone(),
                changed=True, completed_existing=False)

    def recover(self):
        """启动/显式恢复：按注册顺序重做所有已落盘但未完成的隔离裁决。"""
        out = []
        with self.s.lock:
            rows = self.s.q_all(
                "SELECT id FROM quarantine_incident WHERE status='PENDING' ORDER BY created_at,id")
        for r in rows:
            out.append(self.finish_isolation(r["id"], "system.recovery"))
        return {"recovered": out, "count": len(out)}

    # ===== 双角色恢复可信 =====
    def confirm_restore(self, incident_id, role, user, note=""):
        if role not in RESTORE_ROLES:
            raise ECOError("BAD_ROLE", f"恢复确认角色须为 {RESTORE_ROLES}", 400)
        if not user:
            raise ECOError("BAD_REQUEST", "user 必填", 400)
        with self.s.tx() as c:
            inc = c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                            (incident_id,)).fetchone()
            if not inc:
                raise ECOError("INCIDENT_NOT_FOUND", f"事故 {incident_id} 不存在", 404)
            existing_confirm = c.execute(
                "SELECT * FROM quarantine_confirmation WHERE incident_id=? AND role=?",
                (incident_id, role)).fetchone()
            if inc["status"] == "RESTORED":
                if existing_confirm and existing_confirm["user"] == user:
                    return self._incident_dict(c, inc, replayed=True, changed=False,
                                               completed_existing=True)
                raise ECOError("INCIDENT_ALREADY_RESTORED", "事故已恢复，不能再次签认", 409)
            if inc["status"] != "ISOLATED":
                raise ECOError("INCIDENT_NOT_ISOLATED",
                               f"事故状态 {inc['status']} 不可恢复确认", 409)
            if existing_confirm:
                if existing_confirm["user"] == user:
                    return self._incident_dict(c, inc, replayed=True, changed=False,
                                               completed_existing=False)
                raise ECOError("ROLE_ALREADY_CONFIRMED",
                               f"{ROLE_LABELS[role]} 已由 {existing_confirm['user']} 确认", 409,
                               {"existing_user": existing_confirm["user"]})

            active_markers = c.execute(
                "SELECT * FROM quarantine_baseline WHERE incident_id=? AND trust_status='UNTRUSTED'",
                (incident_id,)).fetchall()
            baseline_ids = [r["baseline_id"] for r in active_markers]
            other = self._active_overlap(c, baseline_ids, exclude_incident=incident_id)
            if other:
                raise ECOError("OTHER_QUARANTINE_ACTIVE",
                               "谱系仍被其他活动事故隔离，不能恢复本事故", 409,
                               {"other_incident": other["incident_id"]})
            # 隔离代次内一旦出现任何新发行基线，即视为新分叉，双角色确认也不能恢复。
            fork = c.execute(
                "SELECT * FROM baseline WHERE revision>? ORDER BY revision LIMIT 1",
                (inc["guard_revision"],)).fetchone()
            if fork:
                self._journal(c, incident_id, "RESTORE_REJECTED", user,
                              {"role": role, "reason": "NEW_FORK_DETECTED",
                               "baseline": fork["id"], "guard_revision": inc["guard_revision"]})
                raise ECOError("RESTORE_FORK_DETECTED",
                               "隔离期间谱系发生新分叉/新发行，必须重新评审后再处理", 409,
                               {"new_baseline": fork["id"],
                                "guard_revision": inc["guard_revision"]})

            c.execute(
                "INSERT INTO quarantine_confirmation(incident_id,role,user,note,at) "
                "VALUES(?,?,?,?,?)", (incident_id, role, user, note, self._now_str()))
            self._journal(c, incident_id, "RESTORE_CONFIRMED", user,
                          {"role": role, "user": user, "note": note})
            confirms = c.execute(
                "SELECT role,user FROM quarantine_confirmation WHERE incident_id=?",
                (incident_id,)).fetchall()
            roles = {r["role"]: r["user"] for r in confirms}
            if not all(r in roles for r in RESTORE_ROLES):
                return self._incident_dict(
                    c, c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                                 (incident_id,)).fetchone(),
                    changed=False, awaiting_roles=[r for r in RESTORE_ROLES if r not in roles])
            if len(set(roles.values())) != 2:
                # 正常情况下第二角色会被 DUAL_ROLE 检查挡住；这是数据层纵深防御。
                raise ECOError("DUAL_ROLE_CONFLICT", "两个恢复角色必须由不同自然人确认", 409)

            new_generation = self._current_generation(c) + 1
            now = self._now_str()
            releasing = c.execute("SELECT id FROM eco WHERE status='RELEASING' LIMIT 1").fetchone()
            if releasing:
                raise ECOError("RELEASE_IN_PROGRESS",
                               "存在尚未完成的新发行；恢复可信必须先完成或取消，避免谱系新分叉", 409,
                               {"eco_id": releasing["id"]})
            for eco in c.execute(
                    "SELECT * FROM eco WHERE status IN ('FROZEN','REBASE_REQUIRED','QUEUED')"
            ).fetchall():
                self._supersede_eco(c, eco["id"],
                                    "quarantine restored: trust generation advanced")
                self._invalidate_leases(c, eco["id"], incident_id, new_generation)
                c.execute("UPDATE eco SET status='REBASE_REQUIRED',trust_generation=? WHERE id=?",
                          (new_generation, eco["id"]))
                if eco["status"] == "QUEUED":
                    c.execute(
                        "UPDATE queue_entry SET resolved_at=?,resolution='QUARANTINED' "
                        "WHERE (eco_id=? OR blocker_eco_id=?) AND resolved_at IS NULL",
                        (now, eco["id"], eco["id"]))
                c.execute(
                    "INSERT OR IGNORE INTO quarantine_eco(incident_id,eco_id,generation,"
                    "previous_status,action,marked_at) VALUES(?,?,?,?,?,?)",
                    (incident_id, eco["id"], new_generation, eco["status"],
                     "RESTORE_GENERATION", now))
            c.execute(
                "UPDATE quarantine_baseline SET trust_status='RESTORED',restored_at=? "
                "WHERE incident_id=? AND trust_status='UNTRUSTED'", (now, incident_id))
            c.execute("UPDATE baseline SET trust_generation=? WHERE id IN (%s)"
                      % ",".join("?" * len(baseline_ids)),
                      [new_generation, *baseline_ids])
            c.execute(
                "UPDATE quarantine_eco SET restored_at=? WHERE incident_id=?",
                (now, incident_id))
            tip = c.execute(
                "SELECT b.* FROM baseline b JOIN quarantine_baseline qb ON qb.baseline_id=b.id "
                "WHERE qb.incident_id=? ORDER BY b.revision DESC LIMIT 1",
                (incident_id,)).fetchone()
            c.execute("UPDATE trunk SET base_id=?,base_revision=? WHERE id=1",
                      (tip["id"], tip["revision"]))
            c.execute(
                "UPDATE quarantine_incident SET status='RESTORED',restored_at=? WHERE id=?",
                (now, incident_id))
            self._journal(c, incident_id, "RESTORED", user,
                          {"generation": new_generation, "tip": tip["id"],
                           "confirmations": roles})
            self._audit(c, "quarantine.restore", incident_id, user,
                        {"generation": new_generation, "tip": tip["id"],
                         "confirmations": roles})
            return self._incident_dict(
                c, c.execute("SELECT * FROM quarantine_incident WHERE id=?",
                             (incident_id,)).fetchone(),
                changed=True, restored_generation=new_generation)

    # ===== 查询 / 操作页聚合 =====
    def _incident_dict(self, c, row, *, replayed=False, changed=None, completed_existing=False,
                       awaiting_roles=None, restored_generation=None):
        d = dict(row)
        d["evidence"] = json.loads(d.pop("evidence_json"))
        markers = [dict(r) for r in c.execute(
            "SELECT * FROM quarantine_baseline WHERE incident_id=? ORDER BY generation,baseline_id",
            (row["id"],)).fetchall()]
        d["affected_baselines"] = markers
        d["confirmations"] = [dict(r) for r in c.execute(
            "SELECT * FROM quarantine_confirmation WHERE incident_id=? ORDER BY role",
            (row["id"],)).fetchall()]
        d["awaiting_roles"] = awaiting_roles or [
            r for r in RESTORE_ROLES
            if r not in {x["role"] for x in d["confirmations"]}] if row["status"] == "ISOLATED" else []
        d["replayed"] = replayed
        d["state_changed"] = changed
        d["completed_existing"] = completed_existing
        d["restored_generation"] = restored_generation
        return d

    def incident(self, incident_id):
        with self.s.lock:
            row = self.s.q_one("SELECT * FROM quarantine_incident WHERE id=?", (incident_id,))
            if not row:
                raise ECOError("INCIDENT_NOT_FOUND", f"事故 {incident_id} 不存在", 404)
            return self._incident_dict(self.s.conn, row)

    def list_incidents(self):
        with self.s.lock:
            return [self._incident_dict(self.s.conn, r)
                    for r in self.s.q_all(
                        "SELECT * FROM quarantine_incident ORDER BY created_at,id")]

    def audit(self, incident_id=None, event=None, limit=200):
        sql = "SELECT * FROM quarantine_journal WHERE 1=1"
        args = []
        if incident_id:
            sql += " AND incident_id=?"
            args.append(incident_id)
        if event:
            sql += " AND event=?"
            args.append(event)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(int(limit))
        with self.s.lock:
            rows = self.s.q_all(sql, args)
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.pop("detail_json") or "{}")
            out.append(d)
        return out

    def board(self):
        with self.s.lock:
            conn = self.s.conn
            incidents = self.list_incidents()
            active = conn.execute(
                "SELECT qi.*, qb.baseline_id, qb.relation FROM quarantine_incident qi "
                "JOIN quarantine_baseline qb ON qb.incident_id=qi.id "
                "WHERE qi.status='ISOLATED' AND qb.trust_status='UNTRUSTED' "
                "ORDER BY qi.id, qb.baseline_id").fetchall()
            current_trusted = []
            seen = set()
            for inc in incidents:
                if inc["status"] == "ISOLATED" and inc["trusted_ancestor_id"] not in seen:
                    bid = inc["trusted_ancestor_id"]
                    b = conn.execute("SELECT id,revision,parent_id,fingerprint,trust_generation "
                                     "FROM baseline WHERE id=?", (bid,)).fetchone()
                    current_trusted.append(dict(b) if b else None)
                    seen.add(bid)
            pending_changes = []
            for r in conn.execute(
                    "SELECT qe.*, e.title,e.owner,e.status current_status,e.parent_baseline_id,"
                    "e.freeze_epoch,e.trust_generation eco_trust_generation "
                    "FROM quarantine_eco qe JOIN eco e ON e.id=qe.eco_id "
                    "ORDER BY qe.incident_id,qe.eco_id").fetchall():
                pending_changes.append(dict(r))
            lineage = []
            for b in conn.execute(
                    "SELECT b.id,b.revision,b.parent_id,b.fingerprint,b.trust_generation,"
                    "GROUP_CONCAT(CASE WHEN qb.trust_status='UNTRUSTED' THEN qb.incident_id END, ',') active_incidents "
                    "FROM baseline b LEFT JOIN quarantine_baseline qb ON qb.baseline_id=b.id "
                    "GROUP BY b.id ORDER BY b.revision").fetchall():
                d = dict(b)
                d["active_incidents"] = [x for x in (d["active_incidents"] or "").split(",") if x]
                d["trusted"] = not d["active_incidents"]
                lineage.append(d)
            return {
                "incidents": incidents,
                "affected_lineage": lineage,
                "current_trusted_ancestors": current_trusted,
                "pending_changes": pending_changes,
                "audit": self.audit(limit=100),
                "restore_roles": [{"role": r, "label": ROLE_LABELS[r]} for r in RESTORE_ROLES],
            }
