"""版本化电路拓扑与工程变更影响闭包。

拓扑由“模块实例节点 + 传播边 + 约束引用 + 强制策略”组成。系统根据变更起点做
可达性分析，生成审核前必须复验的实例/模块集合、检查类型，以及每条传播边的人工
可读解释。分析快照不可变，并绑定拓扑版本、拓扑指纹与变更摘要；拓扑更新后旧快照
立即不可用于冻结或发布。
"""
from __future__ import annotations

import copy
import json
import sqlite3
from typing import Any

from .service import ECOError, canon, fp_json
from .store import utcnow

DEFAULT_MAX_CLOSURE_NODES = 500

SEED_TOPOLOGY: dict[str, Any] = {
    "schema": "circuit-topology/1",
    "clock_domains": [
        {"name": "CLK_CORE", "source": "u_clk.core_pll"},
        {"name": "CLK_MEM", "source": "u_clk.mem_div"},
        {"name": "CLK_NOC", "source": "u_clk.noc_pll"},
    ],
    "nodes": [
        {"id": "u_clk", "module": "CLOCK_ROOT", "clock_domain": "CLK_CORE",
         "checks": ["CLOCK_CONSTRAINT_CHECK"]},
        {"id": "u_alu", "module": "alu", "clock_domain": "CLK_CORE",
         "checks": ["FORMAL_EQUIV", "TIMING_STA"]},
        {"id": "u_core", "module": "core", "clock_domain": "CLK_CORE",
         "checks": ["FORMAL_EQUIV", "TIMING_STA"]},
        {"id": "u_l2c", "module": "l2c", "clock_domain": "CLK_MEM",
         "checks": ["FORMAL_EQUIV", "TIMING_STA", "POWER_ANALYSIS", "LAYOUT_DRC"]},
        {"id": "u_noc", "module": "noc", "clock_domain": "CLK_NOC",
         "checks": ["FORMAL_EQUIV", "TIMING_STA", "INTERFACE_CONTRACT_CHECK"]},
        {"id": "u_dbg", "module": "dbg", "clock_domain": "CLK_CORE",
         "checks": ["LINT_INFO"]},
    ],
    "edges": [
        {"from": "u_alu", "to": "u_core", "type": "DATA",
         "reason": "u_core 组合并寄存 u_alu 的运算结果，ALU 变更必须复验 core 时序/等价性"},
        {"from": "u_core", "to": "u_l2c", "type": "DATA",
         "reason": "core 通过异步 FIFO 访问 l2c，存在 CLK_CORE→CLK_MEM 数据交接"},
        {"from": "u_core", "to": "u_noc", "type": "INTERFACE",
         "reason": "core 发起 NoC 事务，接口 valid/ready/credit 契约不得被局部变更破坏"},
        {"from": "u_l2c", "to": "u_noc", "type": "INTERFACE",
         "reason": "l2c 回填 NoC 响应，跨 CLK_MEM→CLK_NOC，必须复验 CDC 与接口契约"},
        {"from": "u_clk", "to": "u_core", "type": "CLOCK",
         "reason": "核心时钟由 u_clk 驱动，时钟约束变化沿时钟树传播"},
        {"from": "u_clk", "to": "u_l2c", "type": "CLOCK",
         "reason": "存储器时钟由 u_clk 分频驱动"},
        {"from": "u_core", "to": "u_dbg", "type": "DATA",
         "reason": "core 将内部观察点连接到调试模块；通常只要求普通等价/Lint 复验，可由设计者说明排除"},
    ],
    "constraint_refs": [
        {"id": "SDC.clk_period_ns", "constraint": "clk_period_ns",
         "targets": ["u_clk", "u_core", "u_alu"],
         "reason": "时钟周期约束直接约束 core/alu 路径"},
        {"id": "SDC.clk_uncertainty_ns", "constraint": "clk_uncertainty_ns",
         "targets": ["u_core", "u_l2c"],
         "reason": "跨时钟域交接使用 uncertainty 余量"},
        {"id": "SDC.max_dynamic_power_mw", "constraint": "max_dynamic_power_mw",
         "targets": ["u_l2c"],
         "reason": "L2 缓存/存储器是动态功耗预算的主要引用节点"},
        {"id": "SDC.target_fmax_ghz", "constraint": "target_fmax_ghz",
         "targets": ["u_core"],
         "reason": "Fmax 目标绑定 core 数据路径"},
    ],
    "policies": [
        {"id": "POLICY_NOC_BOUNDARY", "kind": "MANDATORY_NODE", "node": "u_noc",
         "reason": "NoC 是芯片级发布边界，策略规定任何可达接口契约节点均不得人工排除"},
    ],
}


class ImpactService:
    def __init__(self, store, max_closure_nodes: int = DEFAULT_MAX_CLOSURE_NODES):
        self.s = store
        self.max_closure_nodes = max_closure_nodes

    # ---- 基础辅助 ----
    def _audit(self, c, action: str, entity: str | None, actor: str | None, detail: dict):
        c.execute(
            "INSERT INTO audit_log(actor,action,entity,at,detail_json) VALUES(?,?,?,?,?)",
            (actor, action, entity, utcnow(), json.dumps(detail, ensure_ascii=False)))

    def _graph_row(self, c, version: int | None = None):
        if version is None:
            cur = c.execute("SELECT t.* FROM impact_topology t JOIN impact_current i "
                            "ON t.version=i.version WHERE i.id=1").fetchone()
        else:
            cur = c.execute("SELECT * FROM impact_topology WHERE version=?",
                            (version,)).fetchone()
        if not cur:
            raise ECOError("TOPOLOGY_NOT_FOUND", "电路拓扑版本不存在", 404)
        return cur

    def current_topology(self):
        with self.s.lock:
            row = self._graph_row(self.s.conn)
            graph = json.loads(row["graph_json"])
            return {"version": row["version"], "fingerprint": row["fingerprint"],
                    "status": row["status"], "note": row["note"],
                    "created_by": row["created_by"], "created_at": row["created_at"],
                    "graph": graph}

    def list_topologies(self):
        with self.s.lock:
            rows = self.s.q_all("SELECT version,fingerprint,status,note,created_by,created_at "
                                "FROM impact_topology ORDER BY version")
            return [dict(r) for r in rows]

    # ---- 拓扑规范化与校验 ----
    def _normalize_graph(self, graph: dict) -> dict:
        if not isinstance(graph, dict):
            raise ECOError("BAD_TOPOLOGY", "拓扑必须是对象", 400)
        nodes = graph.get("nodes")
        edges = graph.get("edges", [])
        if not isinstance(nodes, list) or not nodes:
            raise ECOError("BAD_TOPOLOGY", "nodes 必须是非空数组", 400)
        if not isinstance(edges, list):
            raise ECOError("BAD_TOPOLOGY", "edges 必须是数组", 400)

        norm_nodes, node_ids = [], set()
        for n in nodes:
            if not isinstance(n, dict) or not n.get("id") or not n.get("module"):
                raise ECOError("BAD_TOPOLOGY", "每个节点必须包含 id/module", 400,
                               {"node": n})
            node_id = str(n["id"])
            if node_id in node_ids:
                raise ECOError("DUPLICATE_TOPOLOGY_NODE", f"节点 ID 重复: {node_id}", 400,
                               {"node": node_id})
            node_ids.add(node_id)
            checks = n.get("checks", ["FORMAL_EQUIV", "TIMING_STA"])
            if not isinstance(checks, list) or not all(isinstance(x, str) and x for x in checks):
                raise ECOError("BAD_TOPOLOGY", f"节点 {node_id} checks 必须是非空字符串数组",
                               400)
            norm_nodes.append({
                "id": node_id,
                "module": str(n["module"]),
                "clock_domain": str(n.get("clock_domain", "UNSPECIFIED")),
                "checks": list(checks),
            })

        norm_edges, edge_keys = [], set()
        for i, e in enumerate(edges):
            if not isinstance(e, dict) or not e.get("from") or not e.get("to"):
                raise ECOError("BAD_TOPOLOGY", f"边 #{i} 必须包含 from/to", 400, {"edge": e})
            src, dst = str(e["from"]), str(e["to"])
            missing = [x for x in (src, dst) if x not in node_ids]
            if missing:
                raise ECOError("TOPOLOGY_MISSING_NODE",
                               f"边 {src}→{dst} 引用了不存在的节点: {missing}", 400,
                               {"edge": {"from": src, "to": dst}, "missing": missing,
                                "action": "请先创建缺失节点，或删除/修正该传播边"})
            key = (src, dst, str(e.get("type", "DATA")))
            if key in edge_keys:
                raise ECOError("DUPLICATE_TOPOLOGY_EDGE",
                               f"重复传播边: {src}→{dst} ({key[2]})", 400,
                               {"edge": {"from": src, "to": dst, "type": key[2]},
                                "action": "删除重复边，或改用不同关系类型"})
            edge_keys.add(key)
            norm_edges.append({
                "from": src, "to": dst, "type": str(e.get("type", "DATA")),
                "reason": str(e.get("reason", f"{src} 到 {dst} 的电路传播关系")),
                "contract": bool(e.get("contract", False)),
            })

        refs = graph.get("constraint_refs", [])
        if not isinstance(refs, list):
            raise ECOError("BAD_TOPOLOGY", "constraint_refs 必须是数组", 400)
        norm_refs = []
        for r in refs:
            if not isinstance(r, dict) or not r.get("id") or not isinstance(r.get("targets"), list):
                raise ECOError("BAD_TOPOLOGY", "约束引用必须包含 id/targets", 400, {"ref": r})
            targets = [str(x) for x in r["targets"]]
            missing = [x for x in targets if x not in node_ids]
            if missing:
                raise ECOError("TOPOLOGY_MISSING_NODE",
                               f"约束 {r['id']} 引用不存在节点: {missing}", 400,
                               {"constraint_ref": r["id"], "missing": missing,
                                "action": "修正约束引用目标或补全节点"})
            norm_refs.append({"id": str(r["id"]), "constraint": str(r.get("constraint", r["id"])),
                              "targets": targets, "reason": str(r.get("reason", ""))})

        policies = graph.get("policies", [])
        if not isinstance(policies, list):
            raise ECOError("BAD_TOPOLOGY", "policies 必须是数组", 400)
        norm_policies = []
        for p in policies:
            if not isinstance(p, dict) or not p.get("id") or not p.get("node"):
                raise ECOError("BAD_TOPOLOGY", "策略必须包含 id/node", 400, {"policy": p})
            if p["node"] not in node_ids:
                raise ECOError("TOPOLOGY_MISSING_NODE",
                               f"策略 {p['id']} 引用不存在节点 {p['node']}", 400,
                               {"policy": p["id"], "missing": [p["node"]],
                                "action": "修正策略目标节点或补全节点"})
            norm_policies.append({"id": str(p["id"]),
                                  "kind": str(p.get("kind", "MANDATORY_NODE")),
                                  "node": str(p["node"]),
                                  "reason": str(p.get("reason", "策略强制复验节点"))})

        return {
            "schema": "circuit-topology/1",
            "clock_domains": copy.deepcopy(graph.get("clock_domains", [])),
            "nodes": sorted(norm_nodes, key=lambda x: x["id"]),
            "edges": sorted(norm_edges, key=lambda x: (x["from"], x["to"], x["type"])),
            "constraint_refs": sorted(norm_refs, key=lambda x: x["id"]),
            "policies": sorted(norm_policies, key=lambda x: x["id"]),
        }

    def _cycle_path(self, graph: dict) -> list[str] | None:
        adj: dict[str, list[str]] = {n["id"]: [] for n in graph["nodes"]}
        for e in graph["edges"]:
            adj[e["from"]].append(e["to"])
        color: dict[str, int] = {n: 0 for n in adj}
        stack: list[str] = []

        def dfs(node: str) -> list[str] | None:
            color[node] = 1
            stack.append(node)
            for nxt in adj[node]:
                if color[nxt] == 1:
                    start = stack.index(nxt)
                    return stack[start:] + [nxt]
                if color[nxt] == 0:
                    found = dfs(nxt)
                    if found:
                        return found
            stack.pop()
            color[node] = 2
            return None

        for node in sorted(adj):
            if color[node] == 0:
                found = dfs(node)
                if found:
                    return found
        return None

    def validate_topology(self, graph: dict) -> dict:
        norm = self._normalize_graph(graph)
        cycle = self._cycle_path(norm)
        if cycle:
            raise ECOError("TOPOLOGY_CYCLE_DETECTED",
                           f"拓扑存在传播环: {' → '.join(cycle)}", 400,
                           {"cycle": cycle,
                            "action": "断开环上的一条反馈/组合环路，或将反馈边标记为独立时序弧后再发布"})
        return norm

    # ---- 拓扑发布 ----
    def publish_topology(self, graph: dict, by: str, note: str = ""):
        if not by:
            raise ECOError("BAD_REQUEST", "by 必填", 400)
        norm = self.validate_topology(graph)
        topo_fp = fp_json(norm)
        with self.s.tx() as c:
            if c.execute("SELECT 1 FROM eco WHERE status='RELEASING'").fetchone():
                raise ECOError("RELEASE_IN_PROGRESS",
                               "发布中断/进行中禁止更新关系图，避免旧闭包进入发布", 409)
            cur = c.execute("SELECT version FROM impact_current WHERE id=1").fetchone()
            old_version = cur["version"] if cur else 0
            if c.execute("SELECT 1 FROM impact_topology WHERE fingerprint=? AND status='CURRENT'",
                         (topo_fp,)).fetchone():
                row = self._graph_row(c)
                return {"deduped": True, "version": row["version"], "fingerprint": topo_fp}
            version = c.execute("SELECT COALESCE(MAX(version),0)+1 v FROM impact_topology"
                                ).fetchone()["v"]
            c.execute("INSERT INTO impact_topology(version,fingerprint,graph_json,status,note,"
                      "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                      (version, topo_fp, json.dumps(norm, ensure_ascii=False), "CURRENT",
                       note, by, utcnow()))
            c.execute("UPDATE impact_topology SET status='SUPERSEDED' WHERE version!=?",
                      (version,))
            c.execute(
                "INSERT INTO impact_current(id,version) VALUES(1,?) "
                "ON CONFLICT(id) DO UPDATE SET version=excluded.version",
                (version,))
            c.execute("UPDATE impact_snapshot SET status='TOPOLOGY_SUPERSEDED' "
                      "WHERE status='CURRENT' OR status='SUPERSEDED'")

            frozen = c.execute("SELECT * FROM eco WHERE status='FROZEN'").fetchall()
            invalidated = []
            for eco in frozen:
                c.execute("UPDATE eco SET status='REBASE_REQUIRED' WHERE id=?", (eco["id"],))
                c.execute("UPDATE check_run SET status='SUPERSEDED' WHERE eco_id=? "
                          "AND status!='SUPERSEDED'", (eco["id"],))
                c.execute("UPDATE signoff SET voided_at=?,voided_reason=? "
                          "WHERE eco_id=? AND voided_at IS NULL",
                          (utcnow(), "circuit topology updated", eco["id"]))
                c.execute(
                    "INSERT INTO rejected_result(run_id,eco_id,check_type,reason,detail_json,"
                    "received_at) VALUES(?,?,?,?,?,?)",
                    (None, eco["id"], None, "TOPOLOGY_CHANGED",
                     json.dumps({"old_topology_version": old_version,
                                 "new_topology_version": version}, ensure_ascii=False), utcnow()))
                invalidated.append(eco["id"])
            self._audit(c, "topology.publish", f"topology:v{version}", by,
                        {"fingerprint": topo_fp, "note": note,
                         "invalidated_frozen_ecos": invalidated})
            return {"deduped": False, "version": version, "fingerprint": topo_fp,
                    "invalidated_frozen_ecos": invalidated}

    # ---- 闭包计算 ----
    def _index(self, graph: dict):
        nodes = {n["id"]: n for n in graph["nodes"]}
        out: dict[str, list[dict]] = {nid: [] for nid in nodes}
        for e in graph["edges"]:
            out[e["from"]].append(e)
        constraints: dict[str, list[dict]] = {nid: [] for nid in nodes}
        for ref in graph["constraint_refs"]:
            for nid in ref["targets"]:
                constraints[nid].append(ref)
        policies: dict[str, list[dict]] = {nid: [] for nid in nodes}
        for p in graph["policies"]:
            policies[p["node"]].append(p)
        return nodes, out, constraints, policies

    def _edge_span(self, edge: dict, nodes: dict) -> dict:
        src_clk = nodes[edge["from"]]["clock_domain"]
        dst_clk = nodes[edge["to"]]["clock_domain"]
        crossing = bool(src_clk != dst_clk)
        interface = edge["type"] == "INTERFACE" or edge["contract"]
        return {"source_clock": src_clk, "target_clock": dst_clk,
                "cross_clock": crossing, "interface_contract": interface}

    def _traverse(self, graph: dict, roots: list[str], blocked: set[str]):
        nodes, out, constraints, policies = self._index(graph)
        order: list[str] = []
        reasons: dict[str, list[dict]] = {nid: [] for nid in nodes}
        parents: dict[str, tuple[str, dict] | None] = {nid: None for nid in nodes}
        traversed: list[dict] = []
        seen_edges = set()
        queue = list(roots)
        reachable = set()
        for r in roots:
            if r not in blocked:
                reachable.add(r)

        while queue:
            nid = queue.pop(0)
            if nid in blocked or nid not in reachable:
                continue
            if nid not in order:
                order.append(nid)
            for edge in out.get(nid, []):
                dst = edge["to"]
                if dst in blocked:
                    continue
                ekey = (edge["from"], edge["to"], edge["type"])
                if ekey not in seen_edges:
                    seen_edges.add(ekey)
                    span = self._edge_span(edge, nodes)
                    idx = len(traversed)
                    explanation = (f"{edge['from']}({span['source_clock']}) "
                                   f"--{edge['type']}--> {edge['to']}({span['target_clock']})")
                    if span["cross_clock"]:
                        explanation += "；跨时钟域，需要 CDC/异步交接复验"
                    if span["interface_contract"]:
                        explanation += "；跨越接口契约边界，需要契约复验"
                    explanation += f"。原因：{edge['reason']}"
                    traversed.append({"seq": idx + 1, **edge, **span,
                                      "explanation": explanation})
                if dst not in reachable:
                    reachable.add(dst)
                    parents[dst] = (nid, edge)
                    queue.append(dst)

        for r in roots:
            if r in reachable:
                reasons[r].append({"kind": "CHANGE_ORIGIN", "mandatory": True,
                                   "detail": "变更起点本身必须复验，不能人工排除"})
        for edge in traversed:
            base = {"kind": "PROPAGATION_EDGE", "edge": {"from": edge["from"], "to": edge["to"],
                                                         "type": edge["type"]},
                    "detail": edge["reason"]}
            reasons[edge["to"]].append(base)
            if edge["cross_clock"]:
                reasons[edge["to"]].append(
                    {"kind": "CLOCK_CROSSING", "mandatory": True,
                     "edge": base["edge"],
                     "detail": f"{edge['source_clock']}→{edge['target_clock']} 跨时钟域"})
            if edge["interface_contract"]:
                reasons[edge["to"]].append(
                    {"kind": "INTERFACE_CONTRACT", "mandatory": True,
                     "edge": base["edge"], "detail": "接口契约边界强制复验"})
        for nid in order:
            for ref in constraints.get(nid, []):
                reasons[nid].append({"kind": "CONSTRAINT_REF", "mandatory": True,
                                     "constraint_ref": ref["id"],
                                     "constraint": ref["constraint"], "detail": ref["reason"]})
            for pol in policies.get(nid, []):
                if pol["kind"] == "MANDATORY_NODE":
                    reasons[nid].append({"kind": "POLICY", "mandatory": True,
                                         "policy": pol["id"], "detail": pol["reason"]})

        candidates = []
        checks: dict[str, dict] = {}
        for nid in order:
            node = nodes[nid]
            node_reasons = reasons.get(nid, [])
            mandatory_reasons = [r for r in node_reasons if r.get("mandatory")]
            candidates.append({
                "node_id": nid, "module": node["module"], "clock_domain": node["clock_domain"],
                "mandatory": bool(mandatory_reasons), "mandatory_reasons": mandatory_reasons,
                "reasons": node_reasons, "excludable": not mandatory_reasons,
                "excluded": nid in blocked,
                "path": self._path_to(parents, nid, roots),
            })
            for check in node["checks"]:
                item = checks.setdefault(check, {"check_type": check, "nodes": [], "edges": [],
                                                 "reasons": set()})
                item["nodes"].append(nid)
                item["reasons"].add(f"节点 {nid} 的检查目录要求 {check}")
            for ref in constraints.get(nid, []):
                check = "CONSTRAINT_REFERENCE_CHECK"
                item = checks.setdefault(check, {"check_type": check, "nodes": [], "edges": [],
                                                 "reasons": set()})
                item["nodes"].append(nid)
                item["reasons"].add(f"节点 {nid} 引用约束 {ref['constraint']}")
        for edge in traversed:
            new_checks = []
            if edge["cross_clock"]:
                new_checks.append(("CDC_VERIFY", "跨时钟域传播边"))
            if edge["interface_contract"]:
                new_checks.append(("INTERFACE_CONTRACT_CHECK", "接口契约传播边"))
            if edge["type"] == "CLOCK":
                new_checks.append(("CLOCK_TREE_REVIEW", "时钟树传播边"))
            for check, why in new_checks:
                item = checks.setdefault(check, {"check_type": check, "nodes": [], "edges": [],
                                                 "reasons": set()})
                item["edges"].append({"from": edge["from"], "to": edge["to"], "type": edge["type"]})
                item["reasons"].add(why)

        check_out = []
        for check in sorted(checks):
            item = checks[check]
            check_out.append({"check_type": check,
                              "nodes": sorted(set(item["nodes"])),
                              "edges": item["edges"],
                              "reasons": sorted(item["reasons"])})
        accepted = [c for c in candidates if not c["excluded"]]
        return order, candidates, accepted, traversed, parents, check_out

    def _path_to(self, parents, node, roots):
        if node in roots:
            return [node]
        path = [node]
        cur = node
        guard = set()
        while cur not in roots and cur not in guard:
            guard.add(cur)
            parent = parents.get(cur)
            if not parent:
                break
            cur = parent[0]
            path.append(cur)
        return list(reversed(path))

    def _build_result(self, graph, topo_row, roots, change_summary, blocked, exclusions,
                      snapshot_id=None, revision=1, parent_snapshot_id=None):
        version = topo_row["version"]
        order, candidates, accepted, edges, parents, checks = self._traverse(
            graph, roots, blocked)
        if len(order) > self.max_closure_nodes:
            raise ECOError("IMPACT_CLOSURE_TOO_LARGE",
                           f"影响闭包包含 {len(order)} 个节点，超过上限 "
                           f"{self.max_closure_nodes}", 400,
                           {"size": len(order), "limit": self.max_closure_nodes,
                            "action": "拆分变更起点/分批提交流程，或由管理员显式调整闭包大小限制"})
        mandatory_full = {c["node_id"] for c in
                          self._traverse(graph, roots, set())[1] if c["mandatory"]}
        accepted_ids = {c["node_id"] for c in accepted}
        missing_mandatory = sorted(mandatory_full - accepted_ids)
        if missing_mandatory:
            full = {c["node_id"]: c for c in self._traverse(graph, roots, set())[1]}
            conflicts = []
            for nid in missing_mandatory:
                conflicts.append({
                    "node": nid,
                    "mandatory_reasons": full[nid]["mandatory_reasons"],
                    "path_when_not_excluded": full[nid]["path"],
                    "blocked_by_exclusions": sorted(blocked),
                    "action": "恢复该强制节点路径上的人工排除项，或改走策略例外流程",
                })
            raise ECOError("MANUAL_EXCLUSION_CONFLICT",
                           f"人工排除会切断强制复验节点: {missing_mandatory}", 409,
                           {"conflicts": conflicts})

        result = {
            "schema": "impact-closure/1",
            "snapshot_id": snapshot_id,
            "revision": revision,
            "parent_snapshot_id": parent_snapshot_id,
            "scope": None,
            "topology_version": version,
            "topology_fingerprint": topo_row["fingerprint"],
            "roots": sorted(roots),
            "change_summary": copy.deepcopy(change_summary),
            "accepted_nodes": [c["node_id"] for c in accepted],
            "accepted_modules": sorted({c["module"] for c in accepted}),
            "excluded_nodes": sorted(blocked),
            "candidates": candidates,
            "propagation_edges": edges,
            "check_types": checks,
            "exclusions": exclusions,
            "counts": {"candidates": len(candidates), "accepted": len(accepted),
                       "excluded": len(blocked), "edges": len(edges),
                       "check_types": len(checks)},
        }
        stable = {k: v for k, v in result.items()
                  if k not in ("snapshot_id", "status", "current")}
        result["result_fingerprint"] = fp_json(stable)
        return result

    def compute(self, scope: str, roots: list[str], change_summary: dict | None = None,
                by: str = "system", c=None):
        if c is None:
            with self.s.tx() as conn:
                return self._compute(conn, scope, roots, change_summary, by)
        return self._compute(c, scope, roots, change_summary, by)

    def _compute(self, c, scope: str, roots: list[str], change_summary: dict | None, by: str):
        if not scope:
            raise ECOError("BAD_REQUEST", "scope 必填", 400)
        roots = sorted({str(r) for r in (roots or [])})
        if not roots:
            raise ECOError("EMPTY_CHANGE_ROOTS", "至少需要一个变更起点节点", 400)
        topo = self._graph_row(c)
        graph = json.loads(topo["graph_json"])
        missing = [r for r in roots if r not in {n["id"] for n in graph["nodes"]}]
        if missing:
            raise ECOError("CHANGE_ROOT_NOT_FOUND", f"变更起点不存在于拓扑 v{topo['version']}: {missing}",
                           400, {"missing": missing, "topology_version": topo["version"],
                                 "action": "修正实例 ID，或先在新拓扑版本中创建该节点"})
        summary = change_summary or {}
        input_fp = fp_json({"scope": scope, "roots": roots, "change_summary": summary})
        request_id = f"REQ-{scope}:{input_fp}:t{topo['version']}"
        existing_req = c.execute("SELECT * FROM impact_request WHERE id=?",
                                 (request_id,)).fetchone()
        if existing_req:
            snap = c.execute("SELECT * FROM impact_snapshot WHERE request_id=? AND revision=1",
                             (request_id,)).fetchone()
            if snap:
                return self._snapshot_dict(snap, c, replayed=True)

        blocked, exclusions = set(), []
        result = self._build_result(graph, dict(topo), roots, summary, blocked, exclusions)
        snap_id = f"CL-{input_fp}-t{topo['version']}-r1"
        result["snapshot_id"] = snap_id
        result["scope"] = scope
        result_fp = fp_json({k: v for k, v in result.items()
                             if k not in ("snapshot_id", "status", "current")})
        try:
            c.execute("INSERT OR IGNORE INTO impact_request(id,scope,input_fingerprint,"
                      "topology_version,created_at,created_by) VALUES(?,?,?,?,?,?)",
                      (request_id, scope, input_fp, topo["version"], utcnow(), by))
            c.execute(
                "INSERT INTO impact_snapshot(id,request_id,scope,revision,parent_snapshot_id,"
                "topology_version,topology_fingerprint,input_fingerprint,exclusion_fingerprint,"
                "result_fingerprint,status,result_json,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (snap_id, request_id, scope, 1, None, topo["version"], topo["fingerprint"],
                 input_fp, fp_json([]), result_fp, "CURRENT",
                 json.dumps(result, ensure_ascii=False), by, utcnow()))
        except sqlite3.IntegrityError:
            row = c.execute(
                "SELECT s.* FROM impact_snapshot s JOIN impact_latest l "
                "ON l.snapshot_id=s.id WHERE l.scope=? AND l.input_fingerprint=? "
                "ORDER BY s.revision DESC LIMIT 1", (scope, input_fp)).fetchone()
            if row:
                return self._snapshot_dict(row, c, replayed=True)
            raise
        c.execute(
            "INSERT INTO impact_latest(scope,input_fingerprint,snapshot_id,topology_version) "
            "VALUES(?,?,?,?) ON CONFLICT(scope,input_fingerprint) DO UPDATE SET "
            "snapshot_id=excluded.snapshot_id,topology_version=excluded.topology_version",
            (scope, input_fp, snap_id, topo["version"]))
        self._audit(c, "impact.auto", snap_id, by,
                    {"scope": scope, "roots": roots, "topology_version": topo["version"],
                     "topology_fingerprint": topo["fingerprint"],
                     "change_summary": summary, "counts": result["counts"],
                     "result_fingerprint": result_fp,
                     "conclusion": "AUTO_ACCEPTED_FULL_CLOSURE"})
        return self._snapshot_dict(
            c.execute("SELECT * FROM impact_snapshot WHERE id=?", (snap_id,)).fetchone(), c)

    def resolve_roots_for_modules(self, c, modules: list[str], root_instances: list[str] | None):
        topo = self._graph_row(c)
        graph = json.loads(topo["graph_json"])
        by_module: dict[str, list[str]] = {}
        for n in graph["nodes"]:
            by_module.setdefault(n["module"], []).append(n["id"])
        explicit = {str(x) for x in (root_instances or [])}
        missing_explicit = [x for x in explicit if x not in {n["id"] for n in graph["nodes"]}]
        if missing_explicit:
            raise ECOError("CHANGE_ROOT_NOT_FOUND",
                           f"显式变更起点不存在: {missing_explicit}", 400,
                           {"missing": missing_explicit, "topology_version": topo["version"]})
        roots = set(explicit)
        ambiguous = []
        for m in modules:
            instances = by_module.get(m, [])
            if explicit:
                matching = [x for x in instances if x in explicit]
                if matching:
                    roots.update(matching)
                    continue
            if not instances:
                raise ECOError("CHANGE_ROOT_NOT_FOUND",
                               f"模块 {m} 在当前拓扑中没有可作为变更起点的实例", 400,
                               {"module": m, "topology_version": topo["version"],
                                "action": "先发布包含该模块实例的拓扑版本，或使用 root_instances 指定"})
            if len(instances) > 1:
                ambiguous.append({"module": m, "instances": instances})
            else:
                roots.add(instances[0])
        if ambiguous:
            raise ECOError("AMBIGUOUS_MODULE_INSTANCE",
                           "模块存在多个实例，必须通过 root_instances 显式指定变更起点", 409,
                           {"ambiguous": ambiguous,
                            "action": "在创建 ECO 请求中传入 root_instances，明确修改起点实例"})
        return sorted(roots), topo

    # ---- 人工排除 ----
    def exclude(self, snapshot_id: str, exclusions: list[dict], by: str):
        if not by:
            raise ECOError("BAD_REQUEST", "by 必填", 400)
        cleaned = []
        seen = set()
        for item in exclusions or []:
            if not isinstance(item, dict) or not item.get("node"):
                raise ECOError("BAD_REQUEST", "排除项必须包含 node", 400, {"item": item})
            node = str(item["node"])
            reason = str(item.get("reason", "")).strip()
            if not reason:
                raise ECOError("EXCLUSION_REASON_REQUIRED",
                               f"排除节点 {node} 必须填写理由", 400, {"node": node,
                                "action": "补充可审计的技术理由后再提交；强制节点不可排除"})
            if node in seen:
                continue
            seen.add(node)
            cleaned.append({"node": node, "reason": reason, "by": by, "at": utcnow()})
        with self.s.tx() as c:
            return self._exclude(c, snapshot_id, cleaned, by)

    def _exclude(self, c, snapshot_id: str, cleaned: list[dict], by: str):
        snap = c.execute("SELECT * FROM impact_snapshot WHERE id=?", (snapshot_id,)).fetchone()
        if not snap:
            raise ECOError("IMPACT_SNAPSHOT_NOT_FOUND", f"影响闭包快照 {snapshot_id} 不存在", 404)
        latest = c.execute("SELECT * FROM impact_latest WHERE scope=? AND input_fingerprint=?",
                           (snap["scope"], snap["input_fingerprint"])).fetchone()
        if not latest or latest["snapshot_id"] != snapshot_id or snap["status"] != "CURRENT":
            current_id = latest["snapshot_id"] if latest else None
            if snap["status"] != "CURRENT":
                raise ECOError("IMPACT_SNAPSHOT_STALE",
                               f"拓扑已更新，旧闭包 {snapshot_id} 不可修改或用于审核", 409,
                               {"snapshot_id": snapshot_id, "status": snap["status"],
                                "action": "按新拓扑重新计算闭包后再处理人工排除"})
            raise ECOError("IMPACT_SNAPSHOT_NOT_CURRENT",
                           "只能在当前闭包版本上提交人工排除", 409,
                           {"requested": snapshot_id, "current_snapshot_id": current_id,
                            "action": "先打开当前快照，再基于最新候选节点提交排除"})

        topo = self._graph_row(c, snap["topology_version"])
        graph = json.loads(topo["graph_json"])
        # roots/change_summary 从未变快照中读取，保证人工覆盖严格针对同一输入。
        old_result = json.loads(snap["result_json"])
        roots = old_result["roots"]
        change_summary = old_result["change_summary"]
        blocked = {x["node"] for x in cleaned}
        node_ids = {n["id"] for n in graph["nodes"]}
        unknown = sorted(blocked - node_ids)
        if unknown:
            raise ECOError("CHANGE_ROOT_NOT_FOUND", f"排除节点不存在: {unknown}", 400,
                           {"missing": unknown, "action": "刷新候选列表后重新提交"})
        mandatory = {cand["node_id"]: cand["mandatory_reasons"]
                     for cand in old_result["candidates"] if cand["mandatory"]}
        forbidden = sorted(blocked & set(mandatory))
        if forbidden:
            raise ECOError("MANDATORY_EXCLUSION_FORBIDDEN",
                           f"跨时钟/接口契约/约束/策略强制节点不能排除: {forbidden}", 409,
                           {"conflicts": [{"node": n, "mandatory_reasons": mandatory[n]}
                                          for n in forbidden],
                            "action": "移除这些排除项；如有策略例外，走线下 CCB 例外并更新策略拓扑"})

        result = self._build_result(graph, dict(topo), roots, change_summary, blocked, cleaned,
                                    revision=0, parent_snapshot_id=snapshot_id)
        ex_fp = fp_json(sorted((x["node"], x["reason"]) for x in cleaned))
        existing = c.execute(
            "SELECT * FROM impact_snapshot WHERE request_id=? AND exclusion_fingerprint=?",
            (snap["request_id"], ex_fp)).fetchone()
        if existing:
            return self._snapshot_dict(existing, c, replayed=True)

        revision = c.execute("SELECT COALESCE(MAX(revision),0)+1 r FROM impact_snapshot "
                             "WHERE request_id=?", (snap["request_id"],)).fetchone()["r"]
        new_id = f"CL-{snap['input_fingerprint']}-t{snap['topology_version']}-r{revision}"
        result["snapshot_id"] = new_id
        result["scope"] = snap["scope"]
        result["revision"] = revision
        result["parent_snapshot_id"] = snapshot_id
        result_fp = fp_json({k: v for k, v in result.items()
                             if k not in ("snapshot_id", "status", "current")})
        c.execute("UPDATE impact_snapshot SET status='SUPERSEDED' WHERE id=?", (snapshot_id,))
        c.execute(
            "INSERT INTO impact_snapshot(id,request_id,scope,revision,parent_snapshot_id,"
            "topology_version,topology_fingerprint,input_fingerprint,exclusion_fingerprint,"
            "result_fingerprint,status,result_json,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (new_id, snap["request_id"], snap["scope"], revision, snapshot_id,
             snap["topology_version"], snap["topology_fingerprint"], snap["input_fingerprint"],
             ex_fp, result_fp, "CURRENT",
             json.dumps(result, ensure_ascii=False), by, utcnow()))
        c.execute("UPDATE impact_latest SET snapshot_id=? WHERE scope=? AND input_fingerprint=?",
                  (new_id, snap["scope"], snap["input_fingerprint"]))
        for item in cleaned:
            c.execute(
                "INSERT INTO impact_override(snapshot_id,parent_snapshot_id,scope,node_id,"
                "reason,by,created_at) VALUES(?,?,?,?,?,?,?)",
                (new_id, snapshot_id, snap["scope"], item["node"], item["reason"], by, utcnow()))
        self._audit(c, "impact.override", new_id, by,
                    {"scope": snap["scope"], "parent_snapshot_id": snapshot_id,
                     "topology_version": snap["topology_version"],
                     "exclusions": cleaned, "auto_result_fingerprint":
                     json.loads(snap["result_json"])["result_fingerprint"],
                     "manual_result_fingerprint": result_fp,
                     "conclusion": "MANUAL_OVERRIDE_WITH_REASON"})
        return self._snapshot_dict(
            c.execute("SELECT * FROM impact_snapshot WHERE id=?", (new_id,)).fetchone(), c)

    # ---- 查询 ----
    def _snapshot_dict(self, row, c=None, replayed=False):
        d = dict(row)
        result = json.loads(d.pop("result_json"))
        current = False
        topology_current = False
        if c is not None:
            latest = c.execute("SELECT 1 FROM impact_latest WHERE scope=? AND input_fingerprint=? "
                               "AND snapshot_id=?", (row["scope"], row["input_fingerprint"],
                                                     row["id"])).fetchone()
            current = bool(latest) and row["status"] == "CURRENT"
            t = c.execute("SELECT version FROM impact_current WHERE id=1").fetchone()
            topology_current = t and t["version"] == row["topology_version"]
        d["result"] = result
        d["current"] = current
        d["topology_current"] = topology_current
        d["replayed"] = replayed
        d["usable_for_review"] = current and topology_current and row["status"] == "CURRENT"
        return d

    def get_snapshot(self, snapshot_id: str):
        with self.s.lock:
            row = self.s.q_one("SELECT * FROM impact_snapshot WHERE id=?", (snapshot_id,))
            if not row:
                raise ECOError("IMPACT_SNAPSHOT_NOT_FOUND",
                               f"影响闭包快照 {snapshot_id} 不存在", 404)
            return self._snapshot_dict(row, self.s.conn)

    def list_audit(self, scope: str | None = None, snapshot_id: str | None = None,
                   limit: int = 100):
        sql = ("SELECT seq,actor,action,entity,at,detail_json FROM audit_log "
               "WHERE action LIKE 'impact.%' OR action='topology.publish'")
        args = []
        if scope:
            sql += " AND json_extract(detail_json,'$.scope')=?"
            args.append(scope)
        if snapshot_id:
            sql += " AND (entity=? OR json_extract(detail_json,'$.parent_snapshot_id')=?)"
            args.extend([snapshot_id, snapshot_id])
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        with self.s.lock:
            return [dict(r) for r in self.s.q_all(sql, args)]

    def assert_snapshot_usable(self, c, snapshot_id: str | None):
        if not snapshot_id:
            raise ECOError("IMPACT_REQUIRED",
                           "进入审核/冻结前必须先计算电路影响闭包", 409,
                           {"action": "调用影响闭包计算接口，确认候选节点与检查类型"})
        row = c.execute("SELECT * FROM impact_snapshot WHERE id=?", (snapshot_id,)).fetchone()
        if not row:
            raise ECOError("IMPACT_SNAPSHOT_NOT_FOUND",
                           f"影响闭包快照 {snapshot_id} 不存在", 404)
        d = self._snapshot_dict(row, c)
        if not d["usable_for_review"]:
            raise ECOError("IMPACT_SNAPSHOT_STALE",
                           "影响闭包不是当前版本：拓扑或人工排除已更新，旧结果不得冻结/发布",
                           409, {"snapshot_id": snapshot_id, "status": row["status"],
                                 "current": d["current"], "topology_current": d["topology_current"],
                                 "action": "重新计算闭包并重新确认人工排除后再冻结/发布"})
        return d

    def recompute_eco(self, c, impact_input: dict):
        return self._compute(c, impact_input["scope"], impact_input["roots"],
                             impact_input.get("change_summary", {}),
                             impact_input.get("by", "system"))
