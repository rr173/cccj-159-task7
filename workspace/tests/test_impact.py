"""电路影响闭包领域不变量。"""
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.impact import DEFAULT_MAX_CLOSURE_NODES, ImpactService, SEED_TOPOLOGY
from app.runner import run_all_pending
from app.service import ECOError, ECOService, ROLE_METHOD, ROLE_TIMING
from app.store import Store


def fresh():
    store = Store(":memory:")
    return ECOService(store), ImpactService(store)


class ImpactClosureTest(unittest.TestCase):
    def test_seed_closure_from_alu_contains_cdc_contract_and_explains_edges(self):
        _, impact = fresh()
        snap = impact.compute("demo", ["u_alu"], {"change": "ALU retiming"}, "wei.dong")
        r = snap["result"]
        self.assertEqual(r["accepted_nodes"],
                         ["u_alu", "u_core", "u_dbg", "u_l2c", "u_noc"])
        self.assertEqual(r["accepted_modules"],
                         ["alu", "core", "dbg", "l2c", "noc"])
        check_types = {x["check_type"] for x in r["check_types"]}
        self.assertIn("CDC_VERIFY", check_types)
        self.assertIn("INTERFACE_CONTRACT_CHECK", check_types)
        self.assertIn("CONSTRAINT_REFERENCE_CHECK", check_types)
        edge_text = "\n".join(e["explanation"] for e in r["propagation_edges"])
        self.assertIn("跨时钟域", edge_text)
        self.assertIn("接口契约", edge_text)
        self.assertTrue(snap["usable_for_review"])

    def test_same_input_returns_original_snapshot(self):
        _, impact = fresh()
        a = impact.compute("x", ["u_alu"], {"v": 1}, "u")
        b = impact.compute("x", ["u_alu"], {"v": 1}, "u")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(a["result_fingerprint"], b["result_fingerprint"])

    def test_optional_exclusion_requires_reason_and_appends_version(self):
        _, impact = fresh()
        a = impact.compute("x", ["u_core"], {}, "u")
        with self.assertRaises(ECOError) as cm:
            impact.exclude(a["id"], [{"node": "u_alu", "reason": ""}], "designer")
        self.assertEqual(cm.exception.code, "EXCLUSION_REASON_REQUIRED")
        b = impact.exclude(a["id"], [{"node": "u_dbg", "reason": "只改 core 主数据路径，调试观察点未改"}], "designer")
        self.assertEqual(b["revision"], 2)
        self.assertEqual(b["parent_snapshot_id"], a["id"])
        self.assertEqual(b["result"]["excluded_nodes"], ["u_dbg"])
        old = impact.get_snapshot(a["id"])
        self.assertFalse(old["current"])
        self.assertTrue(b["current"])

    def test_mandatory_cross_clock_contract_policy_cannot_be_excluded(self):
        _, impact = fresh()
        snap = impact.compute("x", ["u_alu"], {}, "u")
        for node in ("u_l2c", "u_noc"):
            with self.assertRaises(ECOError) as cm:
                impact.exclude(snap["id"],
                               [{"node": node, "reason": "try skip"}], "designer")
            self.assertEqual(cm.exception.code, "MANDATORY_EXCLUSION_FORBIDDEN")

    def test_exclusion_conflict_when_cutting_mandatory_path(self):
        _, impact = fresh()
        graph = {
            "nodes": [
                {"id": "a", "module": "m1", "clock_domain": "C1"},
                {"id": "b", "module": "m2", "clock_domain": "C1"},
                {"id": "c", "module": "m3", "clock_domain": "C2"},
            ],
            "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}],
            "policies": [{"id": "p", "node": "c", "reason": "强制"}],
        }
        impact.publish_topology(graph, "admin")
        snap = impact.compute("x", ["a"], {}, "u")
        with self.assertRaises(ECOError) as cm:
            impact.exclude(snap["id"], [{"node": "b", "reason": "b 不相关"}], "u")
        self.assertEqual(cm.exception.code, "MANUAL_EXCLUSION_CONFLICT")
        self.assertEqual(cm.exception.extra["conflicts"][0]["node"], "c")

    def test_missing_root_and_topology_missing_node_are_actionable(self):
        _, impact = fresh()
        with self.assertRaises(ECOError) as cm:
            impact.compute("x", ["missing"], {}, "u")
        self.assertEqual(cm.exception.code, "CHANGE_ROOT_NOT_FOUND")
        bad = {"nodes": [{"id": "a", "module": "m"}],
               "edges": [{"from": "a", "to": "b"}]}
        with self.assertRaises(ECOError) as cm:
            impact.publish_topology(bad, "admin")
        self.assertEqual(cm.exception.code, "TOPOLOGY_MISSING_NODE")
        self.assertIn("action", cm.exception.extra)

    def test_cycle_returns_path_and_action(self):
        _, impact = fresh()
        graph = {"nodes": [{"id": "a", "module": "m"}, {"id": "b", "module": "m"}],
                 "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}]}
        with self.assertRaises(ECOError) as cm:
            impact.publish_topology(graph, "admin")
        self.assertEqual(cm.exception.code, "TOPOLOGY_CYCLE_DETECTED")
        self.assertEqual(cm.exception.extra["cycle"], ["a", "b", "a"])

    def test_oversized_closure_returns_limit_and_action(self):
        _, impact = fresh()
        n = DEFAULT_MAX_CLOSURE_NODES + 1
        graph = {"nodes": [{"id": f"n{i}", "module": f"m{i}", "clock_domain": "C"}
                           for i in range(n)],
                 "edges": [{"from": f"n{i}", "to": f"n{i+1}"} for i in range(n - 1)]}
        impact.publish_topology(graph, "admin")
        with self.assertRaises(ECOError) as cm:
            impact.compute("x", ["n0"], {}, "u")
        self.assertEqual(cm.exception.code, "IMPACT_CLOSURE_TOO_LARGE")
        self.assertEqual(cm.exception.extra["limit"], DEFAULT_MAX_CLOSURE_NODES)
        self.assertTrue(cm.exception.extra["action"])

    def test_audit_records_auto_and_manual_conclusions(self):
        _, impact = fresh()
        a = impact.compute("x", ["u_core"], {}, "u")
        b = impact.exclude(a["id"], [{"node": "u_dbg", "reason": "调试观察点未改"}], "d")
        events = impact.list_audit(snapshot_id=b["id"])
        actions = {e["action"] for e in events}
        self.assertIn("impact.auto", actions)
        self.assertIn("impact.override", actions)
        auto = next(e for e in events if e["action"] == "impact.auto")
        manual = next(e for e in events if e["action"] == "impact.override")
        self.assertIn("AUTO", auto["detail_json"])
        self.assertIn("MANUAL", manual["detail_json"])


class ImpactEcoIntegrationTest(unittest.TestCase):
    def _green(self, svc, eid):
        run_all_pending(svc, eid)
        svc.signoff(eid, ROLE_TIMING, "timing.zhang")
        svc.signoff(eid, ROLE_METHOD, "method.li")

    def test_eco_create_auto_closure_and_freeze_binds_versions(self):
        svc, impact = fresh()
        e = svc.create_eco("t", "o", ["alu"],
                           {"alu": {"netlist": "MODULE alu; CELL X; ENDMODULE"}})
        self.assertIsNotNone(e["impact_snapshot_id"])
        f = svc.freeze_eco(e["id"], "o")
        self.assertEqual(f["snapshot"]["impact_closure"]["snapshot_id"],
                         e["impact_snapshot_id"])
        self.assertIn("u_noc", f["snapshot"]["impact_closure"]["accepted_nodes"])

    def test_generated_cdc_and_contract_checks_block_gate_until_pass(self):
        svc, _ = fresh()
        e = svc.create_eco("t", "o", ["alu"],
                           {"alu": {"netlist": "MODULE alu; CELL X; ENDMODULE"}})
        svc.freeze_eco(e["id"], "o")
        gate = {x["type"]: x for x in svc.eco_detail(e["id"])["gate"]["checks"]}
        self.assertTrue(gate["CDC_VERIFY"]["required"])
        self.assertTrue(gate["INTERFACE_CONTRACT_CHECK"]["required"])
        self.assertFalse(svc.eco_detail(e["id"])["gate"]["green"])
        run_all_pending(svc, e["id"])
        self.assertTrue(svc.eco_detail(e["id"])["gate"]["green"])

    def test_topology_update_invalidates_frozen_snapshot_and_blocks_release(self):
        svc, impact = fresh()
        e = svc.create_eco("t", "o", ["alu"], {"alu": {"netlist": "x"}})
        svc.freeze_eco(e["id"], "o")
        self._green(svc, e["id"])
        graph = {**SEED_TOPOLOGY,
                 "edges": [{**e, "reason": e["reason"] + "（拓扑版本 v2 修订说明）"}
                           for e in SEED_TOPOLOGY["edges"]]}
        impact.publish_topology(graph, "admin", "更新传播边说明")
        d = svc.eco_detail(e["id"])
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        self.assertFalse(d["impact"]["usable_for_review"])
        with self.assertRaises(ECOError) as cm:
            svc.release_start(e["id"], "o")
        self.assertEqual(cm.exception.code, "NOT_FROZEN")

    def test_concurrent_same_input_keeps_one_current_snapshot(self):
        svc, impact = fresh()
        results = []
        errors = []

        def worker():
            try:
                results.append(impact.compute("race", ["u_alu"], {"v": 1}, "u"))
            except Exception as exc:  # pragma: no cover - test diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        ids = {x["id"] for x in results}
        self.assertEqual(len(ids), 1)

    def test_old_snapshot_cannot_freeze_after_override(self):
        svc, _ = fresh()
        e = svc.create_eco("t", "o", ["core"],
                           {"core": {"netlist": "MODULE core; CELL X; ENDMODULE"}})
        old_id = e["impact_snapshot_id"]
        new = svc.eco_detail(e["id"])["impact"]
        svc._impact_svc().exclude(old_id, [{"node": "u_dbg", "reason": "调试观察点未改"}], "d")
        # 手动篡改 eco 指针模拟外部拿旧快照冻结，必须被服务端门禁拒绝。
        with svc.s.tx() as c:
            c.execute("UPDATE eco SET impact_snapshot_id=? WHERE id=?", (old_id, e["id"]))
        with self.assertRaises(ECOError) as cm:
            svc.freeze_eco(e["id"], "o")
        self.assertEqual(cm.exception.code, "IMPACT_SNAPSHOT_STALE")
        self.assertTrue(new["current"])


if __name__ == "__main__":
    unittest.main()
