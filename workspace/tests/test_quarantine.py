"""已发行版本事故隔离流程不变量测试。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.quarantine import (QuarantineService, ROLE_QUALITY, ROLE_RELEASE)
from app.runner import run_all_pending, compute_input_fingerprint
from app.service import ECOService, ECOError, ROLE_METHOD, ROLE_TIMING
from app.store import Store


def fresh_service(path=":memory:"):
    store = Store(path)
    svc = ECOService(store)
    qsvc = QuarantineService(store)
    return store, svc, qsvc


def make_eco(svc, module="alu", suffix="", netlist=None):
    netlist = netlist or f"MODULE {module}; CELL ECO_{suffix or 'X'} u; ENDMODULE"
    d = svc.create_eco(f"ECO-{suffix or module}", "owner", [module],
                       {module: {"netlist": netlist}})
    return d["id"]


def freeze_green_release(svc, eco_id):
    svc.freeze_eco(eco_id, "owner")
    run_all_pending(svc, eco_id)
    svc.signoff(eco_id, ROLE_TIMING, "timing.u")
    svc.signoff(eco_id, ROLE_METHOD, "method.u")
    return svc.release_start(eco_id, "owner")


def make_released_baseline(svc, baseline_id="B-R1", module="alu", suffix="1", eco=None):
    eco_id = eco or make_eco(svc, module, suffix)
    rel = freeze_green_release(svc, eco_id)
    assert rel["new_baseline_id"] == baseline_id, rel
    return eco_id


class TestQuarantine(unittest.TestCase):
    def test_registration_requires_quality_lead_and_fields(self):
        _, _, q = fresh_service()
        with self.assertRaises(ECOError) as cm:
            q.register("dev", "B-R0", "batch", "reason", ["ev"], role="DEVELOPER")
        self.assertEqual(cm.exception.code, "FORBIDDEN_ROLE")
        with self.assertRaises(ECOError) as cm:
            q.register("quality", "B-R0", "", "reason", ["ev"])
        self.assertEqual(cm.exception.code, "BATCH_REQUIRED")
        with self.assertRaises(ECOError) as cm:
            q.register("quality", "B-R0", "batch", "", ["ev"])
        self.assertEqual(cm.exception.code, "REASON_REQUIRED")
        with self.assertRaises(ECOError) as cm:
            q.register("quality", "B-R0", "batch", "reason", [])
        self.assertEqual(cm.exception.code, "EVIDENCE_REQUIRED")

    def test_isolates_hit_and_all_descendants_and_rolls_trunk_back(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc, suffix="1")
        e2 = make_eco(svc, "alu", "2", "MODULE alu; CELL ECO_2 u; ENDMODULE")
        freeze_green_release(svc, e2)
        inc = q.register("quality.a", "B-R1", "LOT-1", "metal defect",
                         [{"type": "ticket", "ref": "FA-1"}])
        self.assertEqual(inc["status"], "ISOLATED")
        self.assertEqual(inc["trusted_ancestor_id"], "B-R0")
        self.assertEqual({x["baseline_id"] for x in inc["affected_baselines"]},
                         {"B-R1", "B-R2"})
        self.assertEqual(svc.current_constraints()["base_id"], "B-R0")
        for bid in ("B-R1", "B-R2"):
            self.assertFalse(svc.baseline_detail(bid)["trust"]["trusted"])

    def test_unreleased_ecos_return_to_realign_and_old_results_signoffs_void(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        eco = make_eco(svc, "alu", "open", "MODULE alu; CELL OPEN u; ENDMODULE")
        svc.freeze_eco(eco, "owner")
        run_all_pending(svc, eco)
        svc.signoff(eco, ROLE_TIMING, "timing.u")
        q.register("quality.a", "B-R1", "LOT-1", "cause", ["ev"])
        d = svc.eco_detail(eco)
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        self.assertEqual(d["trust_generation"], 1)
        self.assertTrue(all(x["status"] == "SUPERSEDED" for x in d["gate"]["checks"]))
        self.assertEqual(d["gate"]["valid_signoffs"], [])
        with self.assertRaises(ECOError) as cm:
            svc.signoff(eco, ROLE_METHOD, "method.u")
        self.assertEqual(cm.exception.code, "NOT_FROZEN")

    def test_quarantined_parent_cannot_freeze_or_release_after_refreeze(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        eco = make_eco(svc, "alu", "open", "MODULE alu; CELL OPEN u; ENDMODULE")
        svc.freeze_eco(eco, "owner")
        q.register("quality.a", "B-R1", "LOT-1", "cause", ["ev"])
        # 回退后重冻必须落到最近可信祖先 B-R0，且新信任代次进入快照/检查指纹。
        d = svc.freeze_eco(eco, "owner")
        self.assertEqual(d["parent_baseline_id"], "B-R0")
        self.assertEqual(d["snapshot"]["trust_generation"], 1)
        pkt = svc.check_inputs(eco, "TIMING_STA")
        self.assertEqual(compute_input_fingerprint("TIMING_STA", pkt["inputs"]),
                         pkt["expected_fingerprint"])
        run_all_pending(svc, eco)
        svc.signoff(eco, ROLE_TIMING, "timing.u")
        svc.signoff(eco, ROLE_METHOD, "method.u")
        rel = svc.release_start(eco, "owner")
        new_id = rel["new_baseline_id"]
        self.assertEqual(svc.baseline_detail(new_id)["parent_id"], "B-R0")

    def test_repeated_same_incident_request_is_idempotent(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        payload = ("quality.a", "B-R1", "LOT-1", "cause", [{"ref": "FA-1"}])
        first = q.register(*payload, incident_id="Q-DUP")
        second = q.register(*payload, incident_id="Q-DUP")
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["replayed"])
        self.assertEqual(len(q.list_incidents()), 1)
        self.assertEqual(len([x for x in q.audit() if x["event"] == "ISOLATED"]), 1)

    def test_inflight_release_and_isolation_are_serialized_and_pending_blocks_release(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        eco = make_eco(svc, "alu", "2", "MODULE alu; CELL ECO_2 u; ENDMODULE")
        svc.freeze_eco(eco, "owner")
        run_all_pending(svc, eco)
        svc.signoff(eco, ROLE_TIMING, "timing.u")
        svc.signoff(eco, ROLE_METHOD, "method.u")
        with self.assertRaises(ECOError) as cm:
            svc.release_start(eco, "owner", failpoint="AFTER_PHASE1")
        self.assertEqual(cm.exception.code, "RELEASE_INTERRUPTED")
        with self.assertRaises(ECOError) as cm:
            q.register("quality", "B-R1", "lot", "cause", ["ev"], failpoint="AFTER_REGISTER")
        self.assertEqual(cm.exception.code, "QUARANTINE_INTERRUPTED")
        with self.assertRaises(ECOError) as cm:
            svc.resume_release(eco, "owner")
        self.assertEqual(cm.exception.code, "QUARANTINE_PENDING")
        retried = q.register("quality", "B-R1", "lot", "cause", ["ev"])
        self.assertTrue(retried["replayed"])
        self.assertEqual(retried["status"], "ISOLATED")
        rec = q.recover()
        self.assertEqual(rec["count"], 0)
        self.assertEqual(svc.eco_detail(eco)["status"], "REBASE_REQUIRED")

    def test_persisted_pending_incident_recovers_from_disk(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "q.db")
            store, svc, q = fresh_service(path)
            make_released_baseline(svc)
            with self.assertRaises(ECOError):
                q.register("quality", "B-R1", "lot", "cause", ["ev"],
                           failpoint="AFTER_REGISTER")
            del q, svc, store
            store2 = Store(path)
            q2 = QuarantineService(store2)
            rec = q2.recover()
            self.assertEqual(rec["count"], 1)
            self.assertEqual(rec["recovered"][0]["status"], "ISOLATED")

    def test_restore_requires_two_distinct_roles_and_no_fork(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        inc = q.register("quality", "B-R1", "lot", "cause", ["ev"])
        first_confirm = q.confirm_restore(inc["id"], ROLE_QUALITY, "quality.a")
        replay = q.confirm_restore(inc["id"], ROLE_QUALITY, "quality.a")
        self.assertTrue(replay["replayed"])
        self.assertIn(ROLE_RELEASE, replay["awaiting_roles"])
        with self.assertRaises(ECOError) as cm:
            q.confirm_restore(inc["id"], ROLE_RELEASE, "quality.a")
        self.assertEqual(cm.exception.code, "DUAL_ROLE_CONFLICT")
        d = q.confirm_restore(inc["id"], ROLE_RELEASE, "release.b")
        self.assertEqual(d["status"], "RESTORED")
        self.assertTrue(svc.baseline_detail("B-R1")["trust"]["trusted"])
        self.assertEqual(svc.current_constraints()["base_id"], "B-R1")

    def test_new_fork_during_isolation_blocks_restore(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        inc = q.register("quality", "B-R1", "lot", "cause", ["ev"])
        q.confirm_restore(inc["id"], ROLE_QUALITY, "quality.a")
        # 从可信祖先 B-R0 发布一条新分支（新版本号），即隔离期新分叉。
        fix = make_eco(svc, "l2c", "fix", "MODULE l2c; CELL FORK u; ENDMODULE")
        freeze_green_release(svc, fix)
        with self.assertRaises(ECOError) as cm:
            q.confirm_restore(inc["id"], ROLE_RELEASE, "release.b")
        self.assertEqual(cm.exception.code, "RESTORE_FORK_DETECTED")
        self.assertEqual(q.incident(inc["id"])["status"], "ISOLATED")

    def test_restoration_advances_generation_and_reuses_nothing(self):
        _, svc, q = fresh_service()
        make_released_baseline(svc)
        eco = make_eco(svc, "alu", "open", "MODULE alu; CELL OPEN u; ENDMODULE")
        svc.freeze_eco(eco, "owner")
        run_all_pending(svc, eco)
        inc = q.register("quality", "B-R1", "lot", "cause", ["ev"])
        svc.freeze_eco(eco, "owner")
        run_all_pending(svc, eco)
        q.confirm_restore(inc["id"], ROLE_QUALITY, "q")
        q.confirm_restore(inc["id"], ROLE_RELEASE, "r")
        d = svc.eco_detail(eco)
        self.assertEqual(d["status"], "REBASE_REQUIRED")
        self.assertEqual(d["trust_generation"], 2)
        self.assertTrue(all(x["status"] == "SUPERSEDED" for x in d["gate"]["checks"]))
        self.assertEqual(d["gate"]["valid_signoffs"], [])


if __name__ == "__main__":
    unittest.main()
