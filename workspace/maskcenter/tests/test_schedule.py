"""排程：窗口排他、唯一赢家、操作编号安全重试、lot 单一绑定、曝光次序与封存。"""
import threading

from mdc.domain import DomainError
from tests.helpers import BaseCase


class TestSchedule(BaseCase):
    def setUp(self):
        super().setUp()
        self.s = self.valid_set("S")
        self.dno = self.s["delivery_no"]
        self.tool, self.lot = self.tool_and_lot(self.dno)

    def _reserve(self, start, end, mask=None, op=None, actor="u_disp1",
                tool=None, lot="__USE__"):
        return self.svc.reserve_window(
            actor, tool or self.tool, self.dno,
            mask or self.s["order"][0], start, end,
            self.lot if lot == "__USE__" else lot, op_id=op)

    def test_overlap_rejected_and_arbitrated(self):
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="OP-A")
        with self.assertRaises(DomainError) as cm:
            self._reserve("2026-10-10T09:00:00Z", "2026-10-10T11:00:00Z",
                          actor="u_disp2", op="OP-B")
        self.assertEqual(cm.exception.code, "WINDOW_OVERLAP")
        self.assertEqual(cm.exception.detail["winner_op_id"], "OP-A")
        arb = self.svc.s.q_one(
            "SELECT * FROM arbitration WHERE loser_op_id='OP-B'")
        self.assertIsNotNone(arb)
        self.assertEqual(arb["winner_op_id"], "OP-A")

    def test_safe_retry_with_same_op_replays_conclusion(self):
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="OP-A")

        def lose_once():
            with self.assertRaises(DomainError) as cm:
                self._reserve("2026-10-10T09:00:00Z", "2026-10-10T11:00:00Z",
                              actor="u_disp2", op="OP-B")
            return cm.exception

        first = lose_once()                       # 首次抢占失败（无 replayed）
        self.assertEqual(first.code, "WINDOW_OVERLAP")
        self.assertFalse(first.detail.get("replayed"))
        retry = lose_once()                       # 原操作编号安全重试
        self.assertEqual(retry.code, "WINDOW_OVERLAP")
        self.assertTrue(retry.detail.get("replayed"))
        self.assertEqual(retry.detail["winner_op_id"], "OP-A")

    def test_winner_replay_returns_same_window(self):
        w1 = self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="OP-A")
        w2 = self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="OP-A")
        self.assertTrue(w2["replayed"])
        self.assertEqual(w1["window_id"], w2["window_id"])

    def test_concurrent_race_single_winner(self):
        results, barrier = [], threading.Barrier(2)

        def race(actor, op):
            barrier.wait()
            try:
                r = self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z",
                                  actor=actor, op=op)
                results.append(("W", op, r["window_id"]))
            except DomainError:
                results.append(("L", op, None))

        t1 = threading.Thread(target=race, args=("u_disp1", "OP-T1"))
        t2 = threading.Thread(target=race, args=("u_disp2", "OP-T2"))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(len([r for r in results if r[0] == "W"]), 1)
        n = self.svc.s.q_one(
            "SELECT COUNT(*) c FROM exposure_window WHERE state='RESERVED'")["c"]
        self.assertEqual(n, 1)

    def test_adjacent_windows_do_not_overlap(self):
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="A")
        # 端点相接（start == 上个 end）不算重叠
        self._reserve("2026-10-10T10:00:00Z", "2026-10-10T12:00:00Z", op="B")

    def test_different_tools_same_slot_ok(self):
        t2 = self.svc.create_tool("u_disp2", "STEPPER-B")["id"]
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="A")
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z",
                      tool=t2, actor="u_disp2", lot=None, op="B")

    def test_lot_single_current_set(self):
        s2 = self.valid_set("OTHER")
        with self.assertRaises(DomainError) as cm:
            # 该 lot 已有保留窗口，换绑被拒
            self._reserve("2026-10-11T08:00:00Z", "2026-10-11T09:00:00Z", op="X")
            self.svc.bind_lot("u_disp1", self.lot, s2["delivery_no"],
                              op_id="BIND2")
        self.assertEqual(cm.exception.code, "LOT_WINDOWS_PENDING")

    def test_exposure_order_gate(self):
        wins = self.reserve_all_in_order(self.tool, self.dno, self.s, self.lot)
        with self.assertRaises(DomainError) as cm:
            self.svc.expose("u_disp1", wins[1])
        self.assertEqual(cm.exception.code, "DEPENDENCY_NOT_EXPOSED")
        self.svc.expose("u_disp1", wins[0])
        self.assertEqual(self.svc.get_set(self.dno)["status"], "SEALED")

    def test_sealed_set_rejects_new_window(self):
        wins = self.reserve_all_in_order(self.tool, self.dno, self.s, self.lot)
        self.svc.expose("u_disp1", wins[0])
        with self.assertRaises(DomainError) as cm:
            self._reserve("2026-12-01T08:00:00Z", "2026-12-01T09:00:00Z",
                          op="LATE")
        self.assertEqual(cm.exception.code, "SET_SEALED_INPLACE")

    def test_expose_requires_bound_lot(self):
        w = self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z",
                          lot=None, op="NB")
        with self.assertRaises(DomainError) as cm:
            self.svc.expose("u_disp1", w["window_id"])
        self.assertEqual(cm.exception.code, "LOT_NOT_BOUND")

    def test_expired_op_id_rejected(self):
        from mdc.store import utcnow
        with self.svc.s.tx() as c:
            c.execute(
                "INSERT INTO operation(id,kind,identity,payload_hash,status,created_at,"
                "expires_at) VALUES('OLD','reserve_window','u_disp1',?,'PENDING',?,?)",
                ("h", "2000-01-01T00:00:00.000Z", "2000-01-01T00:05:00.000Z"))
        with self.assertRaises(DomainError) as cm:
            self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="OLD")
        self.assertEqual(cm.exception.code, "OP_EXPIRED")

    def test_payload_conflict_same_op(self):
        self._reserve("2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", op="SAME")
        with self.assertRaises(DomainError) as cm:
            self._reserve("2027-10-10T08:00:00Z", "2027-10-10T10:00:00Z", op="SAME")
        self.assertEqual(cm.exception.code, "OP_PAYLOAD_CONFLICT")
