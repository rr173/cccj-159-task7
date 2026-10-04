"""双签替换、谱系封存、delta set、返工计划。"""
from mdc.domain import DomainError
from tests.helpers import BaseCase


class TestReplacement(BaseCase):
    def setUp(self):
        super().setUp()
        self.s = self.valid_set("R")
        self.dno = self.s["delivery_no"]
        self.tool, self.lot = self.tool_and_lot(self.dno)
        self.up = self.svc.put_content(
            "u_mei", "m_main_fix.gds", "GDS",
            self.gds_bytes(((100, 0), (101, 0), (200, 0), (300, 0))))

    def _request(self):
        return self.svc.request_replacement(
            "u_mei", self.dno, "M_MAIN", self.up["sha256"],
            "修正", op_id="RPL")["replacement_id"]

    def test_unauthorized_role_cannot_request(self):
        with self.assertRaises(DomainError) as cm:
            self.svc.request_replacement("u_disp1", self.dno, "M_MAIN",
                                         self.up["sha256"])
        self.assertEqual(cm.exception.code, "UNAUTHORIZED")

    def test_two_distinct_natural_persons_required(self):
        rid = self._request()
        self.svc.approve_replacement("u_mei", rid, op_id="A1")
        with self.assertRaises(DomainError) as cm:
            self.svc.approve_replacement("u_mei", rid, op_id="A2")
        self.assertEqual(cm.exception.code, "APPROVAL_SAME_PERSON")
        # 仍是 PENDING
        self.assertEqual(self.svc.list_replacements("PENDING")[0]["status"],
                         "PENDING")

    def test_steward_and_me_execute_and_reschedule(self):
        rid = self._request()
        w = self.svc.reserve_window(
            "u_disp1", self.tool, self.dno, self.s["order"][0],
            "2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", self.lot,
            op_id="W1")
        self.svc.approve_replacement("u_mei", rid, op_id="A1")
        exe = self.svc.approve_replacement("u_tao", rid, op_id="A2")
        self.assertEqual(exe["status"], "EXECUTED")
        self.assertEqual(exe["migrated_windows"], [w["window_id"]])
        old = self.svc.get_set(self.dno)
        new = self.svc.get_set(exe["new_delivery_no"])
        self.assertEqual(old["status"], "SUPERSEDED")
        self.assertEqual(new["status"], "ACTIVE")
        self.assertEqual(new["kind"], "REVISION")
        # 新谱系节点 seq=2，同一 lineage
        self.assertEqual(new["lineage_id"], old["lineage_id"])
        self.assertEqual(new["seq"], 2)
        # 窗口与 lot 都重算到新节点
        self.assertEqual(self.svc.list_windows()[0]["set_id"], new["id"])
        self.assertEqual(
            next(l for l in self.svc.list_lots() if l["id"] == self.lot)["set_id"],
            new["id"])
        # 旧节点构件保持，新节点该构件为替换件
        nm = next(m for m in new["members"] if m["mask_name"] == "M_MAIN")
        self.assertEqual(nm["sha256"], self.up["sha256"])

    def test_cannot_replace_on_superseded_node(self):
        rid = self._request()
        self.svc.approve_replacement("u_mei", rid, op_id="A1")
        self.svc.approve_replacement("u_tao", rid, op_id="A2")
        with self.assertRaises(DomainError) as cm:
            self.svc.request_replacement("u_mei", self.dno, "M_MAIN",
                                         self.up["sha256"], op_id="RPL2")
        self.assertEqual(cm.exception.code, "SET_SUPERSEDED")

    def test_post_exposure_replace_permanently_rejected(self):
        # 在新节点曝光一次
        rid = self._request()
        self.svc.approve_replacement("u_mei", rid, op_id="A1")
        exe = self.svc.approve_replacement("u_tao", rid, op_id="A2")
        new_id = exe["new_set_id"]
        new = self.svc.get_set(new_id)
        w = self.svc.reserve_window(
            "u_disp1", self.tool, new_id, new["order"][0],
            "2026-10-10T08:00:00Z", "2026-10-10T10:00:00Z", self.lot,
            op_id="W2")
        self.svc.expose("u_disp1", w["window_id"])
        with self.assertRaises(DomainError) as cm:
            self.svc.request_replacement("u_mei", new_id, "M_MAIN",
                                         self.up["sha256"], op_id="AFTER")
        self.assertEqual(cm.exception.code, "SET_SEALED_INPLACE")

    def test_delta_and_rework_only_after_seal(self):
        wins = self.reserve_all_in_order(self.tool, self.dno, self.s, self.lot)
        # 未曝光（ACTIVE）节点不能做 delta，应走双签替换
        with self.assertRaises(DomainError) as cm:
            self.svc.create_delta(
                "u_mei", self.dno,
                [{"mask_name": "M_MAIN", "new_sha": self.up["sha256"]}],
                op_id="D0")
        self.assertEqual(cm.exception.code, "SET_NOT_SEALED")
        self.svc.expose("u_disp1", wins[0])
        # 主节点曝光后即封存
        dl = self.svc.create_delta(
            "u_mei", self.dno,
            [{"mask_name": "M_MAIN", "new_sha": self.up["sha256"]}],
            op_id="D1")
        self.assertEqual(dl["changed_masks"], ["M_MAIN"])
        delta = self.svc.get_set(dl["delta_set_id"])
        self.assertEqual(delta["kind"], "DELTA")
        self.assertEqual(self.svc.get_set(self.dno)["status"], "SEALED")
        # 返工计划必须 lot 已曝光：曝光其余两个窗口
        self.svc.expose("u_disp1",
                        next(w for w in self.svc.list_windows()
                             if w["mask_name"] == "M_OPC")["id"])
        self.svc.expose("u_disp1",
                        next(w for w in self.svc.list_windows()
                             if w["mask_name"] == "M_IL")["id"])
        rw = self.svc.create_rework_plan("u_mei", self.lot, dl["delta_set_id"],
                                         op_id="RW")
        self.assertEqual(rw["status"], "OPEN")
        # 已曝光 lot 可以绑定同谱系 delta
        self.svc.bind_lot("u_disp1", self.lot, dl["delta_set_id"])

    def test_delta_rejects_foreign_lineage(self):
        # 造另一套已封存谱系，并在其上生成 delta
        other = self.valid_set("OTHER")
        odno = other["delivery_no"]
        tool2 = self.svc.create_tool("u_disp2", "STEPPER-B")["id"]
        lot2 = self.svc.create_lot("u_disp2", "LOT-2")["id"]
        self.svc.bind_lot("u_disp2", lot2, odno)
        owins = []
        for i, m in enumerate(other["order"]):
            w = self.svc.reserve_window(
                "u_disp2", tool2, odno, m,
                f"2026-11-{10+i:02d}T08:00:00Z", f"2026-11-{10+i:02d}T10:00:00Z",
                lot2, op_id=f"OW-{m}")
            owins.append(w["window_id"])
        self.svc.expose("u_disp2", owins[0])
        odl = self.svc.create_delta(
            "u_mei", odno,
            [{"mask_name": "M_MAIN", "new_sha": self.up["sha256"]}], op_id="OD")
        # 当前 lot（谱系 1）绑定 谱系2 的 delta → 拒绝
        wins = self.reserve_all_in_order(self.tool, self.dno, self.s, self.lot)
        self.svc.expose("u_disp1", wins[0])
        self.svc.expose("u_disp1",
                        next(w for w in self.svc.list_windows()
                             if w["mask_name"] == "M_OPC")["id"])
        self.svc.expose("u_disp1",
                        next(w for w in self.svc.list_windows()
                             if w["mask_name"] == "M_IL")["id"])
        with self.assertRaises(DomainError) as cm:
            self.svc.create_rework_plan("u_mei", self.lot, odl["delta_set_id"])
        self.assertEqual(cm.exception.code, "DELTA_LINEAGE_MISMATCH")
