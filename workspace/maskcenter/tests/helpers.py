"""测试公共夹具：临时存储 + 可直接导入的合法演示发行。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mdc.domain import build_gds_for_test
from mdc.service import Service
from mdc.store import Store


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = Service(Store(Path(self.tmp.name)))

    def tearDown(self):
        self.tmp.cleanup()

    def valid_packet(self, suffix="1"):
        return self.svc.make_demo_packet("u_admin", suffix)["packet"]

    def import_valid(self, suffix="1"):
        r = self.svc.import_release(self.valid_packet(suffix), "u_admin")
        self.assertEqual(r["status"], "VALID", r["findings"])
        return r

    def valid_set(self, suffix="1"):
        r = self.import_valid(suffix)
        return self.svc.get_set(r["delivery_no"])

    def tool_and_lot(self, set_key):
        t = self.svc.create_tool("u_disp1", "STEPPER-A")["id"]
        lot = self.svc.create_lot("u_disp1", "LOT-1")["id"]
        self.svc.bind_lot("u_disp1", lot, set_key)
        return t, lot

    def gds_bytes(self, layers=((100, 0), (101, 0), (200, 0))):
        return build_gds_for_test(list(layers))

    def reserve_all_in_order(self, tool, dno, s, lot, day="15"):
        ids = []
        for i, m in enumerate(s["order"]):
            w = self.svc.reserve_window(
                "u_disp1", tool, dno, m,
                f"2026-10-{day}T{8 + i:02d}:00:00Z",
                f"2026-10-{day}T{9 + i:02d}:00:00Z", lot, op_id=f"OP-W-{m}")
            ids.append(w["window_id"])
        return ids
