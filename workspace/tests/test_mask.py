"""光罩投片交付中心领域不变量测试。"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
import zipfile
from pathlib import Path

from app.mask_export import ExportService
from app.mask_service import (
    MaskError, MaskService, norm_ts, parse_layermap, parse_recipe, sha256_hex,
)
from app.mask_store import MaskStore


LAYMAP = b"LAYERMAP chip\nLAYER 1 diff\nLAYER 2 poly\n"
RECIPE = b"RECIPE R1\nLAYER 1\nLAYER 2\nCORNER ss\n"
DIE = b"DIE 5000 3000\n"
SCRIBE = b"SCRIBE WIDTH 80\n"
CORNER_SS = b"CORNER ss\nv=0.8\n"
L1 = b"# gds\n@LAYER 1\n"
L2 = b"# gds\n@LAYER 2\n"


def seed_release(svc, name="chip", bad=None, extra_corner=False):
    """创建并收齐一套合规资料。bad: {slot: data} 用坏内容替换。"""
    files = [
        ("layermap", "layer.map", LAYMAP, None),
        ("recipe", "recipe.r", RECIPE, None),
        ("die", "die.dim", DIE, None),
        ("scribe", "scribe.cfg", SCRIBE, None),
        ("corner", "ss.corner", CORNER_SS, None),
        ("layout", "L01.gds", L1, 1),
        ("layout", "L02.gds", L2, 2),
    ]
    if extra_corner:
        files.append(("corner", "tt.corner", b"CORNER tt\nv=1.0\n", None))
    rid = svc.create_release(name, "u_op")["id"]
    for kind, fname, data, lno in files:
        d = bad.get(fname, data) if bad else data
        svc.add_artifact(rid, kind, fname, d, sha256_hex(d), "u_op", layer_no=lno)
    return rid


def finalized(svc, rid=None, name="chip"):
    rid = rid or seed_release(svc, name)
    assert svc.verify_release(rid)["verdict"] == "PASS"
    svc.finalize_release(rid, "u_op", f"fin-{rid}-{uuid.uuid4().hex[:8]}")
    return rid


def master_set(svc, rid):
    s = svc.create_mask_set(rid, "set", "u_op", f"set-{rid}-{uuid.uuid4().hex[:8]}")
    sid = s["id"]
    nid = svc.mask_set_detail(sid)["nodes"][0]["id"]
    return sid, nid


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = MaskStore(f"{self.dir}/m.db", blob_dir=f"{self.dir}/blobs")
        self.svc = MaskService(self.store)
        # 测试里默认不开打包守护线程，以便显式验证 QUEUED→recover()
        self.exp = ExportService(self.store, export_root=f"{self.dir}/exports", daemon=False)

    def expect(self, code, fn, *a, **k):
        with self.assertRaises(MaskError) as cm:
            fn(*a, **k)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception


class TestImportAndVerify(_Base):
    def test_parser_rejects_garbage(self):
        self.assertEqual(parse_layermap(b"hello")["parse_status"], "PARSE_ERROR")
        self.assertEqual(parse_recipe(b"LAYER x\n")["parse_status"], "PARSE_ERROR")

    def test_tampered_digest_rejected_at_upload(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        e = self.expect("DIGEST_MISMATCH", self.svc.add_artifact,
                        rid, "layermap", "m.map", LAYMAP, "0" * 64, "u_op")
        self.assertEqual(e.extra["actual"], sha256_hex(LAYMAP))
        # 实体绝不入库
        self.assertEqual(self.store.q_one(
            "SELECT COUNT(*) n FROM mask_artifact WHERE release_id=?", (rid,))["n"], 0)

    def test_missing_layer_and_unmapped_located_to_component(self):
        # recipe 要层 1、2；只给 L1，且给一个多余 L9
        rid = self.svc.create_release("c", "u_op")["id"]
        for kind, fname, data, lno in [
                ("layermap", "layer.map", LAYMAP, None),
                ("recipe", "recipe.r", RECIPE, None),
                ("die", "die.dim", DIE, None),
                ("scribe", "scribe.cfg", SCRIBE, None),
                ("corner", "ss.corner", CORNER_SS, None),
                ("layout", "L01.gds", L1, 1),
                ("layout", "L09.gds", b"@LAYER 9\n", 9)]:
            self.svc.add_artifact(rid, kind, fname, data, sha256_hex(data), "u_op", layer_no=lno)
        v = self.svc.verify_release(rid)
        self.assertEqual(v["verdict"], "FAIL")
        codes = {(f["code"], f["component"]) for f in v["findings"]}
        self.assertIn(("MISSING_LAYER", "recipe.r"), codes)
        self.assertIn(("UNMAPPED_LAYOUT_LAYER", "L09.gds"), codes)

    def test_missing_required_component(self):
        # 合规资料去掉 die 构件后核验必须报 MISSING_COMPONENT 并定位槽位
        rid = seed_release(self.svc)
        self.store.conn.execute("DELETE FROM mask_artifact WHERE release_id=? AND kind='die'",
                                (rid,))
        v = self.svc.verify_release(rid)
        self.assertTrue(any(f["code"] == "MISSING_COMPONENT" and f["slot"] == "die"
                            for f in v["findings"]))

    def test_recipe_layer_not_in_layermap(self):
        recipe = b"RECIPE R1\nLAYER 1\nLAYER 2\nLAYER 5\nCORNER ss\n"
        rid = seed_release(self.svc, bad={"recipe.r": recipe})
        v = self.svc.verify_release(rid)
        self.assertTrue(any(f["code"] == "RECIPE_LAYER_NOT_MAPPED" for f in v["findings"]))
        self.assertTrue(any(f["code"] == "MISSING_LAYER" for f in v["findings"]))

    def test_corner_mismatch_located(self):
        rid = seed_release(self.svc, bad={"ss.corner": b"CORNER tt\nv=1\n"})
        v = self.svc.verify_release(rid)
        codes = {f["code"] for f in v["findings"]}
        self.assertIn("CORNER_ARTIFACT_MISSING", codes)  # recipe 要 ss
        self.assertIn("CORNER_NOT_IN_RECIPE", codes)    # 只给了 tt

    def test_finalize_requires_pass(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        self.expect("VERIFICATION_FAILED", self.svc.finalize_release, rid, "u_op", "op1")

    def test_stable_delivery_number_and_dedup(self):
        r1 = finalized(self.svc, name="c1")
        no1 = self.svc.release_detail(r1)["delivery_no"]
        r2 = finalized(self.svc, name="c2")
        d2 = self.svc.release_detail(r2)
        self.assertEqual(d2["delivery_no"], no1)
        # 重复发行规范化时标记 deduped（取规范化返回值）
        dup = self.svc.finalize_release(r2, "u_op", f"replay-{uuid.uuid4().hex[:8]}")
        self.assertTrue(dup["deduped"])
        # blob 实体只落一份
        blobs = self.store.q_all("SELECT DISTINCT blob_id FROM mask_artifact")
        paths = {self.store.blob_path(b["blob_id"]) for b in blobs}
        self.assertEqual(len(paths), len(blobs))

    def test_same_name_different_content_quarantined(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        a = self.svc.add_artifact(rid, "die", "geom.cfg", DIE, sha256_hex(DIE), "u_op")
        self.assertFalse(a["quarantined"])
        # 同名 geom.cfg 却作为 scribe 提交、内容也不同 → 同名异物（同一文件名指代不同构件）
        other = b"SCRIBE WIDTH 120\n"
        a2 = self.svc.add_artifact(rid, "scribe", "geom.cfg", other,
                                   sha256_hex(other), "u_op")
        self.assertTrue(a2["quarantined"])
        qs = self.svc.list_quarantine()
        self.assertEqual(len(qs), 1)
        self.svc.resolve_quarantine(qs[0]["id"], "REJECT_INCOMING", "u_op", "异物")
        cur = self.store.q_one(
            "SELECT * FROM mask_artifact WHERE id=?", (a2["id"],))
        self.assertIsNone(cur)  # 异物被退回
        self.assertEqual(self.svc.list_quarantine(), [])

    def test_same_slot_same_content_deduped(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        a1 = self.svc.add_artifact(rid, "die", "die.dim", DIE, sha256_hex(DIE), "u_op")
        a2 = self.svc.add_artifact(rid, "die", "die.dim", DIE, sha256_hex(DIE), "u_op")
        self.assertEqual(a1["id"], a2["id"])  # 重复导入不复制实体

    def test_same_slot_new_content_requires_version_channel(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        self.svc.add_artifact(rid, "die", "die.dim", DIE, sha256_hex(DIE), "u_op")
        self.expect("SLOT_OCCUPIED", self.svc.add_artifact,
                    rid, "die", "die.dim", b"DIE 9 9\n",
                    sha256_hex(b"DIE 9 9\n"), "u_op")

    def test_resolve_pending_blocks_finalize(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        self.svc.add_artifact(rid, "die", "geom.cfg", DIE, sha256_hex(DIE), "u_op")
        self.svc.add_artifact(rid, "scribe", "geom.cfg", b"SCRIBE WIDTH 120\n",
                              sha256_hex(b"SCRIBE WIDTH 120\n"), "u_op")
        self.expect("VERIFICATION_FAILED", self.svc.finalize_release, rid, "u_op", "op")

    def test_unknown_user_and_role(self):
        self.expect("UNKNOWN_USER", self.svc.create_release, "c", "ghost")


class TestIdempotency(_Base):
    def test_replay_returns_first_result(self):
        rid = finalized(self.svc)
        sid1 = self.svc.create_mask_set(rid, "s", "u_op", "op-set-1")
        sid2 = self.svc.create_mask_set(rid, "s", "u_op", "op-set-1")
        self.assertEqual(sid1["id"], sid2["id"])
        self.assertTrue(sid2.get("replayed"))

    def test_same_op_different_body_rejected(self):
        rid = finalized(self.svc)
        self.svc.create_mask_set(rid, "A", "u_op", "op-x")
        e = self.expect("OP_FINGERPRINT", self.svc.create_mask_set,
                        rid, "B", "u_op", "op-x")
        self.assertEqual(e.http_status, 409)

    def test_expired_op_rejected(self):
        rid = self.svc.create_release("c", "u_op")["id"]
        self.svc.add_artifact(rid, "die", "d", DIE, sha256_hex(DIE), "u_op", op_id="op-d")
        # 手动把过期时间改到过去
        self.store.conn.execute(
            "UPDATE mask_op SET expires_at='2000-01-01T00:00:00+00:00' WHERE op_id='op-d'")
        self.expect("OP_EXPIRED", self.svc.add_artifact,
                    rid, "die", "d2", b"DIE 9 9\n",
                    sha256_hex(b"DIE 9 9\n"), "u_op", op_id="op-d")

    def test_window_requires_op(self):
        rid = finalized(self.svc)
        sid, nid = master_set(self.svc, rid)
        lot = self.svc.create_lot("L1", "u_disp1")["id"]
        self.svc.bind_lot(lot, sid, "u_disp1", "b1")
        self.expect("OP_REQUIRED", self.svc.book_window,
                    lot, "EXP-01", nid, "L01", "2026-10-05T08:00Z",
                    "2026-10-05T10:00Z", "u_disp1", None)


def book_all_master(svc, lot, sid, nid, day=5, op_prefix="w"):
    slots = [s["slot"] for s in svc.node_detail(nid)["slots"] if s["slot"].startswith("L")]
    wins = []
    for i, slot in enumerate(slots):
        h = 8 + 2 * i
        w = svc.book_window(lot, "EXP-01", nid, slot,
                            f"2026-10-{day:02d}T{h:02d}:00Z",
                            f"2026-10-{day:02d}T{h+2:02d}:00Z",
                            "u_disp1", f"{op_prefix}-{slot}")
        wins.append(w)
    return wins


class TestScheduling(_Base):
    def setUp(self):
        super().setUp()
        self.rid = finalized(self.svc)
        self.sid, self.nid = master_set(self.svc, self.rid)
        self.lot = self.svc.create_lot("L1", "u_disp1")["id"]
        self.svc.bind_lot(self.lot, self.sid, "u_disp1", "bind-1")

    def test_order_violation_if_parent_not_scheduled(self):
        # 直接排第二个槽位（乱序）→ 次序拒绝（master 无边，这里验证 slot 去重不是次序；
        # 次序用派生节点验证，见 test_derive_order）
        w = self.svc.book_window(self.lot, "EXP-01", self.nid, "L02",
                                 "2026-10-05T08:00Z", "2026-10-05T10:00Z",
                                 "u_disp1", "w-l02")
        self.assertEqual(w["slot"], "L02")

    def test_machine_overlap_single_winner_concurrent(self):
        barrier = threading.Barrier(3)
        results = []

        def contender(who, op, slot):
            barrier.wait()
            try:
                w = self.svc.book_window(self.lot, "EXP-01", self.nid, slot,
                                         "2026-10-06T08:00Z", "2026-10-06T10:00Z",
                                         who, op)
                results.append(("WIN", w["id"], op))
            except MaskError as e:
                results.append(("LOSE", e.code, op))

        users = ["u_disp1", "u_disp2", "u_disp1"]
        threads = [threading.Thread(target=contender, args=(users[i], f"op-{i}", slot))
                   for i, slot in enumerate(("L01", "L02", "layermap"))]
        for t in threads: t.start()
        for t in threads: t.join()

        wins = [r for r in results if r[0] == "WIN"]
        loses = [r for r in results if r[0] == "LOSE"]
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(loses), 2)
        self.assertTrue(all(r[1] == "WINDOW_OVERLAP" for r in loses))
        # 赢家落定后，用其原 op_id 和完全相同的请求体重试：返回同一窗口，不复制占用
        win_op = wins[0][2]
        win_row = self.store.q_one("SELECT * FROM mask_window WHERE op_id=?", (win_op,))
        again = self.svc.book_window(self.lot, "EXP-01", self.nid, win_row["slot"],
                                     "2026-10-06T08:00Z", "2026-10-06T10:00Z",
                                     win_row["created_by"], win_op)
        self.assertEqual(again["id"], wins[0][1])
        self.assertTrue(again.get("replayed"))
        # 裁决表里资源恰有 1 WIN
        arbs = self.store.q_all(
            "SELECT decision,COUNT(*) n FROM mask_arbitration WHERE resource=? GROUP BY decision",
            ("machine:EXP-01",))
        d = {r["decision"]: r["n"] for r in arbs}
        self.assertEqual(d["WIN"], 1)
        # 机器上该时段仍只有一个窗口实体
        self.assertEqual(self.store.q_one(
            "SELECT COUNT(*) n FROM mask_window WHERE machine_id='EXP-01' AND state='PLANNED'"
        )["n"], 1)

    def test_lot_single_current_set(self):
        sid2, _ = master_set(self.svc, self.rid)
        # 已有排程窗口时不允许改绑另一个 set
        self.svc.book_window(self.lot, "EXP-01", self.nid, "L01",
                             "2026-10-09T08:00Z", "2026-10-09T10:00Z",
                             "u_disp1", "bound-w1")
        e = self.expect("LOT_ALREADY_BOUND", self.svc.bind_lot,
                        self.lot, sid2, "u_disp1", "bind-2")
        self.assertEqual(e.http_status, 409)

    def test_half_open_interval_adjacent_ok(self):
        # [08,10) 与 [10,12) 首尾相接不重叠
        self.svc.book_window(self.lot, "EXP-01", self.nid, "L01",
                             "2026-10-07T08:00Z", "2026-10-07T10:00Z", "u_disp1", "a1")
        w = self.svc.book_window(self.lot, "EXP-01", self.nid, "L02",
                                 "2026-10-07T10:00Z", "2026-10-07T12:00Z",
                                 "u_disp1", "a2")
        self.assertEqual(w["state"], "PLANNED")
        # 真正重叠拒绝（不同 lot、不同槽位，抢同一机器时段 → 机器排他）
        lot2 = self.svc.create_lot("L2", "u_disp2")["id"]
        self.svc.bind_lot(lot2, self.sid, "u_disp2", "b2")
        self.expect("WINDOW_OVERLAP", self.svc.book_window,
                    lot2, "EXP-01", self.nid, "L01",
                    "2026-10-07T09:00Z", "2026-10-07T11:00Z", "u_disp2", "a3")

    def test_derive_requires_order(self):
        # 派生 L03 节点依赖 master
        n2 = self.svc.derive_node(
            self.sid, self.nid, "派生 L3", "u_lo", "L03",
            {"name": "L03.gds", "data": b"@LAYER 3\n"}, "der-1")
        # 父（master）未排程时直接排派生节点 → 次序拒绝
        self.expect("WINDOW_ORDER_VIOLATION", self.svc.book_window,
                    self.lot, "EXP-01", n2["id"], "L03",
                    "2026-10-05T08:00Z", "2026-10-05T10:00Z", "u_disp1", "d1")
        # 先把 master 的所有槽位排完（首尾相接），派生窗口在其后 → 成功
        slots = [s["slot"] for s in self.svc.node_detail(self.nid)["slots"]
                 if s["slot"].startswith("L")]
        for i, slot in enumerate(sorted(slots)):
            self.svc.book_window(self.lot, "EXP-01", self.nid, slot,
                                 f"2026-10-08T{8+2*i:02d}:00Z",
                                 f"2026-10-08T{10+2*i:02d}:00Z",
                                 "u_disp1", f"m-{slot}")
        w = self.svc.book_window(self.lot, "EXP-01", n2["id"], "L03",
                                 "2026-10-08T12:00Z", "2026-10-08T14:00Z",
                                 "u_disp1", "d2")
        self.assertEqual(w["slot"], "L03")

    def test_node_slot_and_set_mismatch(self):
        other_rid = finalized(self.svc, name="other")
        sid2, nid2 = master_set(self.svc, other_rid)
        self.expect("LOT_SET_MISMATCH", self.svc.book_window,
                    self.lot, "EXP-01", nid2, "L01",
                    "2026-10-05T08:00Z", "2026-10-05T10:00Z", "u_disp1", "x1")

    def test_dependency_inversion_on_superseded(self):
        # 造一个修正版后，不能再基于 SUPERSEDED 旧节点派生
        wins = book_all_master(self.svc, self.lot, self.sid, self.nid)
        # 未曝光：双签替换
        r = self.svc.request_replacement(
            self.rid, self.sid, self.nid, "L02", "L02-b.gds", b"@LAYER 2\nB",
            None, "u_op", "fix", "rpl1")
        self.svc.approve_replacement(r["id"], "ME", "u_mei")
        done = self.svc.approve_replacement(r["id"], "LO", "u_lo")
        new_node = done["new_node"]["id"]
        self.expect("DEPENDENCY_INVERSION", self.svc.derive_node,
                    self.sid, self.nid, "bad", "u_lo", "L09",
                    {"name": "x", "data": b"@LAYER 9\n"}, "bad-derive")
        # 基于最新节点可以
        n = self.svc.derive_node(self.sid, new_node, "ok", "u_lo", "L09",
                                 {"name": "L09.gds", "data": b"@LAYER 9\n"}, "ok-derive")
        self.assertEqual(n["kind"], "DERIVED")


class TestReplacement(_Base):
    def setUp(self):
        super().setUp()
        self.rid = finalized(self.svc)
        self.sid, self.nid = master_set(self.svc, self.rid)
        self.lot = self.svc.create_lot("L1", "u_disp1")["id"]
        self.svc.bind_lot(self.lot, self.sid, "u_disp1", "b1")

    def _request(self, op=None):
        return self.svc.request_replacement(
            self.rid, self.sid, self.nid, "L02", "L02-b.gds", b"@LAYER 2\nBB",
            None, "u_op", "fix", op or f"rpl-{uuid.uuid4().hex[:10]}")

    def test_two_distinct_persons_required(self):
        r = self._request()
        self.svc.approve_replacement(r["id"], "ME", "u_mei")
        # 同一自然人即使同时持有两个角色，第二签也必须拒绝
        self.expect("APPROVER_CONFLICT", self.svc.approve_replacement,
                    r["id"], "LO", "u_mei")
        # u_both 持两角色：先以 ME 身份签，不能再以 LO 身份签
        r2 = self._request()
        self.svc.approve_replacement(r2["id"], "ME", "u_both")
        self.expect("APPROVER_CONFLICT", self.svc.approve_replacement,
                    r2["id"], "LO", "u_both")
        # 同一角色重复签 → ALREADY_APPROVED
        self.expect("ALREADY_APPROVED", self.svc.approve_replacement,
                    r2["id"], "ME", "u_mei")
        # 越权：普通操作员不能签
        r3 = self._request()
        self.expect("FORBIDDEN", self.svc.approve_replacement, r3["id"], "LO", "u_op")
        # 角色错误：制造工程师不能签 LO
        self.expect("FORBIDDEN", self.svc.approve_replacement, r3["id"], "LO", "u_mei")

    def test_double_approval_creates_revision_and_reschedules(self):
        # 先排一些 PLANNED 窗口
        wins = book_all_master(self.svc, self.lot, self.sid, self.nid, day=9)
        r = self._request()
        self.svc.approve_replacement(r["id"], "ME", "u_mei")
        done = self.svc.approve_replacement(r["id"], "LO", "u_lo")
        self.assertEqual(done["status"], "DONE")
        new_node = done["new_node"]
        self.assertEqual(new_node["kind"], "REVISION")
        # 旧节点 SUPERSEDED
        self.assertEqual(self.svc.node_detail(self.nid)["status"], "SUPERSEDED")
        # 下游 PLANNED 窗口全部取消
        for w in wins:
            self.assertEqual(self.store.q_one(
                "SELECT state FROM mask_window WHERE id=?", (w["id"],))["state"], "CANCELLED")
        # lot 跟随新节点
        self.assertEqual(self.svc.lot_detail(self.lot)["current_node_id"], new_node["id"])
        # 仅替换槽位内容变化
        slots = {s["slot"]: s["name"] for s in new_node["slots"]}
        self.assertEqual(slots["L02"], "L02-b.gds")
        self.assertEqual(slots["L01"], "L01.gds")

    def test_replace_same_content_rejected(self):
        self.expect("REPLACEMENT_NO_CHANGE", self.svc.request_replacement,
                    self.rid, self.sid, self.nid, "L02", "same.gds", L2,
                    sha256_hex(L2), "u_op", "x", "rplx")

    def test_replace_after_exposure_sealed(self):
        wins = book_all_master(self.svc, self.lot, self.sid, self.nid, day=10)
        self.svc.expose_window(wins[0]["id"], "u_disp1")
        self.expect("EXPOSURE_STARTED", self._request)

    def test_replacement_idempotent_replay(self):
        r1 = self._request("rpl-fixed-1")
        r2 = self._request("rpl-fixed-1")
        self.assertEqual(r1["id"], r2["id"])
        self.assertTrue(r2.get("replayed"))


class TestExposureAndRework(_Base):
    def setUp(self):
        super().setUp()
        self.rid = finalized(self.svc)
        self.sid, self.nid = master_set(self.svc, self.rid)
        self.lot = self.svc.create_lot("L1", "u_disp1")["id"]
        self.svc.bind_lot(self.lot, self.sid, "u_disp1", "b1")
        self.wins = book_all_master(self.svc, self.lot, self.sid, self.nid, day=11)

    def test_first_exposure_seals_all_nodes(self):
        self.svc.expose_window(self.wins[0]["id"], "u_disp1")
        lot = self.svc.lot_detail(self.lot)
        self.assertEqual(lot["status"], "EXPOSING")
        self.assertEqual(self.svc.node_detail(self.nid)["status"], "SEALED")
        # 封存节点不能再排窗口
        self.expect("NODE_SEALED", self.svc.book_window,
                    self.lot, "EXP-02", self.nid, "L01",
                    "2026-10-20T08:00Z", "2026-10-20T10:00Z", "u_disp1", "late1")
        # 已曝光窗口不能取消
        self.expect("WINDOW_EXPOSED", self.svc.cancel_window, self.wins[0]["id"], "u_disp1")

    def test_rework_only_after_exposure_and_delta_bookable(self):
        # 未曝光不允许返工
        self.expect("EXPOSURE_NOT_STARTED", self.svc.create_rework,
                    self.lot, "r", "u_mei",
                    [{"slot": "L01", "name": "n", "data": b"@LAYER 1\nx"}], "rw-early")
        self.svc.expose_window(self.wins[0]["id"], "u_disp1")
        rw = self.svc.create_rework(
            self.lot, "defect", "u_mei",
            [{"slot": "L01", "name": "L01-r1.gds", "data": b"@LAYER 1\nrev1"}], "rw1")
        self.assertEqual(rw["status"], "READY")
        self.assertEqual(rw["delta_set"]["kind"], "DELTA")
        # 绑定 delta set 到已曝光 lot（通过返工计划，合法）
        self.svc.bind_lot(self.lot, rw["delta_set_id"], "u_disp1", "bind-delta")
        # delta 窗口只含变更槽位，且必须在封存父节点之后
        dn = rw["delta_node_id"]
        self.expect("WINDOW_ORDER_VIOLATION", self.svc.book_window,
                    self.lot, "EXP-01", dn, "L01",
                    "2026-10-01T00:00Z", "2026-10-01T02:00Z", "u_disp1", "delta-early")
        w = self.svc.book_window(self.lot, "EXP-01", dn, "L01",
                                 "2026-10-12T08:00Z", "2026-10-12T10:00Z",
                                 "u_disp1", "delta-ok")
        self.assertEqual(w["state"], "PLANNED")

    def test_rework_unknown_slot_rejected(self):
        self.svc.expose_window(self.wins[0]["id"], "u_disp1")
        self.expect("SLOT_NOT_IN_NODE", self.svc.create_rework,
                    self.lot, "r", "u_mei",
                    [{"slot": "L99", "name": "n", "data": b"@LAYER 99\n"}], "rw2")


class TestExport(_Base):
    def setUp(self):
        super().setUp()
        self.rid = finalized(self.svc)
        self.sid, self.nid = master_set(self.svc, self.rid)

    def test_export_package_readonly_and_manifest(self):
        e = self.exp.enqueue(self.nid, "u_op", "exp1")
        done = self.exp.recover()[0]
        self.assertEqual(done["state"], "DONE")
        zpath = Path(done["zip_path"])
        self.assertTrue(zpath.exists())
        self.assertEqual(os.stat(zpath).st_mode & 0o777, 0o440)
        with zipfile.ZipFile(zpath) as zf:
            names = zf.namelist()
            self.assertIn("MANIFEST.json", names)
            self.assertIn("README.txt", names)
            mani = json.loads(zf.read("MANIFEST.json"))
        self.assertEqual(mani["delivery_no"], self.svc.release_detail(self.rid)["delivery_no"])
        # manifest 自摘要可离线复算
        from app.mask_store import canonical_bytes
        expect = sha256_hex(canonical_bytes(
            {k: v for k, v in mani.items() if k != "manifest_sha256"}))
        self.assertEqual(mani["manifest_sha256"], expect)

    def test_export_rejects_tampered_blob(self):
        self.exp.enqueue(self.nid, "u_op", "exp2")
        # 篡改落盘 blob
        art = self.store.q_one("SELECT * FROM mask_artifact WHERE kind='die'")
        p = self.store.blob_path(art["blob_id"])
        p.chmod(0o640)
        p.write_bytes(b"DIE 1 1\n")
        jobs = self.exp.recover()
        self.assertEqual(jobs[0]["state"], "FAILED")
        self.assertEqual(jobs[0]["error"], "DIGEST_MISMATCH")

    def test_export_crash_resume(self):
        e = self.exp.enqueue(self.nid, "u_op", "exp3")
        # 模拟崩溃：作业停在 QUEUED；新进程构造新的 ExportService（不立即恢复）
        store2 = MaskStore(f"{self.dir}/m.db", blob_dir=f"{self.dir}/blobs")
        exp2 = ExportService(store2, export_root=f"{self.dir}/exports", daemon=False)
        # 作业确实停在 QUEUED
        self.assertEqual(self.exp.export_detail(e["id"])["state"], "QUEUED")
        done = exp2.recover()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["state"], "DONE")
        # 幂等：没有未完成作业时返回空，再恢复也不产生第二个包
        self.assertEqual(exp2.recover(), [])
        self.assertEqual(self.store.q_one(
            "SELECT COUNT(*) n FROM mask_export WHERE node_id=? AND state='DONE'",
            (self.nid,))["n"], 1)

    def test_export_replay_same_op(self):
        e1 = self.exp.enqueue(self.nid, "u_op", "exp4")
        e2 = self.exp.enqueue(self.nid, "u_op", "exp4")
        self.assertEqual(e1["id"], e2["id"])


class TestPersistence(unittest.TestCase):
    def test_reopen_db_keeps_state(self):
        d = tempfile.mkdtemp()
        s1 = MaskStore(f"{d}/m.db", blob_dir=f"{d}/blobs")
        svc = MaskService(s1)
        rid = finalized(svc)
        sid, nid = master_set(svc, rid)
        s2 = MaskStore(f"{d}/m.db", blob_dir=f"{d}/blobs")
        svc2 = MaskService(s2)
        self.assertEqual(svc2.release_detail(rid)["delivery_no"],
                         svc.release_detail(rid)["delivery_no"])
        self.assertEqual(svc2.node_detail(nid)["slots"][0]["slot"],
                         svc.node_detail(nid)["slots"][0]["slot"])


class TestNormTs(unittest.TestCase):
    def test_z_suffix_and_order(self):
        a = norm_ts("2026-10-05T08:00Z")
        b = norm_ts("2026-10-05T10:00:00+00:00")
        self.assertLess(a, b)
        with self.assertRaises(MaskError):
            norm_ts("not-a-time")


class TestCrashRecovery(unittest.TestCase):
    def test_pending_op_marked_and_safe_retry_with_same_op(self):
        d = tempfile.mkdtemp()
        store = MaskStore(f"{d}/m.db", blob_dir=f"{d}/blobs")
        svc = MaskService(store)
        rid = finalized(svc)
        sid, nid = master_set(svc, rid)
        lot = svc.create_lot("L", "u_disp1")["id"]
        svc.bind_lot(lot, sid, "u_disp1", "bind-crash")
        # 模拟进程在窗口业务提交前崩溃：手工插一条 PENDING
        from app.mask_store import utcnow
        with store.tx() as c:
            c.execute(
                "INSERT INTO mask_op(op_id,kind,request_fp,status,response_json,http_status,"
                "created_at,expires_at) VALUES(?,?,?,'PENDING','{}',0,?,?)",
                ("win-crash-1", "window.book", "deadbeef", utcnow(), "2099-01-01T00:00:00+00:00"))
        rec = svc.recover_pending_ops()
        self.assertEqual(rec["interrupted_ops"], ["win-crash-1"])
        # 用原编号安全重试：业务正常执行，只产生一个窗口
        w = svc.book_window(lot, "EXP-01", nid, "L01",
                            "2026-12-01T08:00Z", "2026-12-01T10:00Z",
                            "u_disp1", "win-crash-1")
        self.assertEqual(w["state"], "PLANNED")
        self.assertEqual(store.q_one(
            "SELECT COUNT(*) n FROM mask_window WHERE op_id='win-crash-1'")["n"], 1)
        # 再用同编号重放，仍是同一个窗口
        w2 = svc.book_window(lot, "EXP-01", nid, "L01",
                             "2026-12-01T08:00Z", "2026-12-01T10:00Z",
                             "u_disp1", "win-crash-1")
        self.assertEqual(w2["id"], w["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
