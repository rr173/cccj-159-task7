"""光罩投片交付中心 HTTP 端到端测试（真实 socket，零第三方依赖）。"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.client import IncompleteRead

from app.mask_api import make_server
from app.mask_export import ExportService
from app.mask_service import sha256_hex
from app.mask_store import MaskStore


def _req(method, url, body=None, raw=False):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            payload = resp.read()
            return resp.status, (payload if raw else json.loads(payload))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


FILES = [
    ("layermap", "layer.map", "LAYERMAP chip\nLAYER 1 a\nLAYER 2 b\n", None),
    ("recipe", "r.rcp", "RECIPE R\nLAYER 1\nLAYER 2\nCORNER ss\n", None),
    ("die", "die.dim", "DIE 10 20\n", None),
    ("scribe", "s.cfg", "SCRIBE WIDTH 5\n", None),
    ("corner", "ss.c", "CORNER ss\nv=1\n", None),
    ("layout", "L01.gds", "@LAYER 1\n", 1),
    ("layout", "L02.gds", "@LAYER 2\n", 2),
]


class TestMaskHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.store = MaskStore(f"{cls.dir}/m.db", blob_dir=f"{cls.dir}/blobs")
        cls.exp = ExportService(cls.store, export_root=f"{cls.dir}/exp", daemon=True)
        cls.httpd = make_server(cls.store, "127.0.0.1", 0, cls.exp)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.exp.stop_daemon()

    def _finalized(self, name="chip"):
        st, r = _req("POST", f"{self.base}/api/mask/releases", {"name": name, "by": "u_op"})
        self.assertEqual(st, 201)
        rid = r["id"]
        for kind, fname, content, lno in FILES:
            st, a = _req("POST", f"{self.base}/api/mask/releases/{rid}/artifacts",
                         {"kind": kind, "name": fname, "content": content,
                          "declared_sha256": sha256_hex(content.encode()),
                          "layer_no": lno, "by": "u_op"})
            self.assertEqual(st, 201, a)
        st, v = _req("POST", f"{self.base}/api/mask/releases/{rid}/verify", {})
        self.assertEqual(v["verdict"], "PASS")
        st, f = _req("POST", f"{self.base}/api/mask/releases/{rid}/finalize",
                     {"by": "u_op", "op_id": f"fin-{name}-{time.time_ns()}"})
        self.assertEqual(st, 200)
        return rid, f["delivery_no"]

    def test_01_pages_reachable(self):
        for path in ("/", "/schedule", "/fab", "/mask-static/mask.js",
                     "/mask-static/mask_schedule.js", "/mask-static/mask_fab.js"):
            with urllib.request.urlopen(f"{self.base}{path}", timeout=5) as r:
                self.assertEqual(r.status, 200)

    def test_02_full_flow_concurrent_book_and_export(self):
        rid, dno = self._finalized("chipX")
        self.assertTrue(dno.startswith("MS-"))
        st, s = _req("POST", f"{self.base}/api/mask/sets",
                     {"release_id": rid, "name": "X", "by": "u_op",
                      "op_id": f"set-{time.time_ns()}"})
        self.assertEqual(st, 201)
        sid = s["id"]
        st, sd = _req("GET", f"{self.base}/api/mask/sets/{sid}")
        nid = sd["nodes"][0]["id"]

        st, lot = _req("POST", f"{self.base}/api/mask/lots", {"name": "L", "by": "u_disp1"})
        lot_id = lot["id"]
        st, _ = _req("POST", f"{self.base}/api/mask/lots/{lot_id}/bind",
                     {"mask_set_id": sid, "by": "u_disp1",
                      "op_id": f"bind-{time.time_ns()}"})
        self.assertEqual(st, 200)

        # 并发抢同一机器时段（不同 slot）→ 唯一赢家
        barrier = threading.Barrier(3)
        out = []

        def book(who, op, slot):
            barrier.wait()
            st, w = _req("POST", f"{self.base}/api/mask/windows",
                         {"lot_id": lot_id, "machine_id": "EXP-01", "node_id": nid,
                          "slot": slot, "start": "2026-11-01T08:00Z",
                          "end": "2026-11-01T10:00Z", "by": who, "op_id": op})
            out.append((st, w.get("error")))

        ts = [threading.Thread(target=book, args=(u, f"h-{i}-{time.time_ns()}", slot))
              for i, (u, slot) in enumerate(
                  [("u_disp1", "L01"), ("u_disp2", "L02"), ("u_disp1", "layermap")])]
        for t in ts: t.start()
        for t in ts: t.join()
        wins = [o for o in out if o[0] == 201]
        loses = [o for o in out if o[0] == 409]
        self.assertEqual(len(wins), 1)
        self.assertTrue(all(o[1] == "WINDOW_OVERLAP" for o in loses))

        # 导出只读包并下载
        st, e = _req("POST", f"{self.base}/api/mask/exports",
                     {"node_id": nid, "by": "u_op", "op_id": f"exp-{time.time_ns()}"})
        self.assertIn(st, (201, 202))
        eid = e["id"]
        for _ in range(30):
            st, ed = _req("GET", f"{self.base}/api/mask/exports/{eid}")
            if ed["state"] in ("DONE", "FAILED"):
                break
            time.sleep(0.2)
        self.assertEqual(ed["state"], "DONE", ed)
        with urllib.request.urlopen(f"{self.base}/api/mask/exports/{eid}/zip") as z:
            pkg = z.read()
            self.assertEqual(z.headers.get_content_type(), "application/zip")
        self.assertEqual(sha256_hex(pkg), ed["package_sha256"])

    def test_03_tampered_digest_rejected(self):
        st, r = _req("POST", f"{self.base}/api/mask/releases",
                     {"name": "bad", "by": "u_op"})
        rid = r["id"]
        st, err = _req("POST", f"{self.base}/api/mask/releases/{rid}/artifacts",
                       {"kind": "die", "name": "d", "content": "DIE 1 2\n",
                        "declared_sha256": "0" * 64, "by": "u_op"})
        self.assertEqual(st, 422)
        self.assertEqual(err["error"], "DIGEST_MISMATCH")

    def test_04_error_envelope(self):
        st, err = _req("GET", f"{self.base}/api/mask/releases/NOPE")
        self.assertEqual(st, 404)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
