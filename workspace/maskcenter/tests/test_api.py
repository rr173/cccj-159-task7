"""HTTP 接口端到端（真实端口 + 标准库 urllib）。"""
import json
import threading
import tempfile
import unittest
import urllib.request
import urllib.error
from pathlib import Path

from mdc.api import make_server
from mdc.store import Store
from mdc.service import Service


class ApiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.httpd = make_server("127.0.0.1", 0, Store(Path(cls.tmp.name)))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.svc = cls.httpd.service

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, actor=None, op=None, raw=None,
             headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        hdr = headers or {}
        if actor:
            hdr["X-Person-Id"] = actor
        if op:
            hdr["X-Op-Id"] = op
        data = None
        if raw is not None:
            data = raw
        elif body is not None:
            data = json.dumps(body).encode()
            hdr["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdr, method=method)
        try:
            with urllib.request.urlopen(req) as r:
                ct = r.headers.get("Content-Type", "")
                payload = r.read()
                return r.status, (json.loads(payload) if "json" in ct else payload)
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                return e.code, json.loads(payload)
            except json.JSONDecodeError:
                return e.code, payload

    def setUp(self):
        self.suffix = "API" + str(id(self))[-4:]
        self.demo = self.call("POST", "/api/demo-packet",
                              {"suffix": self.suffix}, actor="u_admin")[1]
        self.r = self.call("POST", "/api/imports", self.demo["packet"],
                           actor="u_admin")[1]
        self.dno = self.r["delivery_no"]
        self.assertEqual(self.r["status"], "VALID")

    def test_health_and_lists(self):
        self.assertEqual(self.call("GET", "/api/health")[1]["ok"], True)
        self.assertTrue(len(self.call("GET", "/api/artifacts")[1]) > 0)

    def test_upload_raw_and_dedup(self):
        data = b"hellobytes"
        s1, j1 = self.call("POST", "/api/content", raw=data, actor="u_admin",
                           headers={"X-Logical-Name": "raw1.bin",
                                    "X-Kind": "OTHER"})
        self.assertEqual(s1, 200)
        s2, j2 = self.call("POST", "/api/content", raw=data, actor="u_admin",
                           headers={"X-Logical-Name": "raw1.bin",
                                    "X-Kind": "OTHER"})
        self.assertTrue(j2["dedup"])

    def test_upload_wrong_declared_digest(self):
        s, j = self.call("POST", "/api/content", raw=b"abc", actor="u_admin",
                         headers={"X-Logical-Name": "x", "X-Kind": "GDS",
                                  "X-Sha256": "f" * 64})
        self.assertEqual(j["error"], "DIGEST_MISMATCH")

    def test_requires_actor(self):
        s, j = self.call("POST", "/api/tools", {"name": "X"})
        self.assertEqual(s, 401)
        self.assertEqual(j["error"], "UNAUTHORIZED")

    def test_unauthorized_role(self):
        s, j = self.call("POST", "/api/tools", {"name": "X"}, actor="u_mei")
        self.assertEqual(s, 403)

    def test_full_flow_over_http(self):
        # 工具 / lot / 绑定 / 预订 / 抢占 / 曝光 / 替换 / delta / 打包
        _, tool = self.call("POST", "/api/tools", {"name": "T-" + self.suffix},
                            actor="u_disp1")
        _, lot = self.call("POST", "/api/lots",
                           {"display_name": "L-" + self.suffix},
                           actor="u_disp1")
        self.call("POST", f"/api/lots/{lot['id']}/bind", {"set": self.dno},
                  actor="u_disp1")
        s, win = self.call("POST", "/api/windows", {
            "tool_id": tool["id"], "set": self.dno,
            "mask": "M_MAIN", "lot_id": lot["id"],
            "start_ts": "2026-10-10T08:00:00Z",
            "end_ts": "2026-10-10T10:00:00Z"}, actor="u_disp1", op="W1")
        self.assertEqual(s, 201)
        s2, lose = self.call("POST", "/api/windows", {
            "tool_id": tool["id"], "set": self.dno,
            "mask": "M_MAIN",
            "start_ts": "2026-10-10T09:00:00Z",
            "end_ts": "2026-10-10T11:00:00Z"}, actor="u_disp2", op="W2")
        self.assertEqual(lose["error"], "WINDOW_OVERLAP")
        self.assertEqual(lose["detail"]["winner_op_id"], "W1")
        # 原操作编号安全重试：赢家得到同一窗口
        s3, replay = self.call("POST", "/api/windows", {
            "tool_id": tool["id"], "set": self.dno,
            "mask": "M_MAIN", "lot_id": lot["id"],
            "start_ts": "2026-10-10T08:00:00Z",
            "end_ts": "2026-10-10T10:00:00Z"}, actor="u_disp1", op="W1")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["window_id"], win["window_id"])
        # 曝光 → 封存
        _, ex = self.call("POST", f"/api/windows/{win['window_id']}/expose",
                          {}, actor="u_disp1")
        self.assertEqual(ex["set_status"], "SEALED")
        # 封存后预订被拒
        s4, sealed = self.call("POST", "/api/windows", {
            "tool_id": tool["id"], "set": self.dno,
            "mask": "M_MAIN", "lot_id": lot["id"],
            "start_ts": "2027-10-10T08:00:00Z",
            "end_ts": "2027-10-10T10:00:00Z"}, actor="u_disp1", op="W3")
        self.assertEqual(sealed["error"], "SET_SEALED_INPLACE")
        # delta + 打包 + 下载
        from mdc.domain import build_gds_for_test
        import hashlib
        gds = build_gds_for_test([(100, 0), (101, 0), (200, 0)])
        _, up = self.call("POST", "/api/content", raw=gds, actor="u_mei",
                          headers={"X-Logical-Name": "fix.gds", "X-Kind": "GDS"})
        _, dl = self.call("POST", "/api/deltas", {
            "set": self.dno,
            "changes": [{"mask_name": "M_MAIN", "new_sha": up["sha256"]}]},
            actor="u_mei", op="DL1")
        self.assertIn("MS-", dl["delivery_no"])
        _, pk = self.call("POST", "/api/packages", {"set": self.dno},
                          actor="u_disp1")
        s5, data = self.call("GET", f"/api/packages/{pk['package_id']}/download")
        self.assertEqual(s5, 200)
        self.assertEqual(hashlib.sha256(data).hexdigest(), pk["sha256"])

    def test_audit_present(self):
        rows = self.call("GET", "/api/audit?limit=10")[1]
        self.assertTrue(any(r["action"] == "release.import" for r in rows))


if __name__ == "__main__":
    unittest.main()
