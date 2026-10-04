"""只读交付包：确定性、幂等复用、篡改检测、崩溃续建。"""
import json
import tarfile
from pathlib import Path

from mdc.domain import DomainError
from mdc.store import utcnow
from tests.helpers import BaseCase


class TestPackage(BaseCase):
    def setUp(self):
        super().setUp()
        self.s = self.valid_set("P")
        self.dno = self.s["delivery_no"]

    def test_build_deterministic_and_verify(self):
        p1 = self.svc.build_package("u_disp1", self.dno, op_id="P1")
        self.assertEqual(p1["state"], "READY")
        p2 = self.svc.build_package("u_disp1", self.dno, op_id="P2")
        self.assertTrue(p2["reused"])
        self.assertEqual(p1["sha256"], p2["sha256"])
        path, row = self.svc.get_package_file(p1["package_id"])
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o444")
        with tarfile.open(path) as tar:
            names = tar.getnames()
            self.assertIn("MANIFEST.json", names)
            manifest = json.loads(tar.extractfile("MANIFEST.json").read())
        self.assertEqual(manifest["delivery_no"], self.dno)
        self.assertTrue(manifest["read_only"])
        self.assertEqual(manifest["exposure_order"], self.s["order"])
        self.assertEqual(len(manifest["masks"]), len(self.s["members"]))

    def test_tampered_package_file_rejected(self):
        p = self.svc.build_package("u_disp1", self.dno, op_id="P1")
        fp = Path(p["path"])
        fp.chmod(0o644)
        fp.write_bytes(fp.read_bytes() + b"x")
        with self.assertRaises(DomainError) as cm:
            self.svc.get_package_file(p["package_id"])
        self.assertEqual(cm.exception.code, "PACKAGE_TAMPERED")
        fp.chmod(0o444)

    def test_resume_building_after_crash(self):
        # 直接落一条 BUILDING 记录（进程在构建中途死亡）
        with self.svc.s.tx() as c:
            target = str(self.svc.s.new_package_path("PKG-CRASH"))
            c.execute(
                "INSERT INTO package(id,set_id,file_path,status,op_id,created_by,"
                "created_at) VALUES('PKG-CRASH',?,?, 'BUILDING',?,?,?)",
                (self.s["id"], target, "OP-C", "u_disp1", utcnow()))
        Path(target).write_bytes(b"partial")
        # 新进程：构造即恢复
        svc2 = type(self.svc)(self.svc.s)
        row = self.svc.s.q_one("SELECT * FROM package WHERE id='PKG-CRASH'")
        self.assertEqual(row["status"], "READY")
        path, _ = svc2.get_package_file("PKG-CRASH")
        self.assertTrue(path.exists())

    def test_member_tamper_blocks_build(self):
        member = self.svc.s.q_one(
            "SELECT sha256 FROM set_member WHERE set_id=?", (self.s["id"],))
        path = self.svc.s.cas_path(member["sha256"])
        original = path.read_bytes()
        # CAS 内容被改，但登记摘要未变 → 构建时重新计算发现不一致
        path.chmod(0o644)
        try:
            path.write_bytes(original + b"TAMPER")
            with self.assertRaises(DomainError) as cm:
                self.svc.build_package("u_disp1", self.dno, op_id="PT")
            self.assertIn(cm.exception.code,
                          ("DIGEST_TAMPERED", "PACKAGE_BUILD_FAILED"))
        finally:
            path.write_bytes(original)
            path.chmod(0o444)
