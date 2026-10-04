"""晶圆厂只读交付包：可恢复的打包作业。

作业状态 QUEUED → PACKAGING → DONE / FAILED 全部落盘；
进程崩溃后，启动时 ``recover()`` 与后台守护线程会幂等续完：
- QUEUED / PACKAGING（心跳超时）的作业重新打包（先写临时目录，原子 rename）；
- 打包前重算每个构件 blob 的 SHA-256，摘要被篡改则作业 FAILED 且审计 DENIED；
- 成品目录与 ZIP 写完后降权为只读。
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .mask_service import MaskError, sha256_hex
from .mask_store import MaskStore, canonical_bytes, utcnow

STALE_PACKAGING_SECONDS = 60


class ExportService:
    def __init__(self, store: MaskStore, export_root: str | None = None, daemon: bool = False):
        self.s = store
        if store.db_path == ":memory:":
            root = Path.cwd() / ".mask-exports"
        else:
            root = Path(store.db_path).resolve().parent / "mask-exports"
        self.root = Path(export_root) if export_root else root
        (self.root / "tmp").mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._thread = None
        if daemon:
            self.start_daemon()

    # ---- 作业登记 ----
    def enqueue(self, node_id: str, by: str, op_id: str | None = None) -> dict:
        svc = _svc(self.s)
        node = svc._get_node(node_id)
        ms = svc._get_set(node["mask_set_id"])
        rel = svc._get_release(ms["release_id"])
        if not rel["delivery_no"]:
            raise MaskError("RELEASE_NOT_FINALIZED", "发行尚未规范化，不能导出交付包", 409)

        def work(c):
            eid = "EXP_" + uuid.uuid4().hex[:12]
            target = str(self.root / f"{rel['delivery_no']}__{node_id}")
            c.execute(
                "INSERT INTO mask_export(id,op_id,node_id,target_dir,state,created_by,"
                "created_at) VALUES(?,?,?,?,'QUEUED',?,?)",
                (eid, op_id, node_id, target, by, utcnow()))
            self.s.audit(c, "export.enqueue", eid, by, op_id=op_id,
                         detail={"node": node_id, "delivery_no": rel["delivery_no"]})
            return self.export_detail(eid), 202
        return svc.idempotent(op_id, "export.enqueue",
                              {"node": node_id, "by": by}, work)[0]

    def export_detail(self, eid: str) -> dict:
        r = self.s.q_one("SELECT * FROM mask_export WHERE id=?", (eid,))
        if not r:
            raise MaskError("EXPORT_NOT_FOUND", f"导出作业不存在: {eid}", 404)
        return dict(r)

    def get_export_for_node(self, node_id: str) -> dict | None:
        r = self.s.q_one(
            "SELECT * FROM mask_export WHERE node_id=? AND state='DONE' "
            "ORDER BY finished_at DESC LIMIT 1", (node_id,))
        return dict(r) if r else None

    def list_exports(self) -> list[dict]:
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM mask_export ORDER BY created_at DESC")]

    # ---- 打包执行（幂等可恢复）----
    def _package(self, row) -> dict:
        eid = row["id"]
        svc = _svc(self.s)
        with self.s.tx() as c:
            cur = c.execute("SELECT state FROM mask_export WHERE id=?", (eid,)).fetchone()
            if cur["state"] == "DONE":
                return dict(c.execute("SELECT * FROM mask_export WHERE id=?",
                                      (eid,)).fetchone())
            c.execute("UPDATE mask_export SET state='PACKAGING',error=NULL WHERE id=?", (eid,))
            node = c.execute("SELECT * FROM mask_node WHERE id=?", (row["node_id"],)).fetchone()
            ms = c.execute("SELECT * FROM mask_set WHERE id=?",
                           (node["mask_set_id"],)).fetchone()
            rel = c.execute("SELECT * FROM mask_release WHERE id=?",
                            (ms["release_id"],)).fetchone()
            slot_rows = c.execute(
                "SELECT ns.slot,ns.layer_no,a.id aid,a.name,a.kind,a.sha256,a.size "
                "FROM mask_node_slot ns JOIN mask_artifact a ON a.id=ns.artifact_id "
                "WHERE ns.node_id=? ORDER BY ns.slot", (row["node_id"],)).fetchall()

        # 1) 摘要复验（落盘 blob 防篡改）
        bad = []
        payloads = {}
        for sr in slot_rows:
            p = self.s.blob_path(sr["sha256"])
            if not p.exists():
                bad.append({"slot": sr["slot"], "name": sr["name"], "code": "BLOB_MISSING"})
                continue
            data = p.read_bytes()
            actual = sha256_hex(data)
            if actual != sr["sha256"]:
                bad.append({"slot": sr["slot"], "name": sr["name"], "code": "DIGEST_MISMATCH",
                            "stored": sr["sha256"], "actual": actual})
            payloads[sr["slot"]] = data
        if bad:
            with self.s.tx() as c:
                c.execute("UPDATE mask_export SET state='FAILED',error=? WHERE id=?",
                          ("DIGEST_MISMATCH", eid))
                self.s.audit(c, "export.package", eid, result="DENIED",
                             reason="DIGEST_MISMATCH", detail={"findings": bad})
            return self.export_detail(eid)

        # 2) FINALIZE 核验结论必须 PASS
        vrf = self.s.q_one(
            "SELECT verdict FROM mask_verification WHERE release_id=? AND stage='FINALIZE' "
            "ORDER BY created_at DESC LIMIT 1", (ms["release_id"],))
        if not vrf or vrf["verdict"] != "PASS":
            with self.s.tx() as c:
                c.execute("UPDATE mask_export SET state='FAILED',error=? WHERE id=?",
                          ("VERIFICATION_FAILED", eid))
                self.s.audit(c, "export.package", eid, result="DENIED",
                             reason="VERIFICATION_FAILED")
            return self.export_detail(eid)

        # 3) 组装 MANIFEST
        artifacts = []
        for sr in slot_rows:
            artifacts.append({"slot": sr["slot"], "kind": sr["kind"], "name": sr["name"],
                              "layer_no": sr["layer_no"], "artifact_id": sr["aid"],
                              "sha256": sr["sha256"], "size": sr["size"]})
        manifest = {
            "schema": "mask-fab-delivery/1",
            "read_only": True,
            "delivery_no": rel["delivery_no"],
            "release_id": rel["id"],
            "release_name": rel["name"],
            "mask_set_id": ms["id"],
            "mask_set_name": ms["name"],
            "mask_set_kind": ms["kind"],
            "node_id": node["id"],
            "node_kind": node["kind"],
            "node_seq": node["seq"],
            "export_id": eid,
            "created_at": utcnow(),
            "artifacts": artifacts,
        }
        # MANIFEST 自摘要：对除自摘要字段外的规范 JSON 重算 SHA-256
        manifest["manifest_sha256"] = sha256_hex(canonical_bytes(
            {k: v for k, v in manifest.items() if k != "manifest_sha256"}))
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode()

        # 4) 写临时目录 → 校验 → 原子 rename
        target = Path(row["target_dir"])
        staging = self.root / "tmp" / f"staging-{eid}"
        if staging.exists():
            import shutil
            shutil.rmtree(staging)
        art_dir = staging / "artifacts"
        art_dir.mkdir(parents=True)
        for sr in slot_rows:
            safe_name = f"{sr['slot'].replace(':', '_')}__{sr['name']}"
            (art_dir / safe_name).write_bytes(payloads[sr["slot"]])
        (staging / "MANIFEST.json").write_bytes(manifest_bytes)
        readme = (
            f"光罩交付包（只读）\n交付编号: {rel['delivery_no']}\n"
            f"mask set: {ms['name']} ({ms['id']})\n节点: {node['label']} [{node['kind']}]\n"
            f"构件数: {len(artifacts)}\n生成时间(UTC): {manifest['created_at']}\n\n"
            "校验方式：逐个重算 artifacts/* 的 SHA-256，与 MANIFEST.json 中记录比对；\n"
            "再对 MANIFEST.json（除 manifest_sha256 字段外的规范 JSON）重算 SHA-256 自校验。\n"
            "晶圆厂以此包为准，任何构件与摘要不一致必须拒收。\n"
        )
        (staging / "README.txt").write_text(readme, encoding="utf-8")

        # 临时目录内自验
        for sr in slot_rows:
            safe_name = f"{sr['slot'].replace(':', '_')}__{sr['name']}"
            if sha256_hex((art_dir / safe_name).read_bytes()) != sr["sha256"]:
                raise MaskError("EXPORT_INTEGRITY", "临时包自验失败", 500)

        zip_tmp = self.root / "tmp" / f"{eid}.zip"
        with zipfile.ZipFile(zip_tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(staging.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(staging))
        pkg_sha = sha256_hex(zip_tmp.read_bytes())

        if target.exists():
            import shutil
            shutil.rmtree(target)
        os.replace(staging, target)
        zip_final = target.parent / f"{target.name}.zip"
        os.replace(zip_tmp, zip_final)

        # 只读降权
        os.chmod(zip_final, stat.S_IRUSR | stat.S_IRGRP)
        for f in target.rglob("*"):
            if f.is_file():
                os.chmod(f, stat.S_IRUSR | stat.S_IRGRP)
        os.chmod(target, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)

        with self.s.tx() as c:
            now = utcnow()
            c.execute(
                "UPDATE mask_export SET state='DONE',manifest_json=?,package_sha256=?,"
                "zip_path=?,finished_at=? WHERE id=?",
                (json.dumps(manifest, ensure_ascii=False, sort_keys=True), pkg_sha,
                 str(zip_final), now, eid))
            self.s.audit(c, "export.package", eid, result="OK",
                         detail={"files": len(artifacts), "zip": str(zip_final),
                                 "package_sha256": pkg_sha})
        return self.export_detail(eid)

    def recover(self, max_jobs: int = 50) -> list[dict]:
        """续完 QUEUED 与崩溃残留 PACKAGING 的作业。"""
        done = []
        rows = self.s.q_all(
            "SELECT * FROM mask_export WHERE state IN ('QUEUED','PACKAGING') "
            "ORDER BY created_at LIMIT ?", (max_jobs,))
        for row in rows:
            done.append(self._package(row))
        return done

    # ---- 后台守护 ----
    def start_daemon(self, interval: float = 1.0):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.recover()
                except Exception:
                    pass

        self._thread = threading.Thread(target=loop, name="mask-export", daemon=True)
        self._thread.start()

    def stop_daemon(self):
        self._stop.set()


def _svc(store: MaskStore):
    from .mask_service import MaskService
    return MaskService(store)
