"""光罩投片交付中心 HTTP API（标准库 http.server，零第三方依赖）。

启动: python3 -m app.mask_api --db data/mask.db --port 8081
页面:
  /           交付中心工作台（上传/构件关系/核验结论/谱系）
  /schedule   曝光窗口与 wafer lot 编排（抢占/裁决/双签替换/返工）
  /fab        晶圆厂只读交付包（导出/下载/审计）
"""
from __future__ import annotations

import argparse
import base64
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .mask_export import ExportService
from .mask_service import MaskError, MaskService, sha256_hex
from .mask_store import SEED_USERS, MaskStore

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
_MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8"}


def _decode_artifact(b: dict) -> tuple[str, str, bytes, str | None, int | None]:
    """从请求体解析构件 payload：data 支持 hex/base64，或直接 UTF-8 文本。"""
    kind = b.get("kind")
    name = b.get("name")
    if not kind or not name:
        raise MaskError("BAD_REQUEST", "构件需要 kind 与 name", 400)
    data = None
    if b.get("data_hex") is not None:
        try:
            data = bytes.fromhex(b["data_hex"])
        except ValueError:
            raise MaskError("BAD_REQUEST", "data_hex 不是合法十六进制", 400)
    elif b.get("data_base64") is not None:
        try:
            data = base64.b64decode(b["data_base64"], validate=True)
        except Exception:
            raise MaskError("BAD_REQUEST", "data_base64 不合法", 400)
    elif b.get("content") is not None:
        data = str(b["content"]).encode("utf-8")
    else:
        raise MaskError("BAD_REQUEST", "必须提供 data_hex / data_base64 / content 之一", 400)
    declared = b.get("declared_sha256")
    layer_no = b.get("layer_no")
    return kind, name, data, declared, layer_no


def make_server(store: MaskStore, host="0.0.0.0", port=8081, export_svc: ExportService | None = None):
    svc = MaskService(store)
    export_svc = export_svc or ExportService(store, daemon=True)
    # 崩溃恢复：续完中断的打包作业，并把残留的资源裁决/操作编号标记为 INTERRUPTED
    svc.recover_pending_ops()
    export_svc.recover()

    class Handler(BaseHTTPRequestHandler):
        server_version = "MaskCenter/1.0"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, payload, ctype="application/json", extra_headers=None):
            body = payload if isinstance(payload, bytes) else json.dumps(
                payload, ensure_ascii=False, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise MaskError("BAD_JSON", "请求体不是合法 JSON", 400)

        def _err(self, e: MaskError):
            self._send(e.http_status, {"error": e.code, "message": e.message,
                                       "detail": e.extra})

        def _q(self, name, default=None, cast=str):
            qs = parse_qs(urlparse(self.path).query)
            return cast(qs[name][0]) if name in qs else default

        def _by(self, b):
            return b.get("by") or self.headers.get("X-User")

        def _static(self, rel):
            p = (WEB_DIR / rel).resolve()
            if not str(p).startswith(str(WEB_DIR.resolve())) or not p.is_file():
                self._send(404, {"error": "NOT_FOUND", "message": str(rel)})
                return
            self._send(200, p.read_bytes(), _MIME.get(p.suffix, "application/octet-stream"))

        # ---------- GET ----------
        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                if path == "/":
                    return self._static("mask.html")
                if path == "/schedule":
                    return self._static("mask_schedule.html")
                if path == "/fab":
                    return self._static("mask_fab.html")
                if path.startswith("/mask-static/"):
                    return self._static(path[len("/mask-static/"):])

                if path == "/api/mask/users":
                    return self._send(200, {"users": [{"id": k, **v} for k, v in SEED_USERS.items()]})
                if path == "/api/mask/machines":
                    return self._send(200, {"machines": svc.list_machines()})
                if path == "/api/mask/releases":
                    return self._send(200, {"releases": svc.list_releases()})
                if path == "/api/mask/quarantine":
                    return self._send(200, {"quarantines": svc.list_quarantine(
                        self._q("all") != "1")})
                if path == "/api/mask/sets":
                    return self._send(200, {"mask_sets": svc.list_mask_sets()})
                if path == "/api/mask/lots":
                    return self._send(200, {"lots": svc.list_lots()})
                if path == "/api/mask/windows":
                    return self._send(200, {"windows": svc.list_windows(
                        self._q("machine"), self._q("lot"))})
                if path == "/api/mask/arbitrations":
                    return self._send(200, {"arbitrations": svc.arbitrations(
                        self._q("resource"), self._q("limit", 100, int))})
                if path == "/api/mask/replacements":
                    return self._send(200, {"replacements": svc.list_replacements()})
                if path == "/api/mask/reworks":
                    return self._send(200, {"reworks": svc.list_reworks()})
                if path == "/api/mask/exports":
                    return self._send(200, {"exports": export_svc.list_exports()})
                if path == "/api/mask/audit":
                    return self._send(200, {"events": svc.audit_log(
                        self._q("entity"), self._q("action"), self._q("op_id"),
                        self._q("limit", 200, int))})

                m = re.fullmatch(r"/api/mask/releases/([^/]+)", path)
                if m:
                    return self._send(200, svc.release_detail(m.group(1)))
                m = re.fullmatch(r"/api/mask/releases/([^/]+)/verifications", path)
                if m:
                    return self._send(200, {"verifications": svc.verifications(m.group(1))})
                m = re.fullmatch(r"/api/mask/artifacts/([^/]+)/raw", path)
                if m:
                    art = store.q_one("SELECT * FROM mask_artifact WHERE id=?", (m.group(1),))
                    if not art:
                        raise MaskError("ARTIFACT_NOT_FOUND", "构件不存在", 404)
                    data = store.read_blob(art["blob_id"])
                    return self._send(200, data, "application/octet-stream",
                                      {"Content-Disposition": f'attachment; filename="{art["name"]}"'})
                m = re.fullmatch(r"/api/mask/sets/([^/]+)", path)
                if m:
                    return self._send(200, svc.mask_set_detail(m.group(1)))
                m = re.fullmatch(r"/api/mask/nodes/([^/]+)", path)
                if m:
                    return self._send(200, svc.node_detail(m.group(1)))
                m = re.fullmatch(r"/api/mask/lots/([^/]+)", path)
                if m:
                    return self._send(200, svc.lot_detail(m.group(1)))
                m = re.fullmatch(r"/api/mask/windows/([^/]+)", path)
                if m:
                    r = store.q_one("SELECT * FROM mask_window WHERE id=?", (m.group(1),))
                    if not r:
                        raise MaskError("WINDOW_NOT_FOUND", "窗口不存在", 404)
                    return self._send(200, dict(r))
                m = re.fullmatch(r"/api/mask/exports/([^/]+)", path)
                if m:
                    return self._send(200, export_svc.export_detail(m.group(1)))
                m = re.fullmatch(r"/api/mask/exports/([^/]+)/zip", path)
                if m:
                    e = export_svc.export_detail(m.group(1))
                    if e["state"] != "DONE":
                        raise MaskError("EXPORT_NOT_READY", f"作业状态 {e['state']}", 409)
                    return self._send(200, Path(e["zip_path"]).read_bytes(), "application/zip",
                                      {"Content-Disposition":
                                       f'attachment; filename="{Path(e["zip_path"]).name}"'})
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except MaskError as e:
                self._err(e)

        # ---------- POST ----------
        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                b = self._body()

                if path == "/api/mask/admin/recover":
                    return self._send(200, {
                        "exports": [e["id"] for e in export_svc.recover()],
                        **svc.recover_pending_ops()})
                if path == "/api/mask/admin/reset":
                    store.reset()
                    return self._send(200, {"reset": True})

                if path == "/api/mask/releases":
                    return self._send(201, svc.create_release(
                        b.get("name", ""), self._by(b), b.get("declared_digests")))

                m = re.fullmatch(r"/api/mask/releases/([^/]+)/artifacts", path)
                if m:
                    kind, name, data, declared, layer_no = _decode_artifact(b)
                    return self._send(201, svc.add_artifact(
                        m.group(1), kind, name, data, declared, self._by(b),
                        layer_no=layer_no, op_id=b.get("op_id")))
                m = re.fullmatch(r"/api/mask/releases/([^/]+)/verify", path)
                if m:
                    return self._send(200, svc.verify_release(m.group(1)))
                m = re.fullmatch(r"/api/mask/releases/([^/]+)/finalize", path)
                if m:
                    return self._send(200, svc.finalize_release(
                        m.group(1), self._by(b), b.get("op_id")))
                m = re.fullmatch(r"/api/mask/sets", path)
                if m:
                    return self._send(201, svc.create_mask_set(
                        b["release_id"], b.get("name", "maskset"), self._by(b),
                        b.get("op_id")))
                m = re.fullmatch(r"/api/mask/sets/([^/]+)/nodes/derive", path)
                if m:
                    _, name, data, declared, layer_no = _decode_artifact(b)
                    return self._send(201, svc.derive_node(
                        m.group(1), b["parent_node_id"], b.get("label"), self._by(b),
                        b["slot"], {"name": name, "data": data, "declared_sha256": declared},
                        b.get("op_id")))

                m = re.fullmatch(r"/api/mask/quarantine/([^/]+)/resolve", path)
                if m:
                    return self._send(200, svc.resolve_quarantine(
                        m.group(1), b.get("resolution", ""), self._by(b), b.get("note")))

                if path == "/api/mask/lots":
                    return self._send(201, svc.create_lot(b.get("name", ""), self._by(b)))
                m = re.fullmatch(r"/api/mask/lots/([^/]+)/bind", path)
                if m:
                    return self._send(200, svc.bind_lot(
                        m.group(1), b["mask_set_id"], self._by(b), b.get("op_id")))
                if path == "/api/mask/windows":
                    return self._send(201, svc.book_window(
                        b["lot_id"], b["machine_id"], b["node_id"], b["slot"],
                        b["start"], b["end"], self._by(b), b.get("op_id")))
                m = re.fullmatch(r"/api/mask/windows/([^/]+)/cancel", path)
                if m:
                    return self._send(200, svc.cancel_window(m.group(1), self._by(b)))
                m = re.fullmatch(r"/api/mask/windows/([^/]+)/expose", path)
                if m:
                    return self._send(200, svc.expose_window(m.group(1), self._by(b)))

                m = re.fullmatch(r"/api/mask/sets/([^/]+)/replacements", path)
                if m:
                    _, name, data, declared, _ = _decode_artifact(b)
                    return self._send(201, svc.request_replacement(
                        b["release_id"], m.group(1), b["node_id"], b["slot"], name, data,
                        declared, self._by(b), b.get("reason", ""), b.get("op_id")))
                m = re.fullmatch(r"/api/mask/replacements/([^/]+)/approve", path)
                if m:
                    return self._send(200, svc.approve_replacement(
                        m.group(1), b.get("role", ""), self._by(b)))
                if path == "/api/mask/reworks":
                    changes = []
                    for ch in b.get("changes", []):
                        kind, name, data, declared, layer_no = _decode_artifact(
                            {**ch, "kind": "layout"})
                        changes.append({"slot": ch["slot"], "name": name, "data": data,
                                        "declared_sha256": declared})
                    return self._send(201, svc.create_rework(
                        b["lot_id"], b.get("reason", ""), self._by(b), changes, b.get("op_id")))

                if path == "/api/mask/exports":
                    return self._send(202, export_svc.enqueue(
                        b["node_id"], self._by(b), b.get("op_id")))

                self._send(404, {"error": "NOT_FOUND", "message": path})
            except MaskError as e:
                self._err(e)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.mask_store = store
    httpd.export_svc = export_svc
    return httpd


def main(argv=None):
    ap = argparse.ArgumentParser(description="光罩投片交付中心 HTTP 服务")
    ap.add_argument("--db", default="data/mask.db")
    ap.add_argument("--blob-dir", default=None)
    ap.add_argument("--export-dir", default=None)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8081)
    args = ap.parse_args(argv)
    store = MaskStore(args.db, blob_dir=args.blob_dir)
    export_svc = ExportService(store, export_root=args.export_dir, daemon=True)
    httpd = make_server(store, args.host, args.port, export_svc)
    print(f"光罩投片交付中心: http://{args.host}:{args.port}  (db={args.db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        export_svc.stop_daemon()


if __name__ == "__main__":
    main()
