"""HTTP 接口：仅标准库 http.server，JSON 为主，内容上传支持原始字节。

身份用 X-Person-Id 头；写操作可带 X-Op-Id（原操作编号，安全重试/唯一赢家）。
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from .domain import DomainError
from .service import Service
from .store import Store

WEB_DIR = Path(__file__).resolve().parent / "web"


def _read_json(handler: BaseHTTPRequestHandler, max_bytes: int = 64 * 1024 * 1024):
    n = int(handler.headers.get("Content-Length", "0") or 0)
    if n <= 0:
        return {}
    if n > max_bytes:
        raise DomainError("PAYLOAD_TOO_LARGE", f"请求体超过 {max_bytes} 字节", 413)
    raw = handler.rfile.read(n)
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise DomainError("BAD_JSON", "请求体不是合法 JSON", 400)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "MaskCenter/1.0"
    svc: Service = None  # 由 make_server 注入

    def log_message(self, fmt, *args):  # 安静：审计在服务层
        pass

    # ------------------------------------------------------------ 输出
    def _json(self, obj, status: int = 200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False, sort_keys=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, e: DomainError):
        self._json({"error": e.code, "message": e.message, "detail": e.detail},
                   e.http_status)

    def _actor(self) -> str:
        return self.headers.get("X-Person-Id", "")

    def _op(self):
        return self.headers.get("X-Op-Id") or None

    # ------------------------------------------------------------ 路由
    def do_GET(self):
        try:
            path = urlparse(self.path).path
            q = parse_qs(urlparse(self.path).query)
            svc = self.svc
            if path == "/api/health":
                return self._json({"ok": True})
            if path == "/api/people":
                return self._json(svc.list_people())
            if path == "/api/artifacts":
                return self._json(svc.list_artifacts())
            if path == "/api/releases":
                return self._json(svc.list_releases())
            if path == "/api/sets":
                return self._json(svc.list_sets(q.get("lineage", [None])[0]))
            if path == "/api/tools":
                return self._json(svc.list_tools())
            if path == "/api/windows":
                return self._json(svc.list_windows(
                    q.get("tool", [None])[0], q.get("set", [None])[0],
                    q.get("state", [None])[0]))
            if path == "/api/lots":
                return self._json(svc.list_lots())
            if path == "/api/replacements":
                return self._json(svc.list_replacements(q.get("status", [None])[0]))
            if path == "/api/rework-plans":
                return self._json(svc.list_rework_plans())
            if path == "/api/packages":
                return self._json(svc.list_packages())
            if path == "/api/quarantine":
                return self._json(svc.list_quarantine(q.get("status", [None])[0]))
            if path == "/api/arbitrations":
                rows = self.svc.s.q_all(
                    "SELECT * FROM arbitration ORDER BY decided_at DESC LIMIT 200")
                return self._json([dict(r) for r in rows])
            if path == "/api/audit":
                limit = int(q.get("limit", ["200"])[0])
                return self._json(svc.list_audit(
                    limit=limit, target=q.get("target", [None])[0],
                    op_id=q.get("op", [None])[0]))
            if path.startswith("/api/artifacts/"):
                key = path.rsplit("/", 1)[1]
                if q.get("name"):
                    return self._json(svc.artifact_relations(name=key))
                return self._json(svc.artifact_relations(sha=key))
            if path.startswith("/api/releases/"):
                return self._json(svc.get_release(path.rsplit("/", 1)[1]))
            if path.startswith("/api/sets/"):
                return self._json(svc.get_set(path.rsplit("/", 1)[1]))
            if path.startswith("/api/packages/") and path.endswith("/download"):
                pkg_id = path.split("/")[3]
                p, row = svc.get_package_file(pkg_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-tar")
                self.send_header("Content-Length", str(p.stat().st_size))
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{row["set_id"]}.tar"')
                self.send_header("X-Package-Sha256", row["sha256"])
                self.end_headers()
                with open(p, "rb") as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                return
            if path.startswith("/api/packages/"):
                rows = svc.s.q_all(
                    "SELECT * FROM package WHERE id=? ORDER BY created_at DESC LIMIT 1",
                    (path.rsplit("/", 1)[1],))
                if not rows:
                    raise DomainError("NOT_FOUND", "交付包不存在", 404)
                return self._json(dict(rows[0]))
            # 静态界面
            return self._serve_static(path)
        except DomainError as e:
            return self._error(e)
        except Exception as ex:  # pragma: no cover
            return self._json({"error": "INTERNAL", "message": str(ex)}, 500)

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            svc, body = self.svc, None
            actor, op = self._actor(), self._op()

            if path == "/api/content":
                # 原始字节上传：X-Logical-Name / X-Kind / X-Sha256
                n = int(self.headers.get("Content-Length", "0") or 0)
                data = self.rfile.read(n)
                return self._json(svc.put_content(
                    actor, self.headers["X-Logical-Name"],
                    self.headers.get("X-Kind", "OTHER"), data,
                    self.headers.get("X-Sha256")))

            body = _read_json(self)

            if path == "/api/people":
                return self._json(svc.create_person(
                    actor, body["id"], body["name"], body.get("roles", [])), 201)
            if path == "/api/imports":
                return self._json(svc.import_release(body["packet"] if "packet" in body
                                                     else body, actor), 201)
            if path == "/api/demo-packet":
                return self._json(svc.make_demo_packet(
                    actor, body.get("suffix", "")), 201)
            if path == "/api/tools":
                return self._json(svc.create_tool(actor, body["name"]), 201)
            if path == "/api/lots":
                return self._json(svc.create_lot(actor, body["display_name"]), 201)
            if path == "/api/windows":
                return self._json(svc.reserve_window(
                    actor, body["tool_id"], body["set"], body["mask"],
                    body["start_ts"], body["end_ts"], body.get("lot_id"), op), 201)
            if path.startswith("/api/windows/") and path.endswith("/cancel"):
                wid = path.split("/")[3]
                return self._json(svc.cancel_window(actor, wid, op))
            if path.startswith("/api/windows/") and path.endswith("/expose"):
                wid = path.split("/")[3]
                return self._json(svc.expose(actor, wid, op))
            if path.startswith("/api/lots/") and path.endswith("/bind"):
                lot_id = path.split("/")[3]
                return self._json(svc.bind_lot(actor, lot_id, body["set"], op))
            if path == "/api/replacements":
                return self._json(svc.request_replacement(
                    actor, body["set"], body["mask"], body["new_sha"],
                    body.get("reason", ""), op), 201)
            if path.startswith("/api/replacements/") and path.endswith("/approve"):
                rid = path.split("/")[3]
                return self._json(svc.approve_replacement(actor, rid, op))
            if path.startswith("/api/replacements/") and path.endswith("/reject"):
                rid = path.split("/")[3]
                return self._json(svc.reject_replacement(actor, rid, op))
            if path == "/api/deltas":
                return self._json(svc.create_delta(
                    actor, body["set"], body["changes"],
                    body.get("note", ""), op), 201)
            if path == "/api/rework-plans":
                return self._json(svc.create_rework_plan(
                    actor, body["lot_id"], body["delta"],
                    body.get("note", ""), op), 201)
            if path == "/api/packages":
                return self._json(svc.build_package(actor, body["set"], op), 201)
            if path.startswith("/api/quarantine/") and path.endswith("/resolve"):
                qid = path.split("/")[3]
                return self._json(svc.resolve_quarantine(
                    actor, qid, body["decision"], body.get("new_name")))
            raise DomainError("NOT_FOUND", f"未知接口：POST {path}", 404)
        except DomainError as e:
            return self._error(e)
        except KeyError as e:
            return self._json({"error": "BAD_REQUEST",
                               "message": f"缺少必填字段：{e.args[0]}"}, 400)
        except Exception as ex:  # pragma: no cover
            return self._json({"error": "INTERNAL", "message": str(ex)}, 500)

    # ------------------------------------------------------------ 静态
    def _serve_static(self, path):
        if path in ("/", "/index.html"):
            path = "/index.html"
        target = (WEB_DIR / path.lstrip("/")).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.is_file():
            raise DomainError("NOT_FOUND", path, 404)
        ctype = {".html": "text/html; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8"}.get(target.suffix,
                                                        "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(host: str, port: int, store: Store) -> ThreadingHTTPServer:
    svc = Service(store)

    class _Handler(ApiHandler):
        pass

    _Handler.svc = svc
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.service = svc  # type: ignore[attr-defined]
    httpd.store = store  # type: ignore[attr-defined]
    return httpd
