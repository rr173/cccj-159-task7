"""设计签名封装服务的独立 HTTP/REST 服务。"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .envelope import EnvelopeError, EnvelopeService
from .envelope_store import EnvelopeStore

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
_MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8"}


def _make_handler(svc: EnvelopeService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DesignEnvelope/1.0"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, payload, ctype="application/json", filename=None):
            body = payload if isinstance(payload, bytes) else json.dumps(
                payload, ensure_ascii=False, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise EnvelopeError("BAD_JSON", "请求体不是合法 JSON", 400)

        def _raw_body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _q(self, name, default=None, cast=str):
            qs = parse_qs(urlparse(self.path).query)
            return cast(qs[name][0]) if name in qs else default

        def _static(self, rel):
            p = (WEB_DIR / rel).resolve()
            if not str(p).startswith(str(WEB_DIR.resolve())) or not p.is_file():
                self._send(404, {"error": "NOT_FOUND", "message": rel})
                return
            self._send(200, p.read_bytes(), _MIME.get(p.suffix, "application/octet-stream"))

        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                if path == "/envelopes":
                    return self._static("envelopes.html")
                if path == "/static/envelopes.js":
                    return self._static("envelopes.js")
                if path == "/api/envelope/health":
                    return self._send(200, {"ok": True, "service": "design-envelope"})
                if path == "/api/envelope/root":
                    r = svc.s.active_root()
                    return self._send(200, {k: r[k] for k in
                                            ("kid", "version", "public_key", "status",
                                             "created_at", "activated_at")})
                if path == "/api/envelope/signers":
                    rows = svc.s.q_all(
                        "SELECT a.* FROM signer_key_event a JOIN ("
                        "SELECT kid,MAX(seq) m FROM signer_key_event GROUP BY kid) b "
                        "ON a.kid=b.kid AND a.seq=b.m ORDER BY a.at")
                    return self._send(200, {"signers": [dict(r) for r in rows]})
                if path == "/api/envelope/sessions":
                    return self._send(200, {"sessions": svc.list_sessions()})
                if path == "/api/envelope/envelopes":
                    return self._send(200, {"envelopes": svc.list_envelopes()})
                if path == "/api/envelope/publications":
                    return self._send(200, {"publications": svc.list_publications()})
                if path == "/api/envelope/audit":
                    return self._send(200, {"audit": svc.audits(
                        limit=self._q("limit", 200, int), entity=self._q("entity"),
                        result=self._q("result"))})

                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)", path)
                if m:
                    return self._send(200, svc.session(m.group(1)))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/uploads/([^/]+)", path)
                if m:
                    return self._send(200, svc.upload(m.group(2)))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/challenge/([^/]+)", path)
                if m:
                    return self._send(200, svc.challenge(m.group(1), m.group(2)))
                m = re.fullmatch(r"/api/envelope/envelopes/([^/]+)", path)
                if m:
                    eid = m.group(1)
                    d = svc.envelope(eid)
                    d["manifest"] = svc.manifest(eid)
                    d["signatures"] = svc.signatures(eid)
                    d["publications"] = [r["name"] for r in svc.s.q_all(
                        "SELECT name FROM publication WHERE envelope_id=? AND state='PUBLISHED'",
                        (eid,))]
                    return self._send(200, d)
                m = re.fullmatch(r"/api/envelope/envelopes/([^/]+)/proofs", path)
                if m:
                    return self._send(200, svc.proofs(m.group(1)))
                m = re.fullmatch(r"/api/envelope/envelopes/([^/]+)/verify", path)
                if m:
                    return self._send(200, svc.verify_envelope(
                        m.group(1), self._q("trusted_root_kid")))
                m = re.fullmatch(r"/api/envelope/envelopes/([^/]+)/bundle", path)
                if m:
                    eid = m.group(1)
                    return self._send(200, svc.export_bundle(eid), "application/zip",
                                      f"envelope-{eid[:12]}.zip")
                m = re.fullmatch(r"/api/envelope/lineage", path)
                if m:
                    return self._send(200, svc.lineage(self._q("name"), self._q("envelope_id")))
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except EnvelopeError as e:
                self._send(e.http_status, {"error": e.code, "message": e.message,
                                           "detail": e.extra})

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                # 原始分块上传在解析 JSON 前处理。
                m = re.fullmatch(r"/api/envelope/uploads/([^/]+)/chunks/(\d+)", path)
                if m:
                    uid, idx = m.group(1), int(m.group(2))
                    return self._send(200, svc.put_chunk(
                        uid, idx, self._raw_body(),
                        self.headers.get("X-Chunk-Hash"),
                        self.headers.get("X-Uploaded-By", "api")))

                b = self._json_body()
                by = b.get("by", "api")
                if path == "/api/envelope/keys/generate":
                    return self._send(201, svc.generate_signer_key())
                if path == "/api/envelope/signers":
                    d = svc.register_signer(b["kid"], b["signer"], b["role"], b["public_key"],
                                            by, b.get("replaces_kid"))
                    return self._send(201, d)
                if path == "/api/envelope/root/rotate":
                    return self._send(201, svc.rotate_root(by))
                if path == "/api/envelope/sessions":
                    d = svc.create_session(by, b.get("required_roles"),
                                           b.get("parent_envelope_id"), b.get("metadata"),
                                           b.get("session_id"))
                    return self._send(201, d)
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/artifacts", path)
                if m:
                    d = svc.add_inline_artifact(m.group(1), b["slot"], b["kind"], b["content"],
                                                b.get("detail"), by)
                    return self._send(201, d)
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/uploads", path)
                if m:
                    d = svc.init_upload(m.group(1), b["slot"], b["kind"], b["chunk_size"],
                                        b["total_size"], b.get("detail"), by)
                    return self._send(201, d)
                m = re.fullmatch(r"/api/envelope/uploads/([^/]+)/chunks", path)
                if m:
                    d = svc.put_chunk(m.group(1), int(b["index"]), bytes.fromhex(b["data_hex"]),
                                      b.get("chunk_hash"), by)
                    return self._send(200, d)
                m = re.fullmatch(r"/api/envelope/uploads/([^/]+)/complete", path)
                if m:
                    return self._send(200, svc.complete_upload(m.group(1), by))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/prepare", path)
                if m:
                    return self._send(200, svc.prepare(m.group(1), by))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/signatures", path)
                if m:
                    return self._send(200, svc.submit_signature(
                        m.group(1), b["signed_payload"], b["signature"], by))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/seal", path)
                if m:
                    return self._send(200, svc.seal(m.group(1), by))
                m = re.fullmatch(r"/api/envelope/sessions/([^/]+)/publish", path)
                if m:
                    return self._send(200, svc.publish(m.group(1), b["name"], by))
                m = re.fullmatch(r"/api/envelope/signers/([^/]+)/revoke", path)
                if m:
                    return self._send(200, svc.revoke_signer(
                        m.group(1), by, b.get("reason", "REVOKED")))
                if path == "/api/envelope/verify-offline":
                    return self._send(200, svc.verify_offline_bundle(
                        bytes.fromhex(b["bundle_hex"]), b.get("trusted_root_kid")))
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except KeyError as e:
                self._send(400, {"error": "BAD_REQUEST", "message": f"缺少字段: {e}",
                                 "detail": {}})
            except EnvelopeError as e:
                self._send(e.http_status, {"error": e.code, "message": e.message,
                                           "detail": e.extra})

    return Handler


def serve(db_path="data/envelope.db", port=8090, blob_dir=None):
    store = EnvelopeStore(db_path, blob_dir=blob_dir)
    svc = EnvelopeService(store)
    rec = svc.recover()
    httpd = ThreadingHTTPServer(("0.0.0.0", port), _make_handler(svc))
    print(f"设计签名封装服务已启动: http://localhost:{port}/envelopes  (db={db_path})")
    print(f"恢复原子发布: {len(rec['recovered_publications'])} 个")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/envelope.db")
    ap.add_argument("--blob-dir", default=None)
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()
    serve(args.db, args.port, args.blob_dir)
