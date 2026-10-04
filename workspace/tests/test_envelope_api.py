import json
import socket
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ed25519
from app.envelope import EnvelopeService, canonical_bytes
from app.envelope_api import _make_handler
from app.envelope_store import EnvelopeStore


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class EnvelopeApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        store = EnvelopeStore(f"{cls.tmp}/env.db", f"{cls.tmp}/blobs")
        cls.svc = EnvelopeService(store)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", free_port()), _make_handler(cls.svc))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, method="GET", body=None, raw=False, data=None, headers=None):
        payload = data
        headers = headers or {}
        if body is not None:
            payload = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        req = Request(self.base + path, data=payload, method=method, headers=headers)
        try:
            with urlopen(req, timeout=5) as r:
                data = r.read()
                if raw:
                    return r.status, data
                return r.status, json.loads(data)
        except HTTPError as e:
            out = e.read()
            return e.code, out if raw else json.loads(out)

    def test_full_envelope_flow_via_http(self):
        keys = []
        for role, person in [("TIMING_LEAD", "timing.a"), ("METHODOLOGY_LEAD", "method.b")]:
            s, k = self.call("/api/envelope/keys/generate", "POST", {})
            self.assertEqual(s, 201)
            s, _ = self.call("/api/envelope/signers", "POST", {
                "kid": k["kid"], "signer": person, "role": role,
                "public_key": k["public_key"], "by": "admin"})
            self.assertEqual(s, 201)
            k.update(role=role, person=person)
            keys.append(k)

        s, session = self.call("/api/envelope/sessions", "POST", {"by": "http", "metadata": {"x": 1}})
        self.assertEqual(s, 201)
        sid = session["id"]
        artifacts = [
            ("netlist/core.v", "netlist", "MODULE core; ENDMODULE\n"),
            ("constraints/top.sdc", "constraints", {"period": 1.0}),
            ("modules.json", "modules", ["core"]),
            ("signoffs/record.json", "signoffs", {"records": ["timing", "method"]}),
        ]
        for slot, kind, content in artifacts:
            s, _ = self.call(f"/api/envelope/sessions/{sid}/artifacts", "POST",
                             {"slot": slot, "kind": kind, "content": content, "by": "http"})
            self.assertEqual(s, 201)
        s, prepared = self.call(f"/api/envelope/sessions/{sid}/prepare", "POST", {"by": "http"})
        self.assertEqual(s, 200)
        eid = prepared["envelope_id"]

        for k in keys:
            s, ch = self.call(f"/api/envelope/sessions/{sid}/challenge/{k['kid']}")
            self.assertEqual(s, 200)
            s, env = self.call(f"/api/envelope/envelopes/{eid}")
            msg = {"schema": "design-envelope-signature/1", "envelope_id": eid,
                   "content_hash": env["content_hash"], "merkle_root": env["merkle_root"],
                   "kid": k["kid"], "signed_at": ch["signed_at"]}
            sig = ed25519.sign(bytes.fromhex(k["private_seed"]), canonical_bytes(msg)).hex()
            s, _ = self.call(f"/api/envelope/sessions/{sid}/signatures", "POST",
                             {"signed_payload": ch, "signature": sig, "by": k["person"]})
            self.assertEqual(s, 200)
        s, sealed = self.call(f"/api/envelope/sessions/{sid}/seal", "POST", {"by": "http"})
        self.assertEqual(sealed["state"], "SEALED")
        s, pub = self.call(f"/api/envelope/sessions/{sid}/publish", "POST",
                           {"name": "http-release", "by": "http"})
        self.assertEqual(s, 200)
        self.assertEqual(pub["state"], "PUBLISHED")
        s, verified = self.call(f"/api/envelope/envelopes/{eid}/verify")
        self.assertEqual(s, 200)
        self.assertTrue(verified["ok"])
        s, lineage = self.call(f"/api/envelope/lineage?name=http-release")
        self.assertEqual(lineage["chain"][-1]["envelope_id"], eid)
        s, bundle = self.call(f"/api/envelope/envelopes/{eid}/bundle", raw=True)
        self.assertEqual(s, 200)
        self.assertTrue(EnvelopeService.verify_offline_bundle(bundle)["ok"])

    def test_chunk_upload_resume_and_static_page(self):
        s, session = self.call("/api/envelope/sessions", "POST", {"by": "uploader"})
        sid = session["id"]
        payload = b"0123456789abcdef" * 4
        s, u = self.call(f"/api/envelope/sessions/{sid}/uploads", "POST", {
            "slot": "netlist/chunked.v", "kind": "netlist", "chunk_size": 16,
            "total_size": len(payload), "by": "uploader"})
        self.assertEqual(s, 201)
        uid = u["id"]
        s, _ = self.call(f"/api/envelope/uploads/{uid}/chunks/0", "POST",
                         data=payload[:16], headers={"X-Uploaded-By": "uploader"})
        self.assertEqual(s, 200)
        s, _ = self.call(f"/api/envelope/uploads/{uid}/chunks/3", "POST",
                         data=payload[48:], headers={"X-Uploaded-By": "uploader"})
        self.assertEqual(s, 200)
        s, state = self.call(f"/api/envelope/sessions/{sid}/uploads/{uid}")
        self.assertEqual(state["missing_indexes"], [1, 2])
        for i in (1, 2):
            self.call(f"/api/envelope/uploads/{uid}/chunks/{i}", "POST",
                      data=payload[i * 16:(i + 1) * 16])
        s, done = self.call(f"/api/envelope/uploads/{uid}/complete", "POST", {"by": "uploader"})
        self.assertEqual(s, 200)
        self.assertEqual(done["state"], "READY")
        s, html = self.call("/envelopes", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("设计签名".encode(), html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
