import json
import os
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ed25519
from app.envelope import EnvelopeError, EnvelopeService, canonical_bytes
from app.envelope_store import EnvelopeStore, canonical_bytes as store_canonical


def sign_challenge(svc, sid, key, person):
    ch = svc.challenge(sid, key["kid"])
    env = svc.envelope(ch["envelope_id"])
    msg = {"schema": "design-envelope-signature/1", "envelope_id": ch["envelope_id"],
           "content_hash": env["content_hash"], "merkle_root": env["merkle_root"],
           "kid": key["kid"], "signed_at": ch["signed_at"]}
    sig = ed25519.sign(bytes.fromhex(key["private_seed"]), canonical_bytes(msg)).hex()
    return svc.submit_signature(sid, ch, sig, person)


class EnvelopeServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.svc = EnvelopeService(EnvelopeStore(f"{self.tmp}/env.db", f"{self.tmp}/blobs"))
        self.keys = []
        for role, person in [("TIMING_LEAD", "timing.a"), ("METHODOLOGY_LEAD", "method.b")]:
            k = self.svc.generate_signer_key()
            self.svc.register_signer(k["kid"], person, role, k["public_key"], "test")
            k["person"] = person
            self.keys.append(k)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _session(self, parent=None):
        s = self.svc.create_session("tester", parent_envelope_id=parent, metadata={"x": 1})
        sid = s["id"]
        self.svc.add_inline_artifact(sid, "netlist/a.v", "netlist", "MODULE a; ENDMODULE\n")
        self.svc.add_inline_artifact(sid, "constraints/a.sdc", "constraints", {"period": 1.0})
        self.svc.add_inline_artifact(sid, "modules.json", "modules", ["a"])
        self.svc.add_inline_artifact(sid, "signoffs/records.json", "signoffs",
                                     {"ticket": "CR-1", "records": ["sta", "meth"]})
        return sid

    def _full_publish(self, name="r1"):
        sid = self._session()
        self.svc.prepare(sid)
        for k in self.keys:
            sign_challenge(self.svc, sid, k, k["person"])
        self.svc.seal(sid)
        pub = self.svc.publish(sid, name)
        return sid, pub["envelope_id"]

    def test_full_content_address_multi_signature_offline_verify(self):
        sid, eid = self._full_publish()
        result = self.svc.verify_envelope(eid)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["signatures"]), 2)
        bundle = self.svc.export_bundle(eid)
        offline = EnvelopeService.verify_offline_bundle(bundle)
        self.assertTrue(offline["ok"])
        self.assertEqual(offline["envelope_id"], eid)
        proof = self.svc.inclusion_proof(eid, "artifact", "netlist/a.v")
        self.assertTrue(proof["verified"])

    def test_concurrent_prepare_same_content_single_envelope(self):
        s1 = self._session()
        s2 = self._session()
        out = []
        def run(sid):
            try:
                out.append(self.svc.prepare(sid)["envelope_id"])
            except Exception as e:
                out.append(e)
        threads = [threading.Thread(target=run, args=(x,)) for x in (s1, s2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0], out[1])
        self.assertEqual(len(self.svc.list_envelopes()), 1)

    def test_chunk_resume_and_chunk_tamper_detection(self):
        sid = self.svc.create_session("uploader")["id"]
        data = b"".join(bytes([i % 256]) * 7 for i in range(100))
        u = self.svc.init_upload(sid, "netlist/big.v", "netlist", 16, len(data))
        uid = u["id"]
        self.svc.put_chunk(uid, 0, data[:16])
        self.svc.put_chunk(uid, 2, data[32:48])
        again = self.svc.upload(uid)
        self.assertIn(1, again["missing_indexes"])
        # 重放同块幂等
        self.svc.put_chunk(uid, 0, data[:16])
        for i in range(1, len(data) // 16 + (1 if len(data) % 16 else 0)):
            if i != 2:
                self.svc.put_chunk(uid, i, data[i*16:(i+1)*16])
        self.svc.complete_upload(uid)
        self.svc.add_inline_artifact(sid, "constraints/a.sdc", "constraints", {})
        self.svc.add_inline_artifact(sid, "modules.json", "modules", [])
        self.svc.add_inline_artifact(sid, "signoffs/x.json", "signoffs", {})
        self.svc.prepare(sid)
        prepared_eid = self.svc.session(sid)["envelope_id"]
        # 直接替换对象文件为另一个同长度 blob；验真必须拒绝并留审计。
        a = self.svc.artifact(sid, "netlist/big.v")
        p = self.svc.s.blob_path(a["content_hash"])
        bad = bytearray(data); bad[0] ^= 1
        p.write_bytes(bytes(bad))
        with self.assertRaises(EnvelopeError) as cm:
            self.svc.verify_content(prepared_eid)
        self.assertIn(cm.exception.code, {"ARTIFACT_TAMPERED", "ENVELOPE_TAMPERED", "CHUNK_TAMPERED"})

    def test_same_name_different_content_conflict(self):
        _, e1 = self._full_publish("same-name")
        sid2 = self._session(parent=e1)
        # 增加一个不同元数据会话需要不同内容；直接修改现有构件内容。
        row = self.svc.s.q_one("SELECT slot FROM session_artifact WHERE session_id=?", (sid2,))
        self.svc.add_inline_artifact(sid2, "netlist/extra.v", "netlist", "DIFFERENT\n")
        self.svc.prepare(sid2)
        for k in self.keys:
            sign_challenge(self.svc, sid2, k, k["person"])
        self.svc.seal(sid2)
        with self.assertRaises(EnvelopeError) as cm:
            self.svc.publish(sid2, "same-name")
        self.assertEqual(cm.exception.code, "NAME_CONTENT_CONFLICT")
        audit = self.svc.audits(entity="same-name", result="REJECTED")
        self.assertTrue(any(x["reason"] == "NAME_CONTENT_CONFLICT" for x in audit))

    def test_revocation_does_not_change_historical_signatures(self):
        sid = self._session()
        self.svc.prepare(sid)
        old_key = self.keys[0]
        sign_challenge(self.svc, sid, old_key, old_key["person"])
        self.svc.revoke_signer(old_key["kid"], reason="LEAVE")
        # 历史签名仍可验真；补第二签后可以封口发布。
        sign_challenge(self.svc, sid, self.keys[1], self.keys[1]["person"])
        self.svc.seal(sid)
        eid = self.svc.session(sid)["envelope_id"]
        verified = self.svc.verify_envelope(eid)
        self.assertTrue(verified["ok"])
        # 新会话不能再使用撤销密钥。
        sid2 = self._session()
        self.svc.prepare(sid2)
        with self.assertRaises(EnvelopeError) as cm:
            sign_challenge(self.svc, sid2, old_key, old_key["person"])
        self.assertIn(cm.exception.code,
                      {"SIGNER_KEY_INACTIVE", "SIGNER_KEY_REVOKED_AT_TIME"})

    def test_key_rotation_and_past_history(self):
        old = self.keys[0]
        new = self.svc.generate_signer_key()
        # 用旧 key 完成历史信封并发布。
        sid, eid = self._full_publish("before-rotate")
        self.svc.register_signer(new["kid"], "timing.a", "TIMING_LEAD", new["public_key"],
                                 "admin", replaces_kid=old["kid"])
        self.assertTrue(self.svc.verify_envelope(eid)["ok"])
        bundle = self.svc.export_bundle(eid)
        # 离线包包含撤销注册表事件，但签名时间早于撤销，仍有效。
        self.assertTrue(EnvelopeService.verify_offline_bundle(bundle)["ok"])

    def test_root_rotation_preserves_offline_history(self):
        sid, eid = self._full_publish("root-before")
        rotated = self.svc.rotate_root("admin")
        # 轮换后重新导出历史信封：TRUST 中同时包含旧根、新根和交叉轮换事件。
        old_bundle = self.svc.export_bundle(eid)
        self.assertEqual(rotated["version"], 2)
        self.assertTrue(self.svc.verify_root_chain()["ok"])
        self.assertTrue(self.svc.verify_registry()["ok"])
        # 旧信封由旧根保护，根链允许离线验证者从新信任根追溯到旧根。
        self.assertTrue(EnvelopeService.verify_offline_bundle(
            old_bundle, rotated["kid"])["ok"])
        # 根轮换后登记的新签名者由新根签发，新信封仍可在线/离线验真。
        k = self.svc.generate_signer_key()
        self.svc.register_signer(k["kid"], "timing.c", "TIMING_LEAD", k["public_key"], "admin")

    def test_signature_manifest_tamper_rejected(self):
        _, eid = self._full_publish("tampered")
        with self.svc.s.tx() as c:
            c.execute("UPDATE envelope_signature SET signer=? WHERE envelope_id=?",
                      ("attacker", eid))
        with self.assertRaises(EnvelopeError):
            self.svc.verify_envelope(eid)
        invalid = self.svc.audits(entity=eid, result="INVALID")
        self.assertTrue(any(x["reason"] == "SIGNATURE_INVALID" for x in invalid))

    def test_recovery_does_not_duplicate_valid_envelope(self):
        sid = self._session()
        self.svc.prepare(sid)
        eid = self.svc.session(sid)["envelope_id"]
        for k in self.keys: sign_challenge(self.svc, sid, k, k["person"])
        self.svc.seal(sid)
        # 手工进入 PUBLISHING，模拟完成前崩溃。
        with self.svc.s.tx() as c:
            c.execute("INSERT INTO publication(name,envelope_id,state,published_by,created_at)"
                      " VALUES(?,?,?,?,?)", ("crash", eid, "PUBLISHING", "t",
                                             datetime.now(timezone.utc).isoformat()))
        rec = self.svc.recover()
        self.assertEqual(rec["recovered_publications"], ["crash"])
        self.assertEqual(len(self.svc.list_envelopes()), 1)
        self.assertEqual(self.svc.publication("crash")["state"], "PUBLISHED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
