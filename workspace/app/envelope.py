"""设计签名发布信封领域服务。

不变量：
- 信封 ID 仅由规范化后的网表/约束/模块清单/签核记录及父版本决定。
- 分块、完整对象、签名、签名者注册表均有摘要和可验证包含证明。
- 发布以 PUBLISHING 日志先行，崩溃恢复幂等；同名不同内容确定性拒绝。
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import ed25519
from .envelope_store import EnvelopeStore, canonical_bytes, utcnow

ARTIFACT_KINDS = {"netlist", "constraints", "modules", "signoffs"}
DEFAULT_ROLES = ["TIMING_LEAD", "METHODOLOGY_LEAD"]
CHALLENGE_TOLERANCE_SECONDS = 300


class EnvelopeError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 409, extra=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.extra = extra or {}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_ts(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def json_bytes(obj) -> bytes:
    return canonical_bytes(obj)


def chunk_hashes(data: bytes, chunk_size: int) -> list[str]:
    if chunk_size <= 0:
        raise EnvelopeError("BAD_REQUEST", "chunk_size 必须为正整数", 400)
    return [sha256_hex(data[i:i + chunk_size])
            for i in range(0, len(data), chunk_size)] or [sha256_hex(b"")]


def leaf_hash(leaf_type: str, subject: str, digest: str, extra: dict | None = None) -> str:
    obj = {"type": leaf_type, "subject": subject, "sha256": digest}
    if extra:
        obj.update(extra)
    return sha256_hex(json_bytes(obj))


def _h_pair(left: str, right: str) -> str:
    return sha256_hex(b"node:" + bytes.fromhex(left) + bytes.fromhex(right))


def _h_promote(node: str) -> str:
    return sha256_hex(b"node:" + bytes.fromhex(node))


def _build_tree(leaves: list[str]):
    """构造“只能相同子树大小配对”的规范 Merkle 树。

    奇数尾节点原样提升（promote），不会与尺寸不同的兄弟拼接，从而避免
    10/11 等长度下证明路径出现二义性。
    """
    levels = [{"nodes": [{"hash": h, "size": 1, "start": i}
                        for i, h in enumerate(leaves)]}]
    while len(levels[-1]["nodes"]) > 1:
        cur, nxt = levels[-1]["nodes"], []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur) and cur[i]["size"] == cur[i + 1]["size"]:
                nxt.append({"hash": _h_pair(cur[i]["hash"], cur[i + 1]["hash"]),
                            "size": cur[i]["size"] * 2, "start": cur[i]["start"]})
            else:
                nxt.append({"hash": _h_promote(cur[i]["hash"]),
                            "size": cur[i]["size"], "start": cur[i]["start"]})
        levels.append({"nodes": nxt})
    return levels


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_hex(b"empty-merkle")
    return _build_tree(leaves)[-1]["nodes"][0]["hash"]


def merkle_proof(leaves: list[str], index: int) -> dict:
    if not 0 <= index < len(leaves):
        raise EnvelopeError("LEAF_NOT_FOUND", "Merkle 叶子不存在", 404)
    target = leaves[index]
    levels = _build_tree(leaves)
    path = []
    start, size = index, 1
    cur = target
    for level in levels[:-1]:
        nodes = level["nodes"]
        pos = next(i for i, n in enumerate(nodes) if n["start"] == start and n["size"] == size)
        if pos % 2 == 1:
            sib = nodes[pos - 1]
            path.append({"position": "left", "hash": sib["hash"]})
            cur = _h_pair(sib["hash"], cur)
            start, size = sib["start"], size * 2
        elif pos + 1 < len(nodes) and nodes[pos + 1]["size"] == size:
            sib = nodes[pos + 1]
            path.append({"position": "right", "hash": sib["hash"]})
            cur = _h_pair(cur, sib["hash"])
            size *= 2
        else:
            path.append({"position": "promote"})
            cur = _h_promote(cur)
    return {"leaf_index": index, "leaf_hash": target, "path": path, "root": cur}


def verify_proof(proof: dict) -> bool:
    cur = proof.get("leaf_hash", "")
    try:
        for step in proof.get("path", []):
            if step["position"] == "left":
                cur = _h_pair(step["hash"], cur)
            elif step["position"] == "right":
                cur = _h_pair(cur, step["hash"])
            elif step["position"] == "promote":
                cur = _h_promote(cur)
            else:
                return False
        return cur == proof.get("root")
    except Exception:
        return False


def safe_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_").replace("..", "_")


def artifact_bundle_name(descriptor: dict) -> str:
    # position 已参与内容哈希；导出名再带 position，避免 a/b 与 a_b 两类槽位碰撞。
    return f"{descriptor['position']:04d}-{safe_name(descriptor['slot'])}"


class EnvelopeService:
    def __init__(self, store: EnvelopeStore):
        self.s = store

    def _audit(self, *args, **kwargs):
        self.s.audit(*args, **kwargs)

    def _row(self, sql, args=(), code="NOT_FOUND", message="对象不存在", status=404):
        row = self.s.q_one(sql, args)
        if not row:
            raise EnvelopeError(code, message, status)
        return row

    # ------------------------------------------------------------------ 密钥
    def generate_signer_key(self) -> dict:
        seed = secrets.token_bytes(32)
        pub = ed25519.public_key(seed)
        kid = "signer-" + sha256_hex(pub)[:16]
        return {"kid": kid, "public_key": pub.hex(), "private_seed": seed.hex(),
                "warning": "private_seed 仅本次返回；请离线保存"}

    def _active_root_seed(self):
        root = self.s.active_root()
        if not root or not root["private_seed"]:
            raise EnvelopeError("ROOT_UNAVAILABLE", "当前数据库不持有根私钥，无法签发注册表", 503)
        return root

    def _root_sign(self, event: dict):
        root = self._active_root_seed()
        return root["kid"], ed25519.sign(bytes.fromhex(root["private_seed"]),
                                         json_bytes(event)).hex()

    @staticmethod
    def _registry_event(kid, event, signer, role, public_key, at, detail=None):
        return {
            "schema": "design-signer-registry/1", "kid": kid, "event": event,
            "signer": signer, "role": role, "public_key": public_key, "at": at,
            "detail": detail or {},
        }

    def register_signer(self, kid: str, signer: str, role: str, public_key: str,
                        by: str = "admin", replaces_kid: str | None = None):
        self._valid_pubkey(public_key)
        if not signer or not role:
            raise EnvelopeError("BAD_REQUEST", "signer/role 不能为空", 400)
        now = utcnow()
        detail = {"replaces_kid": replaces_kid} if replaces_kid else {}
        event = self._registry_event(kid, "REGISTER", signer, role, public_key, now, detail)
        root_kid, sig = self._root_sign(event)
        events = [(kid, "REGISTER", signer, role, public_key, now, root_kid, sig, detail)]
        if replaces_kid:
            latest = self.latest_key_event(replaces_kid)
            if not latest or latest["event"] == "REVOKED":
                raise EnvelopeError("SIGNER_KEY_NOT_FOUND", "被轮换密钥不存在或已撤销", 404)
            rev_event = self._registry_event(
                replaces_kid, "REVOKE", latest["signer"], latest["role"],
                latest["public_key"], now, {"reason": "KEY_ROTATED", "replaced_by": kid})
            rk, rsig = self._root_sign(rev_event)
            events.append((replaces_kid, "REVOKE", latest["signer"], latest["role"],
                           latest["public_key"], now, rk, rsig, rev_event["detail"]))
        with self.s.tx() as c:
            for e in events:
                args = (e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],
                        json.dumps(e[8], ensure_ascii=False, sort_keys=True))
                c.execute(
                    "INSERT INTO signer_key_event(kid,event,signer,role,public_key,at,"
                    "root_kid,signature,detail_json) VALUES(?,?,?,?,?,?,?,?,?)", args)
        self._audit("signer.register", kid, by, detail={"role": role, "signer": signer})
        return {"kid": kid, "signer": signer, "role": role, "public_key": public_key,
                "registered_at": now, "replaces_kid": replaces_kid}

    def revoke_signer(self, kid: str, by: str = "admin", reason: str = "REVOKED"):
        latest = self.latest_key_event(kid)
        if not latest:
            raise EnvelopeError("SIGNER_KEY_NOT_FOUND", "签名者密钥不存在", 404)
        if latest["event"] == "REVOKED":
            return {"kid": kid, "deduped": True, "revoked_at": latest["at"]}
        now = utcnow()
        detail = {"reason": reason}
        event = self._registry_event(kid, "REVOKE", latest["signer"], latest["role"],
                                     latest["public_key"], now, detail)
        root_kid, sig = self._root_sign(event)
        with self.s.tx() as c:
            c.execute(
                "INSERT INTO signer_key_event(kid,event,signer,role,public_key,at,"
                "root_kid,signature,detail_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (kid, "REVOKE", latest["signer"], latest["role"], latest["public_key"],
                 now, root_kid, sig, json.dumps(detail, sort_keys=True)))
        self._audit("signer.revoke", kid, by, reason=reason)
        return {"kid": kid, "revoked_at": now}

    @staticmethod
    def _valid_pubkey(public_key: str):
        try:
            raw = bytes.fromhex(public_key)
            if len(raw) != 32:
                raise ValueError
        except Exception:
            raise EnvelopeError("BAD_PUBLIC_KEY", "公钥必须是 32 字节 Ed25519 hex", 400)

    def latest_key_event(self, kid: str):
        return self.s.q_one(
            "SELECT * FROM signer_key_event WHERE kid=? ORDER BY seq DESC LIMIT 1", (kid,))

    def key_authority_at(self, kid: str, at: str | datetime) -> dict:
        when = at if isinstance(at, str) else at.isoformat()
        rows = self.s.q_all(
            "SELECT * FROM signer_key_event WHERE kid=? AND at<=? ORDER BY seq", (kid, when))
        if not rows:
            raise EnvelopeError("SIGNER_KEY_UNKNOWN_AT_TIME", "签名时该密钥尚未登记", 403)
        reg, revoked = None, None
        for r in rows:
            if r["event"] == "REGISTER":
                reg = r
            elif r["event"] == "REVOKE":
                revoked = r
        if not reg:
            raise EnvelopeError("SIGNER_KEY_UNKNOWN_AT_TIME", "该时刻没有有效登记", 403)
        if revoked:
            raise EnvelopeError("SIGNER_KEY_REVOKED_AT_TIME",
                                "签名发生在密钥撤销之后，历史验真拒绝", 403)
        return dict(reg)

    def rotate_root(self, by: str = "admin"):
        """轮换注册表根密钥：新旧根交叉签名同一 ROTATE 事件。

        历史 signer 事件保留其签发时的 root_kid，离线校验沿 root 事件链追溯；
        当前注册表事件改用新根。旧根标记 ROTATED 后不再签发新事件。
        """
        old = self._active_root_seed()
        seed = secrets.token_bytes(32)
        pub = ed25519.public_key(seed)
        kid = "root-" + sha256_hex(pub)[:16]
        if self.s.q_one("SELECT 1 FROM root_key WHERE kid=?", (kid,)):
            raise EnvelopeError("ROOT_EXISTS", "新根 KID 已存在", 409)
        now = utcnow()
        event = {
            "schema": "design-envelope-root-event/1", "event": "ROTATE",
            "old_kid": old["kid"], "new_kid": kid, "new_public_key": pub.hex(),
            "version": old["version"] + 1, "at": now,
        }
        old_sig = ed25519.sign(bytes.fromhex(old["private_seed"]), json_bytes(event)).hex()
        new_sig = ed25519.sign(seed, json_bytes(event)).hex()
        detail = {"signatures": [{"kid": old["kid"], "signature": old_sig},
                                 {"kid": kid, "signature": new_sig}]}
        with self.s.tx() as c:
            c.execute("UPDATE root_key SET status='ROTATED',rotated_at=?,replaced_by_kid=? "
                      "WHERE kid=?", (now, kid, old["kid"]))
            c.execute(
                "INSERT INTO root_key(kid,version,public_key,private_seed,status,created_at,"
                "activated_at) VALUES(?,?,?,?,?,?,?)",
                (kid, old["version"] + 1, pub.hex(), seed.hex(), "ACTIVE", now, now))
            c.execute(
                "INSERT INTO root_event(event,root_kid,public_key,at,signer_kid,signature,"
                "detail_json) VALUES('ROTATE',?,?,?,?,?,?)",
                (kid, pub.hex(), now, old["kid"], old_sig,
                 json.dumps(detail, ensure_ascii=False, sort_keys=True)))
        self._audit("root.rotate", kid, by, detail={"old_kid": old["kid"]})
        return {"kid": kid, "version": old["version"] + 1, "public_key": pub.hex(),
                "activated_at": now, "replaces": old["kid"]}

    def verify_root_chain(self) -> dict:
        roots = {r["kid"]: dict(r) for r in self.s.q_all("SELECT * FROM root_key ORDER BY version")}
        active = [r for r in roots.values() if r["status"] == "ACTIVE"]
        if len(active) != 1:
            raise EnvelopeError("ROOT_CHAIN_INVALID", "必须恰好有一个 ACTIVE 根", 409,
                                {"active": [r["kid"] for r in active]})
        cur = active[0]
        seen = set()
        while cur and cur["kid"] not in seen:
            seen.add(cur["kid"])
            if cur["version"] == 1:
                genesis = self.s.q_one(
                    "SELECT * FROM root_event WHERE root_kid=? AND event='GENESIS' "
                    "ORDER BY seq LIMIT 1", (cur["kid"],))
                if not genesis or not ed25519.verify(
                        bytes.fromhex(cur["public_key"]),
                        json_bytes({"schema": "design-envelope-root/1", "event": "GENESIS",
                                    "kid": cur["kid"], "version": 1,
                                    "public_key": cur["public_key"], "at": cur["activated_at"]}),
                        bytes.fromhex(genesis["signature"])):
                    raise EnvelopeError("ROOT_CHAIN_INVALID",
                                        f"根 {cur['kid']} 创世自签无效", 409)
                return {"ok": True, "active_kid": active[0]["kid"], "roots": len(seen)}
            ev = self.s.q_one(
                "SELECT * FROM root_event WHERE root_kid=? AND event='ROTATE' ORDER BY seq DESC",
                (cur["kid"],))
            if not ev:
                raise EnvelopeError("ROOT_CHAIN_INVALID", f"根 {cur['kid']} 缺少轮换事件", 409)
            detail = json.loads(ev["detail_json"])
            event = {"schema": "design-envelope-root-event/1", "event": "ROTATE",
                     "new_kid": cur["kid"], "new_public_key": cur["public_key"],
                     "version": cur["version"], "at": ev["at"]}
            sigs = {x["kid"]: x["signature"] for x in detail.get("signatures", [])}
            # signer_kid 是旧根；把它放入被新旧根共同签名的事件中，防止数据库列被篡改。
            event["old_kid"] = ev["signer_kid"]
            old_kid = event["old_kid"]
            old = roots.get(old_kid)
            if not old or old.get("replaced_by_kid") != cur["kid"]:
                raise EnvelopeError("ROOT_CHAIN_INVALID", "轮换前后根链接不一致", 409,
                                    {"new": cur["kid"], "old": old_kid})
            if old_kid not in sigs or cur["kid"] not in sigs:
                raise EnvelopeError("ROOT_CHAIN_INVALID", "根轮换缺少交叉签名", 409)
            if not ed25519.verify(bytes.fromhex(old["public_key"]), json_bytes(event),
                                  bytes.fromhex(sigs[old_kid])) or \
               not ed25519.verify(bytes.fromhex(cur["public_key"]), json_bytes(event),
                                  bytes.fromhex(sigs[cur["kid"]])):
                raise EnvelopeError("ROOT_CHAIN_INVALID",
                                    f"根 {old_kid} -> {cur['kid']} 交叉签名无效", 409)
            cur = old
        raise EnvelopeError("ROOT_CHAIN_INVALID", "根链出现环或断链", 409)

    def verify_registry(self) -> dict:
        self.verify_root_chain()
        roots = {r["kid"]: dict(r) for r in self.s.q_all("SELECT * FROM root_key")}
        bad = []
        for r in self.s.q_all("SELECT * FROM signer_key_event ORDER BY seq"):
            root = roots.get(r["root_kid"])
            event = self._registry_event(r["kid"], r["event"], r["signer"], r["role"],
                                         r["public_key"], r["at"], json.loads(r["detail_json"]))
            if not root or not ed25519.verify(bytes.fromhex(root["public_key"]),
                                              json_bytes(event), bytes.fromhex(r["signature"])):
                bad.append(r["seq"])
        if bad:
            raise EnvelopeError("REGISTRY_TAMPERED", "签名者注册表根签名校验失败", 409,
                                {"events": bad})
        return {"ok": True, "events": self.s.q_one(
            "SELECT COUNT(*) n FROM signer_key_event")["n"]}

    # ------------------------------------------------------------------ 会话
    def create_session(self, by: str, required_roles=None, parent_envelope_id=None,
                       metadata=None, session_id=None):
        sid = session_id or f"ses-{uuid.uuid4().hex[:16]}"
        roles = list(required_roles or DEFAULT_ROLES)
        if len(roles) < 2 or len(set(roles)) != len(roles):
            raise EnvelopeError("BAD_REQUEST", "多方签名至少需要两个不同角色", 400)
        if parent_envelope_id:
            self._row("SELECT id FROM envelope WHERE id=?", (parent_envelope_id,),
                      "PARENT_NOT_FOUND", "父信封不存在", 400)
        now = utcnow()
        with self.s.tx() as c:
            try:
                c.execute(
                    "INSERT INTO envelope_session(id,state,created_by,created_at,"
                    "parent_envelope_id,required_roles_json,release_metadata_json)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (sid, "OPEN", by, now, parent_envelope_id, json.dumps(roles),
                     json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)))
            except Exception:
                raise EnvelopeError("SESSION_EXISTS", "会话 ID 已存在", 409)
        self._audit("session.create", sid, by)
        return self.session(sid)

    def _open_session(self, sid: str):
        row = self._row("SELECT * FROM envelope_session WHERE id=?", (sid,),
                        "SESSION_NOT_FOUND", "封装会话不存在", 404)
        if row["state"] != "OPEN":
            raise EnvelopeError("SESSION_NOT_OPEN", f"会话已处于 {row['state']}", 409)
        return row

    def add_inline_artifact(self, sid: str, slot: str, kind: str, content,
                            detail: dict | None = None, by: str = "api"):
        if kind not in ARTIFACT_KINDS:
            raise EnvelopeError("BAD_ARTIFACT_KIND", f"未知构件类型: {kind}", 400)
        if isinstance(content, (dict, list)):
            data = json.dumps(content, ensure_ascii=False, sort_keys=True).encode()
        elif isinstance(content, str):
            data = content.encode()
        elif isinstance(content, bytes):
            data = content
        else:
            raise EnvelopeError("BAD_REQUEST", "content 必须是对象、字符串或字节", 400)
        digest = sha256_hex(data)
        self._open_session(sid)
        with self.s.tx() as c:
            self._insert_artifact(c, sid, slot, kind, None, digest, len(data), digest, data, detail)
        self._audit("artifact.add", f"{sid}/{slot}", by, detail={"sha256": digest, "kind": kind})
        return self.artifact(sid, slot)

    def _insert_artifact(self, c, sid, slot, kind, upload_id, blob_id, size, digest, data, detail):
        if c.execute("SELECT 1 FROM session_artifact WHERE session_id=? AND slot=?",
                     (sid, slot)).fetchone():
            raise EnvelopeError("ARTIFACT_SLOT_EXISTS", f"构件槽位 {slot} 已存在", 409)
        c.execute("INSERT OR IGNORE INTO blob(id,size,created_at) VALUES(?,?,?)",
                  (digest, size, utcnow()))
        if data is not None:
            self.s.write_blob(digest, data)
        pos = c.execute("SELECT COALESCE(MAX(position),-1)+1 p FROM session_artifact "
                        "WHERE session_id=?", (sid,)).fetchone()["p"]
        c.execute(
            "INSERT INTO session_artifact(session_id,slot,kind,position,upload_id,blob_id,"
            "size,content_hash,detail_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (sid, slot, kind, pos, upload_id, blob_id, size, digest,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)))

    def init_upload(self, sid: str, slot: str, kind: str, chunk_size: int,
                    total_size: int, detail: dict | None = None, by: str = "api"):
        self._open_session(sid)
        if kind not in ARTIFACT_KINDS:
            raise EnvelopeError("BAD_ARTIFACT_KIND", f"未知构件类型: {kind}", 400)
        chunk_size = int(chunk_size)
        total_size = int(total_size)
        if chunk_size <= 0 or total_size < 0:
            raise EnvelopeError("BAD_REQUEST", "非法分块大小或总长度", 400)
        uid = f"up-{uuid.uuid4().hex[:16]}"
        now = utcnow()
        with self.s.tx() as c:
            try:
                c.execute(
                    "INSERT INTO upload(id,session_id,slot,kind,chunk_size,total_size,state,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (uid, sid, slot, kind, chunk_size, total_size, "UPLOADING", now, now))
            except Exception:
                raise EnvelopeError("UPLOAD_SLOT_EXISTS", f"槽位 {slot} 已有上传", 409)
        self._audit("upload.init", uid, by,
                    detail={"session": sid, "slot": slot, "total_size": total_size})
        return self.upload(uid)

    def upload(self, uid: str):
        r = self._row("SELECT * FROM upload WHERE id=?", (uid,),
                      "UPLOAD_NOT_FOUND", "上传不存在", 404)
        d = dict(r)
        d["chunks"] = [dict(x) for x in self.s.q_all(
            "SELECT chunk_index,blob_id,size,chunk_hash,received_at FROM upload_chunk "
            "WHERE upload_id=? ORDER BY chunk_index", (uid,))]
        d["received_size"] = sum(x["size"] for x in d["chunks"])
        d["missing_indexes"] = self._missing_indexes(d)
        return d

    @staticmethod
    def _missing_indexes(u):
        expected_count = max(1, (u["total_size"] + u["chunk_size"] - 1) // u["chunk_size"])
        got = {x["chunk_index"] for x in u["chunks"]}
        return [i for i in range(expected_count) if i not in got]

    def put_chunk(self, uid: str, index: int, data: bytes, chunk_hash: str | None = None,
                  by: str = "api"):
        u = self.upload(uid)
        if u["state"] != "UPLOADING":
            raise EnvelopeError("UPLOAD_NOT_OPEN", "上传已结束", 409)
        index = int(index)
        expected_count = max(1, (u["total_size"] + u["chunk_size"] - 1) // u["chunk_size"])
        if index < 0 or index >= expected_count:
            raise EnvelopeError("CHUNK_INDEX_OUT_OF_RANGE", "分块序号越界", 400)
        start = index * u["chunk_size"]
        expected_len = min(u["chunk_size"], u["total_size"] - start)
        if len(data) != expected_len:
            raise EnvelopeError("CHUNK_SIZE_MISMATCH",
                                f"分块 {index} 长度应为 {expected_len}", 400)
        digest = sha256_hex(data)
        if chunk_hash and chunk_hash != digest:
            self._audit("chunk.denied", uid, by, "REJECTED", "CHUNK_HASH_MISMATCH",
                        {"index": index})
            raise EnvelopeError("CHUNK_HASH_MISMATCH", "客户端声明摘要与实际内容不一致", 400)
        with self.s.tx() as c:
            old = c.execute("SELECT chunk_hash FROM upload_chunk WHERE upload_id=? AND chunk_index=?",
                            (uid, index)).fetchone()
            if old and old["chunk_hash"] != digest:
                self._audit_locked(c, "chunk.denied", uid, by, "REJECTED",
                                   "CHUNK_CONFLICT", {"index": index})
                raise EnvelopeError("CHUNK_CONFLICT",
                                    "同一序号已上传不同内容，需重建上传会话", 409)
            if old:
                return self.upload(uid)
            self.s.write_blob(digest, data)
            c.execute("INSERT OR IGNORE INTO blob(id,size,created_at) VALUES(?,?,?)",
                      (digest, len(data), utcnow()))
            c.execute(
                "INSERT INTO upload_chunk(upload_id,chunk_index,blob_id,size,chunk_hash,"
                "received_at) VALUES(?,?,?,?,?,?)",
                (uid, index, digest, len(data), digest, utcnow()))
            c.execute("UPDATE upload SET updated_at=? WHERE id=?", (utcnow(), uid))
        return self.upload(uid)

    def _audit_locked(self, c, action, entity, actor, result, reason, detail):
        c.execute(
            "INSERT INTO envelope_audit(at,actor,action,entity,result,reason,detail_json)"
            " VALUES(?,?,?,?,?,?,?)",
            (utcnow(), actor, action, entity, result, reason,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)))

    def complete_upload(self, uid: str, by: str = "api"):
        u = self.upload(uid)
        if u["state"] == "READY":
            return u
        missing = u["missing_indexes"]
        if missing:
            raise EnvelopeError("UPLOAD_INCOMPLETE", "仍有分块缺失", 409,
                                {"missing_indexes": missing[:100]})
        parts = []
        for ch in u["chunks"]:
            data = self.s.read_blob(ch["chunk_hash"])
            if len(data) != ch["size"] or sha256_hex(data) != ch["chunk_hash"]:
                self._audit("upload.denied", uid, by, "REJECTED", "CHUNK_TAMPERED",
                            {"index": ch["chunk_index"]})
                raise EnvelopeError("CHUNK_TAMPERED", "分块落盘后摘要不一致", 409)
            parts.append(data)
        full = b"".join(parts)
        if len(full) != u["total_size"]:
            raise EnvelopeError("UPLOAD_SIZE_MISMATCH", "汇总长度与声明总长度不一致", 400)
        digest = sha256_hex(full)
        self.s.write_blob(digest, full)
        now = utcnow()
        with self.s.tx() as c:
            c.execute("INSERT OR IGNORE INTO blob(id,size,created_at) VALUES(?,?,?)",
                      (digest, len(full), now))
            c.execute("UPDATE upload SET state='READY',blob_id=?,content_hash=?,updated_at=? "
                      "WHERE id=?", (digest, digest, now, uid))
            detail_row = c.execute("SELECT 1 FROM upload WHERE id=?", (uid,)).fetchone()
            # detail 留空，业务元数据可在后续版本扩展到 upload；当前槽位元数据由 artifact 承载
            self._insert_artifact(c, u["session_id"], u["slot"], u["kind"], uid,
                                  digest, len(full), digest, None, {})
        self._audit("upload.complete", uid, by, detail={"sha256": digest})
        return self.upload(uid)

    def artifact(self, sid: str, slot: str):
        r = self._row("SELECT * FROM session_artifact WHERE session_id=? AND slot=?",
                      (sid, slot), "ARTIFACT_NOT_FOUND", "构件不存在", 404)
        return dict(r)

    # ------------------------------------------------------------------ 封装
    def _artifacts(self, sid: str):
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM session_artifact WHERE session_id=? ORDER BY position,slot", (sid,))]

    def _descriptor(self, a: dict, data: bytes | None = None):
        if data is None:
            data = self.s.read_blob(a["content_hash"])
        if len(data) != a["size"] or sha256_hex(data) != a["content_hash"]:
            raise EnvelopeError("ARTIFACT_TAMPERED", f"构件 {a['slot']} 摘要不一致", 409,
                                {"slot": a["slot"]})
        return {
            "slot": a["slot"], "kind": a["kind"], "position": a["position"],
            "size": a["size"], "sha256": a["content_hash"],
            "detail": json.loads(a["detail_json"]),
            "chunks": chunk_hashes(data, 1024 * 1024),
        }

    def _content_and_leaves(self, session: dict, artifacts: list[dict]):
        blobs = {}
        descriptors = []
        leaves = []
        for a in artifacts:
            data = self.s.read_blob(a["content_hash"])
            blobs[a["slot"]] = data
            desc = self._descriptor(a, data)
            descriptors.append(desc)
            leaves.append(leaf_hash("artifact", a["slot"], a["content_hash"],
                                    {"kind": a["kind"], "position": a["position"], "size": a["size"]}))
            for i, ch in enumerate(desc["chunks"]):
                leaves.append(leaf_hash("chunk", f"{a['slot']}#{i}", ch,
                                        {"slot": a["slot"], "index": i}))
        content = {
            "schema": "design-release-content/1",
            "parent_envelope_id": session["parent_envelope_id"],
            "required_roles": json.loads(session["required_roles_json"]),
            "release_metadata": json.loads(session["release_metadata_json"]),
            "artifacts": descriptors,
        }
        digest = sha256_hex(json_bytes(content))
        return content, digest, leaves, blobs

    def prepare(self, sid: str, by: str = "api"):
        row = self._row("SELECT * FROM envelope_session WHERE id=?", (sid,),
                        "SESSION_NOT_FOUND", "封装会话不存在", 404)
        if row["state"] in ("READY", "SEALED", "PUBLISHED"):
            return self.session(sid)
        if row["state"] != "OPEN":
            raise EnvelopeError("SESSION_NOT_OPEN", f"会话状态 {row['state']} 不可准备", 409)
        arts = self._artifacts(sid)
        kinds = {a["kind"] for a in arts}
        missing = [k for k in ("netlist", "constraints", "modules", "signoffs") if k not in kinds]
        if missing:
            raise EnvelopeError("MISSING_ARTIFACTS", "发布内容缺少必需构件", 400,
                                {"missing": missing})
        content, content_hash, leaves, _ = self._content_and_leaves(row, arts)
        root = merkle_root(leaves)
        manifest = {"schema": "design-release-envelope-manifest/1", "envelope_id": content_hash,
                    "content": content, "content_hash": content_hash, "merkle_root": root,
                    "prepared_at": utcnow()}
        with self.s.tx() as c:
            exists = c.execute("SELECT id FROM envelope WHERE id=?", (content_hash,)).fetchone()
            if not exists:
                c.execute("INSERT INTO envelope(id,content_hash,merkle_root,manifest_json,created_at)"
                          " VALUES(?,?,?,?,?)",
                          (content_hash, content_hash, root,
                           json.dumps(manifest, ensure_ascii=False, sort_keys=True),
                           manifest["prepared_at"]))
                for i, lh in enumerate(leaves):
                    subj, typ, digest = self._leaf_subject(content, i)
                    c.execute(
                        "INSERT INTO envelope_leaf(envelope_id,leaf_index,leaf_type,subject,"
                        "content_hash,leaf_hash) VALUES(?,?,?,?,?,?)",
                        (content_hash, i, typ, subj, digest, lh))
            c.execute("UPDATE envelope_session SET state='READY',prepared_at=?,content_hash=?,"
                      "envelope_id=?,prepare_attempt=prepare_attempt+1 WHERE id=?",
                      (manifest["prepared_at"], content_hash, content_hash, sid))
        self._audit("session.prepare", sid, by, detail={"envelope_id": content_hash})
        return self.session(sid)

    @staticmethod
    def _leaf_subject(content, index):
        i = index
        for a in content["artifacts"]:
            if i == 0:
                return a["slot"], "artifact", a["sha256"]
            i -= 1
            for j, ch in enumerate(a["chunks"]):
                if i == 0:
                    return f"{a['slot']}#{j}", "chunk", ch
                i -= 1
        raise IndexError(index)

    def challenge(self, sid: str, kid: str):
        sess = self._row("SELECT * FROM envelope_session WHERE id=? AND envelope_id IS NOT NULL",
                         (sid,), "ENVELOPE_NOT_READY", "会话尚未 prepare", 409)
        key = self.latest_key_event(kid)
        if not key or key["event"] == "REVOKED":
            raise EnvelopeError("SIGNER_KEY_INACTIVE", "当前密钥不存在或已撤销，不能新签名", 403)
        payload = {
            "schema": "design-envelope-signature/1", "envelope_id": sess["envelope_id"],
            "kid": kid, "signed_at": utcnow(),
        }
        return payload

    def add_signature(self, sid: str, kid: str, signature: str, by: str | None = None):
        sess = self._row("SELECT * FROM envelope_session WHERE id=? AND envelope_id IS NOT NULL",
                         (sid,), "ENVELOPE_NOT_READY", "会话尚未 prepare", 409)
        if sess["state"] not in ("READY", "SEALED", "PUBLISHED"):
            raise EnvelopeError("ENVELOPE_NOT_READY", "信封尚未准备好", 409)
        eid = sess["envelope_id"]
        try:
            sig = bytes.fromhex(signature)
        except Exception:
            raise EnvelopeError("BAD_SIGNATURE", "签名必须是 hex", 400)
        # 签名对象由 challenge 分发；从签名本身无法取回 signed_at，因此客户端必须回传 challenge。
        # API 层把完整 challenge 放入 signed_payload；CLI 同协议。
        raise EnvelopeError("BAD_REQUEST", "内部调用应使用 submit_signature", 500)

    def submit_signature(self, sid: str, signed_payload: dict, signature: str,
                         by: str | None = None):
        sess = self._row("SELECT * FROM envelope_session WHERE id=? AND envelope_id IS NOT NULL",
                         (sid,), "ENVELOPE_NOT_READY", "会话尚未 prepare", 409)
        if sess["state"] not in ("READY", "SEALED", "PUBLISHED"):
            raise EnvelopeError("ENVELOPE_NOT_READY", "信封状态不允许签名", 409)
        eid = sess["envelope_id"]
        required = set(json.loads(sess["required_roles_json"]))
        kid = signed_payload.get("kid")
        signed_at = signed_payload.get("signed_at")
        if signed_payload.get("envelope_id") != eid or \
                signed_payload.get("schema") != "design-envelope-signature/1":
            raise EnvelopeError("BAD_SIGNING_PAYLOAD", "签名挑战与当前信封不匹配", 400)
        try:
            sig = bytes.fromhex(signature)
            ts = parse_ts(signed_at)
        except Exception:
            raise EnvelopeError("BAD_SIGNATURE", "签名/时间格式非法", 400)
        if abs(datetime.now(timezone.utc) - ts) > timedelta(seconds=CHALLENGE_TOLERANCE_SECONDS):
            raise EnvelopeError("SIGNATURE_CHALLENGE_EXPIRED", "签名挑战过期", 403)
        authority = self.key_authority_at(kid, ts)
        if authority["role"] not in required:
            raise EnvelopeError("ROLE_NOT_REQUIRED",
                                f"该信封不需要角色 {authority['role']}", 403)
        env = self.envelope(eid)
        signed_message = {
            "schema": "design-envelope-signature/1", "envelope_id": eid,
            "content_hash": env["content_hash"], "merkle_root": env["merkle_root"],
            "kid": kid, "signed_at": signed_at,
        }
        if signed_payload != {
                "schema": "design-envelope-signature/1", "envelope_id": eid,
                "kid": kid, "signed_at": signed_at}:
            # 客户端只签 challenge；服务端把固定上下文字段并入验签消息，防止裁剪重放。
            pass
        if not ed25519.verify(bytes.fromhex(authority["public_key"]),
                              json_bytes(signed_message), sig):
            self._audit("signature.denied", eid, by or authority["signer"],
                        "REJECTED", "BAD_SIGNATURE")
            raise EnvelopeError("BAD_SIGNATURE", "签名验真失败", 403)
        with self.s.tx() as c:
            old = c.execute("SELECT signature FROM envelope_signature WHERE envelope_id=? AND kid=?",
                            (eid, kid)).fetchone()
            if old:
                if old["signature"] != signature:
                    self._audit_locked(c, "signature.denied", eid,
                                       by or authority["signer"], "REJECTED", "SIGNATURE_CONFLICT")
                    raise EnvelopeError("SIGNATURE_CONFLICT", "同一密钥已对该信封给出不同签名", 409)
            else:
                c.execute(
                    "INSERT INTO envelope_signature(envelope_id,kid,signer,role,signature,"
                    "signed_at,created_at) VALUES(?,?,?,?,?,?,?)",
                    (eid, kid, authority["signer"], authority["role"], signature,
                     signed_at, utcnow()))
        self._audit("signature.add", eid, by or authority["signer"],
                    detail={"kid": kid, "role": authority["role"]})
        return self.session(sid)

    def signatures(self, eid: str):
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM envelope_signature WHERE envelope_id=? ORDER BY seq", (eid,))]

    def _verify_signatures(self, eid: str, manifest: dict, enforce_time: bool = True):
        out = []
        for s in self.signatures(eid):
            auth = self.key_authority_at(s["kid"], s["signed_at"])
            msg = {
                "schema": "design-envelope-signature/1", "envelope_id": eid,
                "content_hash": manifest["content_hash"], "merkle_root": manifest["merkle_root"],
                "kid": s["kid"], "signed_at": s["signed_at"],
            }
            ok = (
                s["signer"] == auth["signer"]
                and s["role"] == auth["role"]
                and ed25519.verify(bytes.fromhex(auth["public_key"]), json_bytes(msg),
                                   bytes.fromhex(s["signature"]))
            )
            out.append({"signature": s, "authority": {
                "signer": auth["signer"], "role": auth["role"],
                "registered_at": auth["at"], "public_key": auth["public_key"]},
                "valid": ok})
            if not ok:
                raise EnvelopeError("SIGNATURE_INVALID", f"{s['kid']} 签名无效", 409)
        return out

    def signature_manifest(self, eid: str):
        env = self.envelope(eid)
        sigs = self.signatures(eid)
        sig_leaves = [leaf_hash("signature", s["kid"], sha256_hex(bytes.fromhex(s["signature"])),
                                {"role": s["role"], "signer": s["signer"],
                                 "signed_at": s["signed_at"]}) for s in sigs]
        return {
            "schema": "design-signature-manifest/1",
            "envelope_id": eid,
            "content_hash": env["content_hash"],
            "content_merkle_root": env["merkle_root"],
            "signatures": sigs,
            "signature_merkle_root": merkle_root(sig_leaves),
        }

    def seal(self, sid: str, by: str = "api"):
        sess = self._row("SELECT * FROM envelope_session WHERE id=?", (sid,),
                         "SESSION_NOT_FOUND", "封装会话不存在", 404)
        if sess["state"] in ("SEALED", "PUBLISHED"):
            return self.session(sid)
        if sess["state"] != "READY":
            raise EnvelopeError("ENVELOPE_NOT_READY", "只有 READY 会话可封口", 409)
        eid = sess["envelope_id"]
        env = self.envelope(eid)
        manifest = json.loads(env["manifest_json"])
        self.verify_content(eid, audit=False)
        checked = self._verify_signatures(eid, manifest)
        required = json.loads(sess["required_roles_json"])
        by_role = {}
        for item in checked:
            s = item["signature"]
            by_role.setdefault(s["role"], set()).add(s["signer"])
        missing = [r for r in required if not by_role.get(r)]
        if missing:
            raise EnvelopeError("SIGNATURES_INCOMPLETE", "必需角色签名不齐", 409,
                                {"missing_roles": missing})
        if len({s["signer"] for s in self.signatures(eid)}) < 2:
            raise EnvelopeError("SIGNATURES_INCOMPLETE", "多方签名必须来自至少两个自然人", 409)
        with self.s.tx() as c:
            c.execute("UPDATE envelope_session SET state='SEALED',sealed_at=? WHERE id=?",
                      (utcnow(), sid))
        self._audit("session.seal", sid, by, detail={"envelope_id": eid})
        return self.session(sid)

    def envelope(self, eid: str):
        return dict(self._row("SELECT * FROM envelope WHERE id=?", (eid,),
                              "ENVELOPE_NOT_FOUND", "信封不存在", 404))

    def manifest(self, eid: str):
        return json.loads(self.envelope(eid)["manifest_json"])

    def verify_content(self, eid: str, audit: bool = True):
        env = self.envelope(eid)
        manifest = json.loads(env["manifest_json"])
        sess_rows = self.s.q_all(
            "SELECT * FROM envelope_session WHERE envelope_id=? ORDER BY prepared_at,id", (eid,))
        if not sess_rows:
            raise EnvelopeError("ENVELOPE_NO_SESSION", "信封没有会话来源", 409)
        sess = dict(sess_rows[0])
        arts = self._artifacts(sess["id"])
        content, digest, leaves, _ = self._content_and_leaves(sess, arts)
        expected = json.loads(json.dumps(manifest["content"], sort_keys=True, ensure_ascii=False))
        actual = json.loads(json.dumps(content, sort_keys=True, ensure_ascii=False))
        problems = []
        if digest != env["content_hash"] or content != expected:
            problems.append("CONTENT_DIGEST_MISMATCH")
        if merkle_root(leaves) != env["merkle_root"]:
            problems.append("MERKLE_ROOT_MISMATCH")
        for row in self.s.q_all("SELECT * FROM envelope_leaf WHERE envelope_id=? ORDER BY leaf_index",
                                (eid,)):
            if row["leaf_index"] >= len(leaves) or row["leaf_hash"] != leaves[row["leaf_index"]]:
                problems.append("LEAF_INDEX_TAMPERED")
                break
        if problems:
            if audit:
                self._audit("verify.content", eid, None, "INVALID", ",".join(problems))
            raise EnvelopeError("ENVELOPE_TAMPERED", "内容摘要或分块索引校验失败", 409,
                                {"reasons": problems})
        # 分块落盘逐块验证（完整 blob 与内容哈希已在 _descriptor 中验证）。
        for a in manifest["content"]["artifacts"]:
            data = self.s.read_blob(a["sha256"])
            for i, ch in enumerate(a["chunks"]):
                start = i * 1024 * 1024
                if sha256_hex(data[start:start + 1024 * 1024] or b"") != ch:
                    if audit:
                        self._audit("verify.content", eid, None, "INVALID", "CHUNK_TAMPERED",
                                    {"slot": a["slot"], "index": i})
                    raise EnvelopeError("CHUNK_TAMPERED", "分块被篡改", 409,
                                        {"slot": a["slot"], "index": i})
        return {"ok": True, "envelope_id": eid, "content_hash": digest,
                "merkle_root": env["merkle_root"], "artifacts": len(arts)}

    def verify_envelope(self, eid: str, trusted_root_kid: str | None = None):
        try:
            self.verify_registry()
            result = self.verify_content(eid, audit=True)
            env = self.envelope(eid)
            manifest = json.loads(env["manifest_json"])
            sig_check = self._verify_signatures(eid, manifest)
            sm = self.signature_manifest(eid)
            final_leaves = [r["leaf_hash"] for r in self.s.q_all(
                "SELECT leaf_hash FROM envelope_leaf WHERE envelope_id=? ORDER BY leaf_index", (eid,))]
            # 重建签名叶子（与导出保持一致），验证 final root。
            for s in self.signatures(eid):
                final_leaves.append(leaf_hash(
                    "signature", s["kid"], sha256_hex(bytes.fromhex(s["signature"])),
                    {"role": s["role"], "signer": s["signer"], "signed_at": s["signed_at"]}))
            final_root = merkle_root(final_leaves)
            result.update({"ok": True, "final_merkle_root": final_root,
                           "signatures": [{"kid": x["signature"]["kid"], "role": x["signature"]["role"],
                                           "signer": x["signature"]["signer"],
                                           "signed_at": x["signature"]["signed_at"], "valid": True}
                                          for x in sig_check],
                           "signature_manifest": sm})
            self._audit("verify.envelope", eid, None, "VALID",
                        detail={"signatures": len(sig_check)})
            return result
        except EnvelopeError as e:
            self._audit("verify.envelope", eid, None, "INVALID", e.code,
                        {"detail": e.extra})
            raise

    # ------------------------------------------------------------------ 发布
    def publish(self, sid: str, name: str, by: str = "api"):
        sess = self._row("SELECT * FROM envelope_session WHERE id=?", (sid,),
                         "SESSION_NOT_FOUND", "封装会话不存在", 404)
        if sess["state"] == "PUBLISHED":
            pub = self.s.q_one("SELECT * FROM publication WHERE envelope_id=? AND name=?",
                               (sess["envelope_id"], name))
            if pub:
                return self.publication(name)
        if sess["state"] != "SEALED":
            # 自动尝试封口；签名不足会得到确定性错误。
            if sess["state"] == "READY":
                self.seal(sid, by)
                sess = self.s.q_one("SELECT * FROM envelope_session WHERE id=?", (sid,))
            if sess["state"] != "SEALED":
                raise EnvelopeError("ENVELOPE_NOT_SEALED", "信封封口前不能发布", 409)
        eid = sess["envelope_id"]
        conflict = None
        with self.s.tx() as c:
            existing = c.execute("SELECT * FROM publication WHERE name=?", (name,)).fetchone()
            if existing and existing["envelope_id"] != eid:
                conflict = EnvelopeError(
                    "NAME_CONTENT_CONFLICT",
                    "同名发布已指向不同内容；必须使用新名称", 409,
                    {"name": name, "existing_envelope_id": existing["envelope_id"],
                     "attempted_envelope_id": eid})
            elif existing and existing["state"] == "PUBLISHED":
                return dict(existing)
            elif not existing:
                now = utcnow()
                c.execute(
                    "INSERT INTO publication(name,envelope_id,state,published_by,created_at)"
                    " VALUES(?,?,?,?,?)",
                    (name, eid, "PUBLISHING", by, now))
        if conflict:
            self._audit("publish.denied", name, by, "REJECTED", "NAME_CONTENT_CONFLICT",
                        conflict.extra)
            raise conflict
        self._finish_publication(name)
        self.s.q_one("UPDATE envelope_session SET state='PUBLISHED' WHERE id=?", (sid,))
        self._audit("session.publish", sid, by, detail={"name": name, "envelope_id": eid})
        return self.publication(name)

    def _finish_publication(self, name: str):
        pub = self._row("SELECT * FROM publication WHERE name=?", (name,),
                        "PUBLICATION_NOT_FOUND", "发布不存在", 404)
        if pub["state"] == "PUBLISHED" and Path(pub["release_path"]).exists():
            return dict(pub)
        eid = pub["envelope_id"]
        bundle = self.export_bundle(eid)
        release_hash = sha256_hex(bundle)
        path = self.s.blob_dir / "releases" / f"{safe_name(name)}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.s.tmp_path(f"release-{safe_name(name)}.json")
        receipt = {
            "schema": "design-release-receipt/1", "name": name,
            "envelope_id": eid, "published_by": pub["published_by"],
            "created_at": pub["created_at"], "finished_at": utcnow(),
            "release_bundle_sha256": release_hash,
        }
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(receipt, f, ensure_ascii=False, sort_keys=True, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        with self.s.tx() as c:
            c.execute("UPDATE publication SET state='PUBLISHED',finished_at=?,release_path=?,"
                      "release_hash=? WHERE name=? AND envelope_id=?",
                      (receipt["finished_at"], str(path), release_hash, name, eid))
            c.execute("UPDATE envelope_session SET state='PUBLISHED' WHERE envelope_id=?", (eid,))
            self._audit_locked(c, "publish.complete", name, pub["published_by"], "OK", None,
                               {"envelope_id": eid, "release_hash": release_hash})
        return self.publication(name)

    def recover(self):
        recovered = []
        for r in self.s.q_all("SELECT name FROM publication WHERE state='PUBLISHING'"):
            recovered.append(self._finish_publication(r["name"])["name"])
        # READY/SEALED 是可恢复的正常持久状态；绝不为同一 content_hash 另建 envelope。
        return {"recovered_publications": recovered}

    def publication(self, name: str):
        return dict(self._row("SELECT * FROM publication WHERE name=?", (name,),
                              "PUBLICATION_NOT_FOUND", "发布不存在", 404))

    def list_publications(self):
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM publication ORDER BY created_at DESC,name")]

    # ------------------------------------------------------------------ 查询
    def session(self, sid: str):
        r = self._row("SELECT * FROM envelope_session WHERE id=?", (sid,),
                      "SESSION_NOT_FOUND", "封装会话不存在", 404)
        d = dict(r)
        for k in ("required_roles_json", "release_metadata_json"):
            d[k.removesuffix("_json")] = json.loads(d.pop(k))
        d["artifacts"] = self._artifacts(sid)
        d["uploads"] = [self.upload(x["id"]) for x in self.s.q_all(
            "SELECT id FROM upload WHERE session_id=? ORDER BY created_at", (sid,))]
        if d.get("envelope_id"):
            d["signatures"] = self.signatures(d["envelope_id"])
            d["signature_count"] = len(d["signatures"])
        else:
            d["signatures"], d["signature_count"] = [], 0
        return d

    def list_sessions(self):
        return [self.session(r["id"]) for r in self.s.q_all(
            "SELECT id FROM envelope_session ORDER BY created_at")]

    def list_envelopes(self):
        out = []
        for r in self.s.q_all("SELECT * FROM envelope ORDER BY created_at"):
            d = dict(r)
            d["signature_count"] = self.s.q_one(
                "SELECT COUNT(*) n FROM envelope_signature WHERE envelope_id=?",
                (r["id"],))["n"]
            d["publications"] = [x["name"] for x in self.s.q_all(
                "SELECT name FROM publication WHERE envelope_id=? AND state='PUBLISHED'", (r["id"],))]
            out.append(d)
        return out

    def lineage(self, name: str | None = None, eid: str | None = None):
        if name:
            eid = self.publication(name)["envelope_id"]
        if not eid:
            raise EnvelopeError("BAD_REQUEST", "需要 name 或 envelope_id", 400)
        chain = []
        seen = set()
        cur = eid
        while cur and cur not in seen:
            seen.add(cur)
            m = self.manifest(cur)
            names = [r["name"] for r in self.s.q_all(
                "SELECT name FROM publication WHERE envelope_id=? AND state='PUBLISHED' ORDER BY name",
                (cur,))]
            chain.append({"envelope_id": cur, "names": names,
                          "parent_envelope_id": m["content"]["parent_envelope_id"],
                          "created_at": self.envelope(cur)["created_at"],
                          "signature_count": len(self.signatures(cur))})
            cur = m["content"]["parent_envelope_id"]
        return {"head_envelope_id": eid, "chain": list(reversed(chain))}

    def proofs(self, eid: str, include_signatures: bool = True):
        env = self.envelope(eid)
        leaves = [dict(r) for r in self.s.q_all(
            "SELECT * FROM envelope_leaf WHERE envelope_id=? ORDER BY leaf_index", (eid,))]
        leaf_hashes = [x["leaf_hash"] for x in leaves]
        if include_signatures:
            for s in self.signatures(eid):
                leaves.append({"leaf_type": "signature", "leaf_index": len(leaves),
                               "subject": s["kid"], "content_hash": sha256_hex(
                                   bytes.fromhex(s["signature"])),
                               "leaf_hash": leaf_hash("signature", s["kid"],
                                                      sha256_hex(bytes.fromhex(s["signature"])),
                                                      {"role": s["role"], "signer": s["signer"],
                                                       "signed_at": s["signed_at"]})})
                leaf_hashes = [x["leaf_hash"] for x in leaves]
        root = merkle_root(leaf_hashes)
        return {"envelope_id": eid, "root": root,
                "proofs": [merkle_proof(leaf_hashes, i) for i in range(len(leaf_hashes))],
                "leaves": [{"index": x["leaf_index"], "type": x["leaf_type"],
                            "subject": x["subject"], "sha256": x["content_hash"],
                            "leaf_hash": x["leaf_hash"]} for x in leaves]}

    def inclusion_proof(self, eid: str, leaf_type: str, subject: str):
        bundle = self.proofs(eid)
        for i, leaf in enumerate(bundle["leaves"]):
            if leaf["type"] == leaf_type and leaf["subject"] == subject:
                proof = bundle["proofs"][i]
                proof["type"] = leaf_type
                proof["subject"] = subject
                proof["verified"] = verify_proof(proof)
                return proof
        raise EnvelopeError("LEAF_NOT_FOUND", "叶子不存在", 404)

    # ------------------------------------------------------------------ 导出
    def _trust_bundle(self):
        return {
            "roots": [dict(r) for r in self.s.q_all(
                "SELECT kid,version,public_key,status,created_at,activated_at,rotated_at,"
                "replaced_by_kid FROM root_key ORDER BY version")],
            "root_events": [dict(r) for r in self.s.q_all("SELECT * FROM root_event ORDER BY seq")],
            "signer_events": [dict(r) for r in self.s.q_all(
                "SELECT * FROM signer_key_event ORDER BY seq")],
        }

    def export_bundle(self, eid: str) -> bytes:
        env = self.envelope(eid)
        manifest = json.loads(env["manifest_json"])
        self.verify_content(eid, audit=False)
        sig_manifest = self.signature_manifest(eid)
        proofs = self.proofs(eid)
        trust = self._trust_bundle()
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False,
                                                   sort_keys=True, indent=2))
            z.writestr("SIGNATURES.json", json.dumps(sig_manifest, ensure_ascii=False,
                                                     sort_keys=True, indent=2))
            z.writestr("TRUST.json", json.dumps(trust, ensure_ascii=False, sort_keys=True, indent=2))
            z.writestr("PROOFS.json", json.dumps(proofs, ensure_ascii=False,
                                                 sort_keys=True, indent=2))
            sess = self.s.q_one("SELECT id FROM envelope_session WHERE envelope_id=? "
                                "ORDER BY prepared_at,id", (eid,))
            for a in self._artifacts(sess["id"]):
                z.writestr(f"artifacts/{artifact_bundle_name(a)}",
                           self.s.read_blob(a["content_hash"]))
        return zbuf.getvalue()

    @staticmethod
    def _verify_offline_root_chain(trust: dict, trusted_root_kid: str | None) -> list[str]:
        roots = {r["kid"]: r for r in trust.get("roots", [])}
        active = [r for r in roots.values() if r.get("status") == "ACTIVE"]
        if trusted_root_kid:
            active = [r for r in active if r["kid"] == trusted_root_kid]
        if len(active) != 1:
            return ["TRUSTED_ROOT_NOT_FOUND"]
        events = [e for e in trust.get("root_events", []) if e.get("event") == "ROTATE"]
        by_new = {e["root_kid"]: e for e in events}
        cur, seen = active[0], set()
        while cur and cur["kid"] not in seen:
            seen.add(cur["kid"])
            if cur["version"] == 1:
                gen = next((e for e in trust.get("root_events", [])
                            if e.get("root_kid") == cur["kid"] and e.get("event") == "GENESIS"), None)
                event = {"schema": "design-envelope-root/1", "event": "GENESIS",
                         "kid": cur["kid"], "version": 1, "public_key": cur["public_key"],
                         "at": cur["activated_at"]}
                if not gen or not ed25519.verify(bytes.fromhex(cur["public_key"]),
                                                 json_bytes(event),
                                                 bytes.fromhex(gen["signature"])):
                    return ["ROOT_GENESIS_INVALID"]
                return []
            ev = by_new.get(cur["kid"])
            old = roots.get(ev["signer_kid"]) if ev else None
            if not ev or not old or old.get("replaced_by_kid") != cur["kid"]:
                return [f"ROOT_LINK_INVALID:{cur['kid']}"]
            detail = json.loads(ev["detail_json"])
            sigs = {x["kid"]: x["signature"] for x in detail.get("signatures", [])}
            event = {"schema": "design-envelope-root-event/1", "event": "ROTATE",
                     "old_kid": old["kid"], "new_kid": cur["kid"],
                     "new_public_key": cur["public_key"], "version": cur["version"],
                     "at": ev["at"]}
            if old["kid"] not in sigs or cur["kid"] not in sigs:
                return [f"ROOT_ROTATION_SIGNATURES_MISSING:{cur['kid']}"]
            if not ed25519.verify(bytes.fromhex(old["public_key"]), json_bytes(event),
                                  bytes.fromhex(sigs[old["kid"]])) or \
               not ed25519.verify(bytes.fromhex(cur["public_key"]), json_bytes(event),
                                  bytes.fromhex(sigs[cur["kid"]])):
                return [f"ROOT_ROTATION_INVALID:{old['kid']}->{cur['kid']}"]
            cur = old
        return ["ROOT_CHAIN_BROKEN"]

    @staticmethod
    def verify_offline_bundle(data: bytes, trusted_root_kid: str | None = None) -> dict:
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            manifest = json.loads(z.read("MANIFEST.json"))
            sigm = json.loads(z.read("SIGNATURES.json"))
            trust = json.loads(z.read("TRUST.json"))
            proofs = json.loads(z.read("PROOFS.json"))
        except Exception as e:
            raise EnvelopeError("BUNDLE_INVALID", f"离线信封格式损坏: {e}", 400)
        problems = []
        # 重新计算构件、chunk 与内容 root。
        leaves = []
        for a in manifest["content"]["artifacts"]:
            raw = z.read(f"artifacts/{artifact_bundle_name(a)}")
            if len(raw) != a["size"] or sha256_hex(raw) != a["sha256"]:
                problems.append(f"artifact:{a['slot']}")
            if chunk_hashes(raw, 1024 * 1024) != a["chunks"]:
                problems.append(f"chunks:{a['slot']}")
            leaves.append(leaf_hash("artifact", a["slot"], a["sha256"],
                                    {"kind": a["kind"], "position": a["position"], "size": a["size"]}))
            for i, ch in enumerate(a["chunks"]):
                leaves.append(leaf_hash("chunk", f"{a['slot']}#{i}", ch,
                                        {"slot": a["slot"], "index": i}))
        content_hash = sha256_hex(json_bytes(manifest["content"]))
        if content_hash != manifest["content_hash"] or content_hash != manifest["envelope_id"]:
            problems.append("CONTENT_DIGEST_MISMATCH")
        if merkle_root(leaves) != manifest["merkle_root"]:
            problems.append("MERKLE_ROOT_MISMATCH")
        # 根链与注册表。
        problems.extend(EnvelopeService._verify_offline_root_chain(trust, trusted_root_kid))
        root_by_kid = {r["kid"]: r for r in trust["roots"]}
        latest = {}
        for ev in trust["signer_events"]:
            root = root_by_kid.get(ev["root_kid"])
            event = {
                "schema": "design-signer-registry/1", "kid": ev["kid"], "event": ev["event"],
                "signer": ev["signer"], "role": ev["role"], "public_key": ev["public_key"],
                "at": ev["at"], "detail": json.loads(ev["detail_json"]),
            }
            if not root or not ed25519.verify(bytes.fromhex(root["public_key"]),
                                              json_bytes(event), bytes.fromhex(ev["signature"])):
                problems.append(f"registry:{ev['kid']}:{ev['seq']}")
            state = latest.setdefault(ev["kid"], {"register": None, "revoke": None})
            if ev["event"] == "REGISTER":
                state["register"] = ev
            elif ev["event"] == "REVOKE":
                state["revoke"] = ev
        # 签名。
        sig_leaves = []
        signers = set()
        required = set(manifest["content"]["required_roles"])
        got_roles = set()
        for s in sigm["signatures"]:
            state = latest.get(s["kid"]) or {"register": None, "revoke": None}
            ev = state["register"]
            revoked = state["revoke"]
            msg = {
                "schema": "design-envelope-signature/1", "envelope_id": manifest["envelope_id"],
                "content_hash": manifest["content_hash"], "merkle_root": manifest["merkle_root"],
                "kid": s["kid"], "signed_at": s["signed_at"],
            }
            ok = ev and ev["at"] <= s["signed_at"] and \
                s["signer"] == ev["signer"] and s["role"] == ev["role"] and \
                (not revoked or s["signed_at"] < revoked["at"]) and \
                ed25519.verify(bytes.fromhex(ev["public_key"]), json_bytes(msg),
                               bytes.fromhex(s["signature"]))
            if not ok:
                problems.append(f"signature:{s['kid']}")
            else:
                got_roles.add(s["role"])
                signers.add(s["signer"])
            sig_leaves.append(leaf_hash("signature", s["kid"],
                                        sha256_hex(bytes.fromhex(s["signature"])),
                                        {"role": s["role"], "signer": s["signer"],
                                         "signed_at": s["signed_at"]}))
        if got_roles != required or len(signers) < 2:
            problems.append("SIGNATURES_INCOMPLETE")
        final_root = merkle_root(leaves + sig_leaves)
        if proofs["root"] != final_root:
            problems.append("FINAL_ROOT_MISMATCH")
        if any(not verify_proof(p) for p in proofs["proofs"]):
            problems.append("MERKLE_PROOF_INVALID")
        if problems:
            raise EnvelopeError("OFFLINE_VERIFICATION_FAILED", "离线验真失败", 409,
                                {"reasons": sorted(set(problems))})
        return {"ok": True, "envelope_id": manifest["envelope_id"],
                "final_merkle_root": final_root,
                "signatures": len(sigm["signatures"])}

    def audits(self, limit: int = 200, entity: str | None = None, result: str | None = None):
        sql = "SELECT * FROM envelope_audit"
        where, args = [], []
        if entity:
            where.append("entity=?")
            args.append(entity)
        if result:
            where.append("result=?")
            args.append(result)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY seq DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.s.q_all(sql, args)]
