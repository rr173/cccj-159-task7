"""光罩投片交付中心 —— 领域核心。

职责：
- 资料解析（层映射 / recipe / die / scribe / 工艺角 / GDS·OASIS 占位解析）
- 导入校验：摘要、版图层 ↔ 层映射 ↔ recipe ↔ 工艺角，每个不一致定位到具体构件
- 规范化指纹与稳定交付编号；重复导入去重；同名异物隔离
- mask set 谱系（主版 / 修正版 / 派生层 / 曝光后 delta），依赖倒置与环检测
- 曝光窗口与 lot 编排：先后次序、机器时间排他、单当前 mask set、并发唯一赢家
- 双角色批准替换（制造工程师 + 版图负责人，不同自然人）
- 曝光后永久封存与 delta 返工
- 幂等操作编号（过期 / 指纹不符均明确拒绝）
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone

from .mask_store import (
    MaskStore, OP_TTL_SECONDS, REQUIRED_META_SLOTS, SEED_USERS, canonical_bytes, utcnow,
)


class MaskError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400, extra: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.extra = extra or {}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def norm_ts(s: str) -> str:
    """规范化 ISO-8601 时间串（接受 Z 后缀），词法可比较。"""
    if not s:
        raise MaskError("BAD_REQUEST", "时间不能为空", 400)
    try:
        t = s.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="minutes")
    except ValueError:
        raise MaskError("BAD_REQUEST", f"时间格式无法解析: {s}", 400)


# ---------------- 资料解析 ----------------

def _text_lines(data: bytes) -> list[str] | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.splitlines()


def parse_layermap(data: bytes) -> dict:
    lines = _text_lines(data)
    if lines is None:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "层映射必须是 UTF-8 文本"}
    layers: list[dict] = []
    seen = set()
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "LAYERMAP":
            continue
        if parts[0] != "LAYER" or len(parts) < 3:
            return {"parse_status": "PARSE_ERROR",
                    "parse_detail": f"第 {i} 行格式错误（应为 LAYER <层号> <名称>）: {raw!r}"}
        try:
            no = int(parts[1])
        except ValueError:
            return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行层号不是整数"}
        if no in seen:
            return {"parse_status": "PARSE_ERROR", "parse_detail": f"层 {no} 重复定义"}
        seen.add(no)
        layers.append({"layer_no": no, "name": parts[2]})
    if not layers:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "层映射中没有任何 LAYER 记录"}
    return {"parse_status": "OK", "detail": {"layers": layers}}


def parse_recipe(data: bytes) -> dict:
    lines = _text_lines(data)
    if lines is None:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "recipe 必须是 UTF-8 文本"}
    recipe_id, layers, corners = None, set(), []
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "RECIPE":
            if len(parts) < 2:
                return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行缺少 recipe id"}
            recipe_id = parts[1]
        elif parts[0] == "LAYER":
            if len(parts) < 2:
                return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行缺少层号"}
            try:
                layers.add(int(parts[1]))
            except ValueError:
                return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行层号不是整数"}
        elif parts[0] == "CORNER":
            if len(parts) < 2:
                return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行缺少工艺角名"}
            corners.append(parts[1])
        else:
            return {"parse_status": "PARSE_ERROR",
                    "parse_detail": f"第 {i} 行无法识别（只接受 RECIPE/LAYER/CORNER）: {raw!r}"}
    if not recipe_id:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "recipe 缺少 RECIPE <id> 记录"}
    return {"parse_status": "OK",
            "detail": {"recipe_id": recipe_id, "layers": sorted(layers), "corners": corners}}


def parse_die(data: bytes) -> dict:
    lines = _text_lines(data)
    if lines is None:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "die 文件必须是 UTF-8 文本"}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] != "DIE" or len(parts) < 3:
            return {"parse_status": "PARSE_ERROR",
                    "parse_detail": f"应为 DIE <width_um> <height_um>: {raw!r}"}
        try:
            w, h = float(parts[1]), float(parts[2])
        except ValueError:
            return {"parse_status": "PARSE_ERROR", "parse_detail": "die 尺寸不是数字"}
        if w <= 0 or h <= 0:
            return {"parse_status": "PARSE_ERROR", "parse_detail": "die 尺寸必须为正数"}
        return {"parse_status": "OK", "detail": {"width_um": w, "height_um": h}}
    return {"parse_status": "PARSE_ERROR", "parse_detail": "die 文件缺少 DIE 记录"}


def parse_scribe(data: bytes) -> dict:
    lines = _text_lines(data)
    if lines is None:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "scribe 文件必须是 UTF-8 文本"}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] != "SCRIBE" or len(parts) < 3 or parts[1] != "WIDTH":
            return {"parse_status": "PARSE_ERROR",
                    "parse_detail": f"应为 SCRIBE WIDTH <um>: {raw!r}"}
        try:
            w = float(parts[2])
        except ValueError:
            return {"parse_status": "PARSE_ERROR", "parse_detail": "scribe 宽度不是数字"}
        if w <= 0:
            return {"parse_status": "PARSE_ERROR", "parse_detail": "scribe 宽度必须为正数"}
        return {"parse_status": "OK", "detail": {"width_um": w}}
    return {"parse_status": "PARSE_ERROR", "parse_detail": "scribe 文件缺少 SCRIBE 记录"}


def parse_corner(data: bytes) -> dict:
    lines = _text_lines(data)
    if lines is None:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "工艺角文件必须是 UTF-8 文本"}
    name, params = None, {}
    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "CORNER":
            if len(parts) < 2:
                return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行缺少角名"}
            name = parts[1]
        elif "=" in line:
            k, v = line.split("=", 1)
            params[k.strip()] = v.strip()
        else:
            return {"parse_status": "PARSE_ERROR", "parse_detail": f"第 {i} 行无法识别: {raw!r}"}
    if not name:
        return {"parse_status": "PARSE_ERROR", "parse_detail": "工艺角文件缺少 CORNER <name>"}
    return {"parse_status": "OK", "detail": {"corner": name, "params": params}}


def parse_layout(data: bytes) -> dict:
    """GDS/OASIS 在真实系统中是二进制；这里接受任意字节，并从可识别的
    ``@LAYER <n>`` 声明行（演示/质检清单）中提取包含的版图层。"""
    layers = []
    try:
        text = data.decode("utf-8")
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("@LAYER"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        layers.append(int(parts[1]))
                    except ValueError:
                        return {"parse_status": "PARSE_ERROR",
                                "parse_detail": f"@LAYER 层号不是整数: {raw!r}"}
    except UnicodeDecodeError:
        pass  # 纯二进制 GDS/OASIS：版图层以层映射/recipe 对应核验为准
    return {"parse_status": "OK", "detail": {"declared_layers": sorted(set(layers))}}


PARSERS = {
    "layermap": parse_layermap,
    "recipe": parse_recipe,
    "die": parse_die,
    "scribe": parse_scribe,
    "corner": parse_corner,
    "layout": parse_layout,
}
META_KINDS = {"layermap", "recipe", "die", "scribe"}


class MaskService:
    def __init__(self, store: MaskStore):
        self.s = store

    # ============ 通用辅助 ============
    @staticmethod
    def user(user_id: str | None):
        if not user_id:
            return None
        u = SEED_USERS.get(user_id)
        return {"id": user_id, "name": u["name"], "roles": u["roles"]} if u else None

    def require_user(self, user_id: str | None, role: str | None = None):
        u = self.user(user_id)
        if not u:
            raise MaskError("UNKNOWN_USER", f"未知操作人: {user_id!r}", 401)
        if role and role not in u["roles"]:
            raise MaskError("FORBIDDEN", f"用户 {u['name']} 不具备角色 {role}", 403)
        return u

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    def _audit(self, c, action, entity=None, actor=None, result="OK", reason=None,
               op_id=None, detail=None):
        self.s.audit(c, action, entity, actor, result, reason, op_id, detail)

    def _row_artifact(self, r) -> dict:
        d = dict(r)
        d["detail"] = json.loads(d.pop("detail_json"))
        return d

    def _row_release(self, r) -> dict:
        d = dict(r)
        d["declared_digests"] = json.loads(d.pop("declared_digests_json"))
        return d

    # ============ 幂等操作编号 ============
    def idempotent(self, op_id: str | None, kind: str, request: dict, fn,
                   ttl_seconds: int = OP_TTL_SECONDS):
        """返回 (response_dict, http_status, replayed:bool)。

        ``fn(c)`` 必须接受一个事务游标并在该事务内完成全部业务写入。

        - 无 op_id：fn(None) 在其自管事务内执行。
        - 相同 op_id 重放：返回首次的稳定结果（成功或被拒），不重复执行业务。
        - 过期（默认 24h）：即使原操作成功过也以 OP_EXPIRED 拒绝。
        - 同 op_id 不同请求体：OP_FINGERPRINT 拒绝。
        - PENDING（上次执行进程崩溃）：后来者接管重跑（业务自身有内容/窗口去重）。
        - PENDING 登记、业务、DONE 标记在**同一事务**：业务回滚则登记一并回滚，
          不会毒化 op_id；同 op 并发由单把锁串行，第一个提交后其余读到 DONE 重放。
        """
        if not op_id:
            return (*fn(None), False)
        fp_body = {"kind": kind, "request": {k: v for k, v in request.items() if k != "op_id"}}
        fp = sha256_hex(canonical_bytes(fp_body))
        now = datetime.now(timezone.utc)

        def settle(row):
            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at <= now:
                raise MaskError("OP_EXPIRED", f"操作编号 {op_id} 已过期，请使用新编号重试",
                                410, {"op_id": op_id, "expires_at": row["expires_at"]})
            if row["request_fp"] != fp:
                raise MaskError("OP_FINGERPRINT",
                                "同一操作编号携带了不同请求体，拒绝执行", 409,
                                {"op_id": op_id})
            payload = json.loads(row["response_json"])
            if isinstance(payload, dict):
                payload = {**payload, "replayed": True}
            return payload, row["http_status"], True

        expires = (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")
        # 说明：进程内单把锁 + BEGIN IMMEDIATE 已把所有业务写事务串行化。
        # - 业务在幂等事务内回滚 → PENDING 行随事务回滚，op_id 立即释放，不毒化；
        # - 提交成功 → 行已为 DONE，后来者读到后重放；
        # - 唯一残留 PENDING 的情形是进程在提交前崩溃，由后来者直接接管重跑
        #   （业务自身具备内容/窗口唯一去重，接管不会产生重复实体）。
        with self.s.tx() as c:
            row = c.execute("SELECT * FROM mask_op WHERE op_id=?", (op_id,)).fetchone()
            if row is not None and row["status"] in ("DONE", "REJECTED"):
                return settle(row)
            if row is None:
                c.execute(
                    "INSERT INTO mask_op(op_id,kind,request_fp,status,response_json,"
                    "http_status,created_at,expires_at) VALUES(?,?,?,'PENDING','{}',0,?,?)",
                    (op_id, kind, fp, utcnow(), expires))
            elif row["status"] == "INTERRUPTED":
                # 崩溃残留：原编号接管重跑（请求体以本次为准，刷新指纹与有效期）
                c.execute("UPDATE mask_op SET kind=?,request_fp=?,status='PENDING',"
                          "response_json='{}',http_status=0,created_at=?,expires_at=? "
                          "WHERE op_id=?",
                          (kind, fp, utcnow(), expires, op_id))
                self.s.audit(c, "op.resume", None, None, "OK", "INTERRUPTED_RESUME", op_id,
                             {"kind": kind})
            # 残留 PENDING（未经过 recover 的极罕见情况）也直接接管重跑
            try:
                resp, status = fn(c)
            except MaskError as e:
                body = {"error": e.code, "message": e.message, "detail": e.extra}
                c.execute("UPDATE mask_op SET status='REJECTED',response_json=?,http_status=? "
                          "WHERE op_id=?",
                          (json.dumps(body, ensure_ascii=False), e.http_status, op_id))
                raise
            c.execute("UPDATE mask_op SET status='DONE',response_json=?,http_status=? "
                      "WHERE op_id=?",
                      (json.dumps(resp, ensure_ascii=False), status, op_id))
        return resp, status, False

    # ============ 发行 / 导入 ============
    def create_release(self, name: str, by: str, declared_digests: dict | None = None) -> dict:
        self.require_user(by)
        if not name or not name.strip():
            raise MaskError("BAD_REQUEST", "发行名不能为空", 400)
        rid = self._new_id("REL")
        now = utcnow()
        with self.s.tx() as c:
            c.execute(
                "INSERT INTO mask_release(id,name,declared_digests_json,created_by,created_at)"
                " VALUES(?,?,?,?,?)",
                (rid, name.strip(), json.dumps(declared_digests or {}, sort_keys=True), by, now))
            self._audit(c, "release.create", rid, by, detail={"name": name})
        return self.release_detail(rid)

    def _slot_for(self, kind: str, detail: dict, layer_no, corner_name) -> str:
        if kind == "layout":
            if layer_no is None:
                raise MaskError("BAD_REQUEST", "layout 构件必须给出 layer_no", 400)
            return f"L{int(layer_no):02d}"
        if kind == "corner":
            name = corner_name or detail.get("corner")
            if not name:
                raise MaskError("BAD_REQUEST", "corner 构件缺少工艺角名", 400)
            return f"CORNER:{name}"
        if kind not in META_KINDS:
            raise MaskError("BAD_REQUEST", f"未知构件类型: {kind}", 400)
        return kind

    def add_artifact(self, release_id: str, kind: str, name: str, data: bytes,
                     declared_sha256: str | None, by: str,
                     layer_no: int | None = None, op_id: str | None = None,
                     allow_version: bool = False) -> dict:
        """收料：落内容寻址 blob，校验摘要，解析，并做同名异物检测。

        allow_version=True 用于替换/返工通道（同一槽位产生新版本，不走同名隔离）。
        """
        self.require_user(by)
        rel = self._get_release(release_id)
        if rel["status"] != "COLLECTING" and not allow_version:
            raise MaskError("RELEASE_NOT_COLLECTING",
                            f"发行 {release_id} 已规范化（{rel['status']}），不能再收新料；"
                            "修订请走替换/派生通道", 409)
        if kind not in PARSERS:
            raise MaskError("BAD_REQUEST", f"未知构件类型: {kind}", 400)
        if not name:
            raise MaskError("BAD_REQUEST", "构件文件名不能为空", 400)

        def work(c):
            return self._add_artifact_tx(release_id, kind, name, data, declared_sha256, by,
                                         layer_no, allow_version, c=c), 201

        return self.idempotent(op_id, "artifact.upload",
                               {"release": release_id, "kind": kind, "name": name,
                                "declared": declared_sha256, "layer_no": layer_no,
                                "sha256": sha256_hex(data)}, work)[0]

    def _add_artifact_tx(self, release_id, kind, name, data, declared_sha256, by,
                         layer_no, allow_version, c=None) -> dict:
        actual = sha256_hex(data)
        now = utcnow()
        # 上传即核验摘要：声明摘要与实算不符，明确拒绝（疑似篡改/传输出错）
        digest_ok = True
        if declared_sha256 and declared_sha256.lower() != actual:
            digest_ok = False
        parsed = PARSERS[kind](data)
        detail = parsed.get("detail", {})
        slot = self._slot_for(kind, detail, layer_no, None)

        def body(c):
            vid = self._new_id("VRF")
            c.execute("INSERT INTO mask_verification(id,release_id,stage,verdict,created_at)"
                      " VALUES(?,?,?,?,?)",
                      (vid, release_id, "UPLOAD", "PASS" if digest_ok and
                       parsed["parse_status"] == "OK" else "FAIL", now))
            if not digest_ok:
                c.execute(
                    "INSERT INTO mask_finding(verification_id,release_id,code,severity,"
                    "slot,component,message,detail_json,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (vid, release_id, "DIGEST_MISMATCH", "ERROR", slot, name,
                     f"构件 {name} 声明摘要与实算不符（声明 {declared_sha256[:16]}… / "
                     f"实算 {actual[:16]}…）",
                     json.dumps({"declared": declared_sha256, "actual": actual}, sort_keys=True),
                     now))
                self._audit(c, "artifact.upload", name, by, "DENIED", "DIGEST_MISMATCH",
                            detail={"slot": slot})
            if parsed["parse_status"] != "OK":
                c.execute(
                    "INSERT INTO mask_finding(verification_id,release_id,code,severity,"
                    "slot,component,message,detail_json,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (vid, release_id, "PARSE_ERROR", "ERROR", slot, name,
                     f"构件 {name} 解析失败: {parsed['parse_detail']}", "{}", now))

            if not digest_ok:
                # 摘要不符：实体绝不入库
                raise MaskError("DIGEST_MISMATCH",
                                f"构件 {name} 的摘要被篡改或传输损坏，已拒绝入库", 422,
                                {"slot": slot, "declared": declared_sha256, "actual": actual})
            if parsed["parse_status"] != "OK":
                raise MaskError("PARSE_ERROR",
                                f"构件 {name} 无法解析: {parsed['parse_detail']}", 422,
                                {"slot": slot})

            self.s.write_blob(actual, data)
            self.s.ensure_blob_row(c, actual, len(data))

            # 版本位：同槽位同内容即重复导入（复用，不复制实体）；不同内容需走版本通道
            prev = c.execute(
                "SELECT * FROM mask_artifact WHERE release_id=? AND slot=? "
                "ORDER BY version DESC LIMIT 1", (release_id, slot)).fetchone()
            if prev:
                if prev["sha256"] == actual:
                    # 重复导入相同实体：幂等返回既有构件
                    resp = self._row_artifact(prev)
                    resp["quarantined"] = False
                    resp["quarantine_id"] = None
                    return resp
                if not allow_version:
                    raise MaskError("SLOT_OCCUPIED",
                                    f"槽位 {slot} 已有不同内容构件（{prev['name']}）；"
                                    "替换/返工请走版本通道",
                                    409, {"slot": slot, "existing": prev["id"]})
                ver = prev["version"] + 1
            else:
                ver = 1

            # 同名异物隔离：同一文件名在别处以不同内容存在（可能是不同 kind/槽位，
            # 也可能是另一发行）。同槽位新版本属于替换/返工通道，是正常谱系演进。
            quarantined = False
            collision = None
            if not allow_version:
                collision = c.execute(
                    "SELECT * FROM mask_artifact WHERE name=? AND sha256<>? "
                    "AND NOT (release_id=? AND slot=?) LIMIT 1",
                    (name, actual, release_id, slot)).fetchone()
            qid = None
            if collision:
                quarantined = True
                qrow = c.execute(
                    "SELECT id FROM mask_quarantine WHERE release_id=? AND name=? AND kind=? "
                    "AND incoming_blob=? AND status='PENDING'",
                    (release_id, name, kind, actual)).fetchone()
                if qrow:
                    qid = qrow["id"]
                else:
                    qid = self._new_id("Q")
                    c.execute(
                        "INSERT INTO mask_quarantine(id,release_id,artifact_id,kind,name,"
                        "existing_blob,incoming_blob,status,created_at)"
                        " VALUES(?,?,?,?,?,?,?,'PENDING',?)",
                        (qid, release_id, "", kind, name, collision["sha256"], actual, now))

            aid = self._new_id("ART")
            c.execute(
                "INSERT INTO mask_artifact(id,release_id,kind,slot,name,blob_id,size,sha256,"
                "declared_sha256,parse_status,parse_detail,detail_json,version,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (aid, release_id, kind, slot, name, actual, len(data), actual,
                 declared_sha256, parsed["parse_status"], parsed.get("parse_detail", ""),
                 json.dumps(detail, ensure_ascii=False, sort_keys=True), ver, now))
            if qid:
                c.execute("UPDATE mask_quarantine SET artifact_id=? WHERE id=?", (aid, qid))
            self._audit(c, "artifact.upload", aid, by,
                        detail={"slot": slot, "name": name, "version": ver, "size": len(data),
                                "sha256": actual, "quarantined": quarantined,
                                "deduped": collision is None and ver == 1})
            resp = self._row_artifact(c.execute(
                "SELECT * FROM mask_artifact WHERE id=?", (aid,)).fetchone())
            resp["quarantined"] = quarantined
            resp["quarantine_id"] = qid
            return resp

        if c is not None:
            return body(c)
        with self.s.tx() as c:
            return body(c)

    def _get_release(self, rid: str) -> dict:
        r = self.s.q_one("SELECT * FROM mask_release WHERE id=?", (rid,))
        if not r:
            raise MaskError("RELEASE_NOT_FOUND", f"发行不存在: {rid}", 404)
        return self._row_release(r)

    def release_detail(self, rid: str) -> dict:
        rel = self._get_release(rid)
        arts = [self._row_artifact(r) for r in self.s.q_all(
            "SELECT * FROM mask_artifact WHERE release_id=? ORDER BY slot, version", (rid,))]
        qs = [dict(r) for r in self.s.q_all(
            "SELECT * FROM mask_quarantine WHERE release_id=? ORDER BY created_at", (rid,))]
        sets = [dict(r) for r in self.s.q_all(
            "SELECT * FROM mask_set WHERE release_id=? ORDER BY created_at", (rid,))]
        rel["artifacts"] = arts
        rel["quarantines"] = qs
        rel["mask_sets"] = sets
        return rel

    def _release_detail_c(self, c, rid: str) -> dict:
        r = c.execute("SELECT * FROM mask_release WHERE id=?", (rid,)).fetchone()
        if not r:
            raise MaskError("RELEASE_NOT_FOUND", f"发行不存在: {rid}", 404)
        rel = self._row_release(r)
        rel["artifacts"] = [self._row_artifact(x) for x in c.execute(
            "SELECT * FROM mask_artifact WHERE release_id=? ORDER BY slot, version", (rid,))]
        rel["quarantines"] = [dict(x) for x in c.execute(
            "SELECT * FROM mask_quarantine WHERE release_id=? ORDER BY created_at", (rid,))]
        rel["mask_sets"] = [dict(x) for x in c.execute(
            "SELECT * FROM mask_set WHERE release_id=? ORDER BY created_at", (rid,))]
        return rel

    def list_releases(self) -> list[dict]:
        out = []
        for r in self.s.q_all("SELECT * FROM mask_release ORDER BY created_at DESC"):
            d = self._row_release(r)
            d["artifact_count"] = self.s.q_one(
                "SELECT COUNT(*) n FROM mask_artifact WHERE release_id=?", (d["id"],))["n"]
            out.append(d)
        return out

    # ---- 同名异物处置 ----
    def resolve_quarantine(self, qid: str, resolution: str, by: str, note: str | None = None):
        self.require_user(by)
        if resolution not in ("REJECT_INCOMING", "ACCEPT_NEW"):
            raise MaskError("BAD_REQUEST", "resolution 必须是 REJECT_INCOMING / ACCEPT_NEW", 400)
        with self.s.tx() as c:
            q = c.execute("SELECT * FROM mask_quarantine WHERE id=?", (qid,)).fetchone()
            if not q:
                raise MaskError("QUARANTINE_NOT_FOUND", f"隔离记录不存在: {qid}", 404)
            if q["status"] != "PENDING":
                raise MaskError("QUARANTINE_RESOLVED", "该同名冲突已处置", 409,
                                {"resolution": q["resolution"]})
            if resolution == "REJECT_INCOMING":
                # 删除被判定为异物的构件行（blob 内容寻址保留供审计取证）
                c.execute("DELETE FROM mask_artifact WHERE id=?", (q["artifact_id"],))
            c.execute("UPDATE mask_quarantine SET status='RESOLVED',resolution=?,note=?,"
                      "resolved_at=?,resolved_by=? WHERE id=?",
                      (resolution, note, utcnow(), by, qid))
            self._audit(c, "quarantine.resolve", qid, by,
                        detail={"resolution": resolution, "name": q["name"], "note": note})
        return dict(self.s.q_one("SELECT * FROM mask_quarantine WHERE id=?", (qid,)))

    def list_quarantine(self, pending_only: bool = True) -> list[dict]:
        sql = "SELECT * FROM mask_quarantine"
        if pending_only:
            sql += " WHERE status='PENDING'"
        return [dict(r) for r in self.s.q_all(sql + " ORDER BY created_at")]

    # ============ 核验与规范化 ============
    def _current_artifacts(self, c, rid: str):
        """每槽位最新版本（初版发行只有 v1）。"""
        rows = c.execute(
            "SELECT a.* FROM mask_artifact a JOIN ("
            " SELECT slot, MAX(version) mv FROM mask_artifact WHERE release_id=? GROUP BY slot"
            ") t ON a.slot=t.slot AND a.version=t.mv WHERE a.release_id=? "
            "ORDER BY a.slot", (rid, rid)).fetchall()
        return list(rows)

    def verify_release(self, rid: str, stage: str = "FINALIZE", c=None) -> dict:
        rel = self._get_release(rid)
        now = utcnow()
        findings: list[dict] = []

        def add(code, sev, message, slot=None, component=None, artifact_id=None, detail=None):
            findings.append({"code": code, "severity": sev, "slot": slot,
                             "component": component or slot, "artifact_id": artifact_id,
                             "message": message, "detail": detail or {}})

        with self.s.using_tx(c) as c:
            arts = self._current_artifacts(c, rid)
            by_slot = {a["slot"]: a for a in arts}

            # 防御性复验：落盘 blob 实摘必须与库内一致（防篡改）
            for a in arts:
                if not self.s.blob_path(a["blob_id"]).exists():
                    add("BLOB_MISSING", "ERROR", f"构件 {a['name']} 的实体在存储中缺失",
                        a["slot"], a["name"], a["id"])
                    continue
                actual = sha256_hex(self.s.read_blob(a["blob_id"]))
                if actual != a["sha256"]:
                    add("DIGEST_MISMATCH", "ERROR",
                        f"构件 {a['name']} 落盘摘要与登记不符，疑似被篡改",
                        a["slot"], a["name"], a["id"],
                        {"stored": a["sha256"], "actual": actual})

            # 待处置同名异物
            for q in c.execute("SELECT * FROM mask_quarantine WHERE release_id=? AND status='PENDING'",
                               (rid,)):
                add("QUARANTINE_PENDING", "ERROR",
                    f"同名异物待处置: {q['kind']} 构件 {q['name']} 与既有构件内容不同",
                    component=q["name"], detail={"quarantine_id": q["id"]})

            # 必需元数据构件
            for s_ in REQUIRED_META_SLOTS:
                if s_ not in by_slot:
                    add("MISSING_COMPONENT", "ERROR", f"缺少必需构件: {s_}", slot=s_)

            lmap = by_slot.get("layermap")
            recipe = by_slot.get("recipe")
            mapped = set()
            if lmap and lmap["parse_status"] == "OK":
                mapped = {x["layer_no"] for x in json.loads(lmap["detail_json"])["layers"]}
            recipe_layers, recipe_id, recipe_corners = set(), None, set()
            if recipe and recipe["parse_status"] == "OK":
                rd = json.loads(recipe["detail_json"])
                recipe_layers, recipe_id = set(rd["layers"]), rd["recipe_id"]
                recipe_corners = set(rd["corners"])

            # 版图层
            layout_layers = {}
            for a in arts:
                if a["kind"] == "layout":
                    try:
                        no = int(a["slot"][1:])
                    except ValueError:
                        continue
                    layout_layers[no] = a
                    declared = set(json.loads(a["detail_json"]).get("declared_layers", []))
                    if declared and no not in declared:
                        add("LAYER_SLOT_MISMATCH", "ERROR",
                            f"构件 {a['name']} 申报槽位 L{no:02d} 不在其声明版图层 {sorted(declared)} 中",
                            a["slot"], a["name"], a["id"])

            if not layout_layers:
                add("MISSING_LAYER", "ERROR", "没有任何版图（GDS/OASIS）构件")

            # 层映射 ↔ recipe ↔ 版图 三者对应
            for no in sorted(recipe_layers):
                if lmap and no not in mapped:
                    add("RECIPE_LAYER_NOT_MAPPED", "ERROR",
                        f"recipe {recipe_id} 引用层 {no}，但层映射中没有该层（缺层）",
                        "recipe", recipe["name"], recipe["id"], {"layer_no": no})
                if no not in layout_layers:
                    add("MISSING_LAYER", "ERROR",
                        f"recipe {recipe_id} 需要层 {no}，但缺少该层 GDS/OASIS 构件（缺层）",
                        "recipe", recipe["name"], recipe["id"], {"layer_no": no})
            for no, a in sorted(layout_layers.items()):
                if lmap and no not in mapped:
                    add("UNMAPPED_LAYOUT_LAYER", "ERROR",
                        f"版图层 {no}（{a['name']}）在层映射中没有对应条目",
                        a["slot"], a["name"], a["id"], {"layer_no": no})
            if lmap:
                for no in sorted(mapped - recipe_layers):
                    add("LAYER_NOT_IN_RECIPE", "WARN",
                        f"层 {no} 在层映射中但 recipe {recipe_id} 未引用", "layermap",
                        lmap["name"], lmap["id"], {"layer_no": no})

            # 工艺角对应
            corner_arts = {json.loads(a["detail_json"]).get("corner"): a
                           for a in arts if a["kind"] == "corner"}
            for cn in sorted(recipe_corners):
                if cn not in corner_arts:
                    add("CORNER_ARTIFACT_MISSING", "ERROR",
                        f"recipe {recipe_id} 声明工艺角 {cn}，但缺少对应工艺角构件（缺层/缺件）",
                        "recipe", recipe["name"], recipe["id"], {"corner": cn})
            for cn, a in sorted(corner_arts.items()):
                if recipe and cn not in recipe_corners:
                    add("CORNER_NOT_IN_RECIPE", "WARN",
                        f"工艺角 {cn} 不在 recipe {recipe_id} 声明中", a["slot"], a["name"],
                        a["id"], {"corner": cn})

            verdict = "FAIL" if any(f["severity"] == "ERROR" for f in findings) else "PASS"
            vid = self._new_id("VRF")
            c.execute("INSERT INTO mask_verification(id,release_id,stage,verdict,created_at)"
                      " VALUES(?,?,?,?,?)", (vid, rid, stage, verdict, now))
            for f in findings:
                c.execute(
                    "INSERT INTO mask_finding(verification_id,release_id,code,severity,"
                    "artifact_id,slot,component,message,detail_json,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (vid, rid, f["code"], f["severity"], f.get("artifact_id"), f["slot"],
                     f["component"], f["message"],
                     json.dumps(f["detail"], ensure_ascii=False, sort_keys=True), now))
            self._audit(c, "verification", rid, result=verdict,
                        detail={"stage": stage, "errors": sum(
                            f["severity"] == "ERROR" for f in findings)})
            return {"verification_id": vid, "release_id": rid, "stage": stage,
                    "verdict": verdict, "findings": findings}

    def finalize_release(self, rid: str, by: str, op_id: str | None = None) -> dict:
        self.require_user(by)

        def work(c):
            return self._finalize_tx(rid, by, c), 200
        return self.idempotent(op_id, "release.finalize",
                               {"release": rid, "by": by}, work)[0]

    def _normalized_fingerprint(self, arts) -> str:
        struct = []
        for a in sorted(arts, key=lambda x: (x["slot"], x["version"])):
            struct.append({"slot": a["slot"], "kind": a["kind"], "name": a["name"],
                           "sha256": a["sha256"],
                           "detail": json.loads(a["detail_json"])})
        return sha256_hex(canonical_bytes({"schema": "mask-delivery/1", "artifacts": struct}))

    def _finalize_tx(self, rid: str, by: str, c=None) -> dict:
        with self.s.using_tx(c) as c:
            relrow = c.execute("SELECT * FROM mask_release WHERE id=?", (rid,)).fetchone()
            if not relrow:
                raise MaskError("RELEASE_NOT_FOUND", f"发行不存在: {rid}", 404)
            if relrow["status"] == "FINALIZED":
                twin = relrow
                return {**self._release_detail_c(c, rid), "replayed": True,
                        "deduped": bool(relrow["normalized_fingerprint"] is None
                                        and relrow["delivery_no"])}
            if relrow["status"] != "COLLECTING":
                raise MaskError("RELEASE_BAD_STATE",
                                f"发行状态为 {relrow['status']}，无法规范化", 409)
            vrf = self.verify_release(rid, "FINALIZE", c)
            if vrf["verdict"] != "PASS":
                raise MaskError("VERIFICATION_FAILED", "核验未通过，拒绝规范化；请按 findings 修正",
                                422, {"verification_id": vrf["verification_id"],
                                      "findings": vrf["findings"]})
            arts = self._current_artifacts(c, rid)
            fp = self._normalized_fingerprint(arts)
            twin = c.execute(
                "SELECT * FROM mask_release WHERE normalized_fingerprint=? AND id<>?",
                (fp, rid)).fetchone()
            if twin:
                # 完整资料重复导入：复用稳定交付编号，不复制任何实体，也不写指纹唯一列
                c.execute("UPDATE mask_release SET status='FINALIZED',delivery_no=?,"
                          "finalized_at=? WHERE id=?",
                          (twin["delivery_no"], utcnow(), rid))
                self._audit(c, "release.finalize", rid, by,
                            detail={"delivery_no": twin["delivery_no"], "deduped": True,
                                    "canonical_of": twin["id"]})
                return {**self._release_detail_c(c, rid), "delivery_no": twin["delivery_no"],
                        "deduped": True, "canonical_release": twin["id"]}
            delivery_no = "MS-" + fp[:12].upper()
            c.execute("UPDATE mask_release SET status='FINALIZED',normalized_fingerprint=?,"
                      "delivery_no=?,finalized_at=? WHERE id=?",
                      (fp, delivery_no, utcnow(), rid))
            self._audit(c, "release.finalize", rid, by, detail={"delivery_no": delivery_no})
            return {**self._release_detail_c(c, rid), "delivery_no": delivery_no,
                    "deduped": False}

    def verifications(self, rid: str) -> list[dict]:
        out = []
        for v in self.s.q_all(
                "SELECT * FROM mask_verification WHERE release_id=? ORDER BY created_at", (rid,)):
            d = dict(v)
            d["findings"] = [dict(f) for f in self.s.q_all(
                "SELECT * FROM mask_finding WHERE verification_id=? ORDER BY id", (v["id"],))]
            for f in d["findings"]:
                f["detail"] = json.loads(f.pop("detail_json"))
            out.append(d)
        return out

    # ============ mask set 与谱系 ============
    def create_mask_set(self, release_id: str, name: str, by: str,
                        op_id: str | None = None) -> dict:
        self.require_user(by)

        def work(c):
            return self._create_set_tx(release_id, name, by, c), 201
        return self.idempotent(op_id, "maskset.create",
                               {"release": release_id, "name": name, "by": by}, work)[0]

    def _create_set_tx(self, release_id, name, by, c=None):
        with self.s.using_tx(c) as c:
            relrow = c.execute("SELECT status FROM mask_release WHERE id=?",
                               (release_id,)).fetchone()
            if not relrow:
                raise MaskError("RELEASE_NOT_FOUND", f"发行不存在: {release_id}", 404)
            if relrow["status"] != "FINALIZED":
                raise MaskError("RELEASE_NOT_FINALIZED", "发行必须先通过核验并规范化", 409)
            arts = self._current_artifacts(c, release_id)
            sid = self._new_id("SET")
            now = utcnow()
            c.execute("INSERT INTO mask_set(id,release_id,name,kind,created_at,created_by)"
                      " VALUES(?,?,?,'MASTER',?,?)", (sid, release_id, name, now, by))
            nid = self._new_id("NODE")
            c.execute("INSERT INTO mask_node(id,mask_set_id,seq,kind,label,status,created_by,"
                      "created_at) VALUES(?,? ,1,'MASTER',?,'ACTIVE',?,?)",
                      (nid, sid, f"{name} 主版 R1", by, now))
            for a in arts:
                layer_no = int(a["slot"][1:]) if a["kind"] == "layout" else None
                c.execute("INSERT INTO mask_node_slot(node_id,slot,artifact_id,layer_no)"
                          " VALUES(?,?,?,?)", (nid, a["slot"], a["id"], layer_no))
            self._audit(c, "maskset.create", sid, by,
                        detail={"release": release_id, "master_node": nid, "slots": len(arts)})
            sid_out = sid
        # c 为外部（幂等）游标时事务尚未提交，用该游标读取即可；自管事务此时已提交
        return self.mask_set_detail(sid_out, c)

    def _get_set(self, sid: str):
        r = self.s.q_one("SELECT * FROM mask_set WHERE id=?", (sid,))
        if not r:
            raise MaskError("SET_NOT_FOUND", f"mask set 不存在: {sid}", 404)
        return r

    def _get_node(self, nid: str):
        r = self.s.q_one("SELECT * FROM mask_node WHERE id=?", (nid,))
        if not r:
            raise MaskError("NODE_NOT_FOUND", f"谱系节点不存在: {nid}", 404)
        return r

    def _node_slots(self, c, nid: str) -> dict:
        return {r["slot"]: r for r in c.execute(
            "SELECT * FROM mask_node_slot WHERE node_id=?", (nid,))}

    def _tip_node(self, c, sid: str):
        return c.execute(
            "SELECT * FROM mask_node WHERE mask_set_id=? ORDER BY seq DESC LIMIT 1",
            (sid,)).fetchone()

    def _descendants(self, c, nid: str) -> set:
        seen, stack = set(), [nid]
        while stack:
            cur = stack.pop()
            for r in c.execute("SELECT child_node_id FROM mask_node_edge WHERE parent_node_id=?",
                               (cur,)):
                if r["child_node_id"] not in seen:
                    seen.add(r["child_node_id"])
                    stack.append(r["child_node_id"])
        return seen

    def _ancestors(self, c, nid: str) -> set:
        seen, stack = set(), [nid]
        while stack:
            cur = stack.pop()
            for r in c.execute("SELECT parent_node_id FROM mask_node_edge WHERE child_node_id=?",
                               (cur,)):
                if r["parent_node_id"] not in seen:
                    seen.add(r["parent_node_id"])
                    stack.append(r["parent_node_id"])
        return seen

    def _assert_no_cycle(self, c, parent, child):
        """供连接已存在的节点时使用：parent==child 或 parent 已在 child 下游即为环。
        派生/修正产生的是全新节点，调用方应跳过本检查（新节点尚无任何边）。"""
        if parent == child:
            raise MaskError("LINEAGE_CYCLE", "节点不能依赖自身", 422)
        if parent in self._descendants(c, child):
            raise MaskError("LINEAGE_CYCLE",
                            f"添加 {parent} → {child} 会形成谱系环（依赖倒置）", 422,
                            {"path": [child, parent]})

    def derive_node(self, set_id: str, parent_node_id: str, label: str, by: str,
                    slot: str, artifact_payload: dict | None = None,
                    op_id: str | None = None) -> dict:
        """登记派生层节点：内容直接继承父节点，新槽位指向新构件。

        artifact_payload = {name, data:bytes, declared_sha256}
        """
        self.require_user(by, "LAYOUT_OWNER")

        def work(c):
            return self._derive_tx(set_id, parent_node_id, label, by, slot,
                                   artifact_payload, c), 201
        return self.idempotent(op_id, "node.derive",
                               {"set": set_id, "parent": parent_node_id, "slot": slot,
                                "label": label, "by": by,
                                "sha256": artifact_payload and sha256_hex(
                                    artifact_payload.get("data", b""))}, work)[0]

    def _derive_tx(self, set_id, parent_id, label, by, slot, payload, c=None):
        with self.s.using_tx(c) as c:
            s = c.execute("SELECT * FROM mask_set WHERE id=?", (set_id,)).fetchone()
            if not s:
                raise MaskError("SET_NOT_FOUND", f"mask set 不存在: {set_id}", 404)
            parent = c.execute("SELECT * FROM mask_node WHERE id=?", (parent_id,)).fetchone()
            if not parent:
                raise MaskError("NODE_NOT_FOUND", f"谱系节点不存在: {parent_id}", 404)
            if parent["mask_set_id"] != set_id:
                raise MaskError("DEPENDENCY_INVERSION", "父节点不属于该 mask set，禁止跨集派生",
                                422)
            if parent["status"] == "SUPERSEDED":
                raise MaskError("DEPENDENCY_INVERSION",
                                "不能基于已被修正取代（SUPERSEDED）的节点派生，属于依赖倒置",
                                422, {"node": parent_id})
            slots = self._node_slots(c, parent_id)
            if slot in slots:
                raise MaskError("SLOT_EXISTS",
                                f"槽位 {slot} 在父节点已存在；替换构件请走双签替换", 409)
            # 新构件必须随派生一起登记（layout 类，新版本通道）
            if not payload:
                raise MaskError("BAD_REQUEST", "派生层必须提供新构件 payload", 400)
            art = self._add_artifact_tx(s["release_id"], "layout", payload["name"],
                                        payload["data"], payload.get("declared_sha256"), by,
                                        int(slot[1:]) if slot.startswith("L") else None,
                                        allow_version=True, c=c)
            seq = c.execute("SELECT MAX(seq) m FROM mask_node WHERE mask_set_id=?",
                            (set_id,)).fetchone()["m"] + 1
            nid = self._new_id("NODE")
            c.execute("INSERT INTO mask_node(id,mask_set_id,seq,kind,label,status,reason,"
                      "created_by,created_at) VALUES(?,?,?,'DERIVED',?,'ACTIVE',?, ?,?)",
                      (nid, set_id, seq, label or f"派生层 {slot}", "derive", by, utcnow()))
            for sl, r in slots.items():
                c.execute("INSERT INTO mask_node_slot(node_id,slot,artifact_id,layer_no)"
                          " SELECT ?,slot,artifact_id,layer_no FROM mask_node_slot "
                          "WHERE node_id=? AND slot=?", (nid, parent_id, sl))
            c.execute("INSERT INTO mask_node_slot(node_id,slot,artifact_id,layer_no) VALUES(?,?,?,?)",
                      (nid, slot, art["id"],
                       int(slot[1:]) if slot.startswith("L") else None))
            c.execute("INSERT INTO mask_node_edge(parent_node_id,child_node_id) VALUES(?,?)",
                      (parent_id, nid))
            self._audit(c, "node.derive", nid, by,
                        detail={"set": set_id, "parent": parent_id, "new_slot": slot})
            nid_out = nid
        return self.node_detail(nid_out, c)

    def node_detail(self, nid: str, c=None) -> dict:
        def body(c):
            n = c.execute("SELECT * FROM mask_node WHERE id=?", (nid,)).fetchone()
            if not n:
                raise MaskError("NODE_NOT_FOUND", f"谱系节点不存在: {nid}", 404)
            d = dict(n)
            d["slots"] = []
            for r in c.execute(
                    "SELECT ns.slot,ns.artifact_id,ns.layer_no,a.name,a.sha256,a.version,a.kind "
                    "FROM mask_node_slot ns JOIN mask_artifact a ON a.id=ns.artifact_id "
                    "WHERE ns.node_id=? ORDER BY ns.slot", (nid,)):
                d["slots"].append(dict(r))
            d["parents"] = [r["parent_node_id"] for r in c.execute(
                "SELECT parent_node_id FROM mask_node_edge WHERE child_node_id=? "
                "ORDER BY parent_node_id", (nid,))]
            d["children"] = [r["child_node_id"] for r in c.execute(
                "SELECT child_node_id FROM mask_node_edge WHERE parent_node_id=? "
                "ORDER BY child_node_id", (nid,))]
            rep = c.execute(
                "SELECT id,node_id AS replaces_node_id,slot FROM mask_replacement "
                "WHERE new_node_id=?", (nid,)).fetchone()
            d["replaces"] = dict(rep) if rep else None
            return d
        if c is not None:
            return body(c)
        with self.s.tx() as c:
            return body(c)

    def mask_set_detail(self, sid: str, c=None) -> dict:
        s = self._get_set(sid)
        d = dict(s)

        def body(c):
            d["nodes"] = [self.node_detail(r["id"], c) for r in c.execute(
                "SELECT id FROM mask_node WHERE mask_set_id=? ORDER BY seq", (sid,))]
            return d
        if c is not None:
            return body(c)
        with self.s.tx() as c:
            return body(c)

    def list_mask_sets(self) -> list[dict]:
        out = []
        for r in self.s.q_all(
                "SELECT ms.*, (SELECT COUNT(*) FROM mask_node n WHERE n.mask_set_id=ms.id) nodes"
                " FROM mask_set ms ORDER BY ms.created_at"):
            out.append(dict(r))
        return out

    # ============ lot 与曝光窗口编排 ============
    def create_lot(self, name: str, by: str) -> dict:
        self.require_user(by, "DISPATCHER")
        lid = self._new_id("LOT")
        with self.s.tx() as c:
            c.execute("INSERT INTO mask_lot(id,name,status,created_at) VALUES(?,?,'CREATED',?)",
                      (lid, name, utcnow()))
            self._audit(c, "lot.create", lid, by, detail={"name": name})
        return self.lot_detail(lid)

    def lot_detail(self, lid: str, c=None) -> dict:
        def body(c):
            r = c.execute("SELECT * FROM mask_lot WHERE id=?", (lid,)).fetchone()
            if not r:
                raise MaskError("LOT_NOT_FOUND", f"lot 不存在: {lid}", 404)
            d = dict(r)
            d["windows"] = [dict(w) for w in c.execute(
                "SELECT * FROM mask_window WHERE lot_id=? ORDER BY start_ts", (lid,))]
            return d
        if c is not None:
            return body(c)
        with self.s.tx() as c:
            return body(c)

    def list_lots(self) -> list[dict]:
        return [self.lot_detail(r["id"]) for r in self.s.q_all(
            "SELECT id FROM mask_lot ORDER BY created_at")]

    def bind_lot(self, lot_id: str, mask_set_id: str, by: str, op_id: str | None = None) -> dict:
        self.require_user(by, "DISPATCHER")

        def work(c):
            return self._bind_tx(lot_id, mask_set_id, by, c), 200
        return self.idempotent(op_id, "lot.bind",
                               {"lot": lot_id, "set": mask_set_id, "by": by}, work)[0]

    def _bind_tx(self, lot_id, set_id, by, c=None):
        with self.s.using_tx(c) as c:
            lot = c.execute("SELECT * FROM mask_lot WHERE id=?", (lot_id,)).fetchone()
            if not lot:
                raise MaskError("LOT_NOT_FOUND", f"lot 不存在: {lot_id}", 404)
            if not c.execute("SELECT 1 FROM mask_set WHERE id=?", (set_id,)).fetchone():
                raise MaskError("SET_NOT_FOUND", f"mask set 不存在: {set_id}", 404)
            now = utcnow()
            active_windows = c.execute(
                "SELECT COUNT(*) n FROM mask_window WHERE lot_id=? AND state!='CANCELLED'",
                (lot_id,)).fetchone()["n"]
            if lot["status"] in ("EXPOSING", "EXPOSED"):
                # 唯一合法例外：为该 lot 已建的 delta 返工计划
                plan = c.execute(
                    "SELECT * FROM mask_rework WHERE lot_id=? AND status='READY' "
                    "AND delta_set_id=? ORDER BY created_at DESC LIMIT 1",
                    (lot_id, set_id)).fetchone()
                if not plan:
                    raise MaskError("LOT_EXPOSURE_STARTED",
                                    "lot 已开始曝光，原 mask set 永久封存；只能通过返工计划"
                                    "绑定 delta set", 409)
            elif active_windows:
                # 重新绑定前必须先取消既有排程
                winner = c.execute(
                    "SELECT op_id FROM mask_arbitration WHERE resource=? AND decision='WIN' "
                    "ORDER BY decided_at DESC LIMIT 1", (f"lot:{lot_id}",)).fetchone()
                c.execute(
                    "INSERT INTO mask_arbitration(id,op_id,resource,contender,decision,reason,"
                    "decided_at) VALUES(?,?,?,?,'LOSE','LOT_ALREADY_BOUND',?)",
                    (self._new_id("ARB"), f"bind:{lot_id}:{set_id}", f"lot:{lot_id}", by, now))
                raise MaskError("LOT_ALREADY_BOUND",
                                "同一 lot 只能有一个当前 mask set；请先取消现有排程再改绑",
                                409, {"current_mask_set": lot["mask_set_id"]})
            tip = self._tip_node(c, set_id)
            c.execute("UPDATE mask_lot SET mask_set_id=?,current_node_id=?,bound_at=?,"
                      "status=CASE WHEN status='CREATED' THEN 'SCHEDULED' ELSE status END "
                      "WHERE id=?", (set_id, tip["id"], now, lot_id))
            c.execute(
                "INSERT INTO mask_arbitration(id,op_id,resource,contender,decision,reason,"
                "decided_at) VALUES(?,?,?,?,'WIN',NULL,?)",
                (self._new_id("ARB"), f"bind:{lot_id}:{set_id}", f"lot:{lot_id}", by, now))
            self._audit(c, "lot.bind", lot_id, by, detail={"set": set_id, "node": tip["id"]})
            lot_id_out = lot_id
        return self.lot_detail(lot_id_out, c)

    def _record_lose(self, c, resource, contender, reason, window_id=None, op_id=None):
        c.execute(
            "INSERT INTO mask_arbitration(id,op_id,resource,contender,decision,reason,window_id,"
            "decided_at) VALUES(?,?,?,?,'LOSE',?,?,?)",
            (self._new_id("ARB"), op_id or self._new_id("OP"), resource, contender, reason,
             window_id, utcnow()))

    def book_window(self, lot_id: str, machine_id: str, node_id: str, slot: str,
                    start_ts: str, end_ts: str, by: str, op_id: str) -> dict:
        """调度员预订曝光窗口。op_id 必填：同编号安全重试，并发抢占唯一赢家。"""
        self.require_user(by, "DISPATCHER")
        if not op_id:
            raise MaskError("OP_REQUIRED", "预订窗口必须携带操作编号以支持安全重试", 400)
        start, end = norm_ts(start_ts), norm_ts(end_ts)
        if not start < end:
            raise MaskError("BAD_REQUEST", "窗口开始必须早于结束", 400)

        def work(c):
            return self._book_tx(lot_id, machine_id, node_id, slot, start, end, by, op_id, c), 201
        return self.idempotent(op_id, "window.book",
                               {"lot": lot_id, "machine": machine_id, "node": node_id,
                                "slot": slot, "start": start, "end": end, "by": by}, work)[0]

    def _book_tx(self, lot_id, machine_id, node_id, slot, start, end, by, op_id, c=None):
        with self.s.using_tx(c) as c:
            lot = c.execute("SELECT * FROM mask_lot WHERE id=?", (lot_id,)).fetchone()
            if not lot:
                raise MaskError("LOT_NOT_FOUND", f"lot 不存在: {lot_id}", 404)
            machine = c.execute("SELECT * FROM mask_machine WHERE id=?",
                                (machine_id,)).fetchone()
            if not machine or not machine["enabled"]:
                raise MaskError("MACHINE_NOT_FOUND", f"曝光机不可用: {machine_id}", 404)
            node = c.execute("SELECT * FROM mask_node WHERE id=?", (node_id,)).fetchone()
            if not node:
                raise MaskError("NODE_NOT_FOUND", f"谱系节点不存在: {node_id}", 404)
            now = utcnow()
            # 重放窗口（崩溃/重试时窗口已存在）
            existing = c.execute("SELECT * FROM mask_window WHERE op_id=?", (op_id,)).fetchone() \
                if op_id else None
            if existing:
                return dict(existing)

            # lot 必须绑定包含该节点的当前 mask set
            bound_sets = {lot["mask_set_id"]}
            if lot["status"] in ("EXPOSING", "EXPOSED"):
                for r in c.execute(
                        "SELECT delta_set_id FROM mask_rework WHERE lot_id=? AND status='READY'",
                        (lot_id,)):
                    bound_sets.add(r["delta_set_id"])
            if node["mask_set_id"] not in bound_sets:
                raise MaskError("LOT_SET_MISMATCH",
                                "节点不属于该 lot 当前绑定的 mask set", 409,
                                {"lot_set": lot["mask_set_id"], "node_set": node["mask_set_id"]})
            slots = self._node_slots(c, node_id)
            if slot not in slots:
                raise MaskError("SLOT_NOT_IN_NODE", f"节点 {node_id} 不含槽位 {slot}", 404)
            if node["status"] == "SUPERSEDED":
                raise MaskError("NODE_SUPERSEDED", "该节点已被修正版取代，不能再排程", 409)
            if node["status"] == "SEALED" and node["kind"] != "DELTA":
                raise MaskError("NODE_SEALED", "节点已随曝光永久封存，不能新增窗口", 409)
            dup = c.execute(
                "SELECT 1 FROM mask_window WHERE lot_id=? AND node_id=? AND slot=? AND state IN "
                "('PLANNED','EXPOSED')", (lot_id, node_id, slot)).fetchone()
            if dup:
                raise MaskError("WINDOW_ALREADY_BOOKED",
                                f"该 lot 的 {node_id}/{slot} 已有有效窗口", 409)

            # 先后次序：同 lot 内，父节点的版图层槽位必须已排程且结束不晚于本窗口开始。
            # 仅版图层（L..）实际需要曝光；layermap/recipe/die/scribe/corner 元数据不排窗口。
            for r in c.execute("SELECT parent_node_id FROM mask_node_edge WHERE child_node_id=?",
                               (node_id,)):
                pid = r["parent_node_id"]
                pslots = [s for s in self._node_slots(c, pid) if s.startswith("L")]
                for ps in pslots:
                    w = c.execute(
                        "SELECT * FROM mask_window WHERE lot_id=? AND node_id=? AND slot=? "
                        "AND state!='CANCELLED' ORDER BY start_ts", (lot_id, pid, ps)).fetchall()
                    if not w:
                        self._record_lose(c, f"machine:{machine_id}", by,
                                          "WINDOW_ORDER_VIOLATION", op_id=op_id)
                        raise MaskError("WINDOW_ORDER_VIOLATION",
                                        f"父节点 {pid} 的槽位 {ps} 尚未排程，"
                                        "主版/修正版/派生层必须遵守先后次序（依赖倒置）", 409,
                                        {"parent_node": pid, "parent_slot": ps})
                    if w[-1]["end_ts"] > start:
                        self._record_lose(c, f"machine:{machine_id}", by,
                                          "WINDOW_ORDER_VIOLATION", op_id=op_id)
                        raise MaskError("WINDOW_ORDER_VIOLATION",
                                        f"窗口早于父节点 {pid}/{ps} 的曝光完成时间"
                                        f"（{w[-1]['end_ts']}），违反先后次序", 409,
                                        {"parent_node": pid, "parent_slot": ps,
                                         "parent_end": w[-1]["end_ts"], "start": start})

            # 机器时间排他：半开区间 [start, end)
            clash = c.execute(
                "SELECT * FROM mask_window WHERE machine_id=? AND state!='CANCELLED' AND "
                "start_ts < ? AND end_ts > ? LIMIT 1", (machine_id, end, start)).fetchone()
            if clash:
                self._record_lose(c, f"machine:{machine_id}", by, "WINDOW_OVERLAP",
                                  clash["id"], op_id)
                raise MaskError("WINDOW_OVERLAP",
                                f"曝光机 {machine_id} 在 {start} ~ {end} 已被窗口 "
                                f"{clash['id']}（{clash['start_ts']}~{clash['end_ts']}）占用",
                                409, {"machine_id": machine_id, "winner_window": clash["id"],
                                      "winner_op": clash["op_id"], "start": start, "end": end})

            wid = self._new_id("WIN")
            c.execute(
                "INSERT INTO mask_window(id,op_id,machine_id,lot_id,node_id,slot,start_ts,end_ts,"
                "state,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,'PLANNED',?,?)",
                (wid, op_id, machine_id, lot_id, node_id, slot, start, end, by, now))
            c.execute(
                "INSERT INTO mask_arbitration(id,op_id,resource,contender,decision,reason,"
                "window_id,decided_at) VALUES(?,?,?,?,'WIN',NULL,?,?)",
                (self._new_id("ARB"), op_id, f"machine:{machine_id}", by, wid, now))
            self._audit(c, "window.book", wid, by, op_id=op_id,
                        detail={"machine": machine_id, "lot": lot_id, "node": node_id,
                                "slot": slot, "start": start, "end": end})
            return dict(c.execute("SELECT * FROM mask_window WHERE id=?", (wid,)).fetchone())

    def cancel_window(self, window_id: str, by: str) -> dict:
        self.require_user(by, "DISPATCHER")
        with self.s.tx() as c:
            w = c.execute("SELECT * FROM mask_window WHERE id=?", (window_id,)).fetchone()
            if not w:
                raise MaskError("WINDOW_NOT_FOUND", f"窗口不存在: {window_id}", 404)
            if w["state"] == "CANCELLED":
                return dict(w)
            if w["state"] == "EXPOSED":
                raise MaskError("WINDOW_EXPOSED", "已曝光窗口不能取消", 409)
            c.execute("UPDATE mask_window SET state='CANCELLED' WHERE id=?", (window_id,))
            self._audit(c, "window.cancel", window_id, by)
            return dict(c.execute("SELECT * FROM mask_window WHERE id=?",
                                  (window_id,)).fetchone())

    def expose_window(self, window_id: str, by: str) -> dict:
        self.require_user(by, "DISPATCHER")
        with self.s.tx() as c:
            w = c.execute("SELECT * FROM mask_window WHERE id=?", (window_id,)).fetchone()
            if not w:
                raise MaskError("WINDOW_NOT_FOUND", f"窗口不存在: {window_id}", 404)
            if w["state"] == "EXPOSED":
                return dict(w)
            if w["state"] == "CANCELLED":
                raise MaskError("WINDOW_CANCELLED", "窗口已取消，不能曝光", 409)
            now = utcnow()
            c.execute("UPDATE mask_window SET state='EXPOSED',exposed_at=? WHERE id=?",
                      (now, window_id))
            # lot 开始曝光 → 当前 mask set 全部节点永久封存
            lot = c.execute("SELECT * FROM mask_lot WHERE id=?", (w["lot_id"],)).fetchone()
            first_exposure = lot["status"] not in ("EXPOSING", "EXPOSED")
            c.execute("UPDATE mask_lot SET status='EXPOSING',started_at=COALESCE(started_at,?) "
                      "WHERE id=?", (now, w["lot_id"]))
            if first_exposure and lot["mask_set_id"]:
                c.execute("UPDATE mask_node SET status='SEALED',sealed_at=COALESCE(sealed_at,?) "
                          "WHERE mask_set_id=? AND status='ACTIVE'",
                          (now, lot["mask_set_id"]))
            self._audit(c, "window.expose", window_id, by, detail={"lot": w["lot_id"]})
            # 全部槽位曝光完成 → lot EXPOSED
            node = c.execute("SELECT * FROM mask_node WHERE id=?", (w["node_id"],)).fetchone()
            total = c.execute("SELECT COUNT(*) n FROM mask_node_slot WHERE node_id=?",
                              (w["node_id"],)).fetchone()["n"]
            done = c.execute(
                "SELECT COUNT(DISTINCT slot) n FROM mask_window WHERE node_id=? AND state='EXPOSED'",
                (w["node_id"],)).fetchone()["n"]
            if total == done and node["kind"] != "DELTA":
                c.execute("UPDATE mask_lot SET status='EXPOSED',completed_at=? WHERE id=?",
                          (now, w["lot_id"]))
            return dict(c.execute("SELECT * FROM mask_window WHERE id=?",
                                  (window_id,)).fetchone())

    def list_windows(self, machine_id=None, lot_id=None) -> list[dict]:
        sql = "SELECT * FROM mask_window WHERE 1=1"
        args = []
        if machine_id:
            sql += " AND machine_id=?"; args.append(machine_id)
        if lot_id:
            sql += " AND lot_id=?"; args.append(lot_id)
        return [dict(r) for r in self.s.q_all(sql + " ORDER BY start_ts", args)]

    def list_machines(self) -> list[dict]:
        return [dict(r) for r in self.s.q_all("SELECT * FROM mask_machine ORDER BY id")]

    def arbitrations(self, resource=None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM mask_arbitration"
        args = []
        if resource:
            sql += " WHERE resource=?"; args.append(resource)
        return [dict(r) for r in self.s.q_all(
            sql + " ORDER BY decided_at DESC LIMIT ?", args + [limit])]

    # ============ 双角色批准替换 ============
    def request_replacement(self, release_id: str, mask_set_id: str, node_id: str, slot: str,
                            name: str, data: bytes, declared_sha256: str | None,
                            requested_by: str, reason: str,
                            op_id: str | None = None) -> dict:
        self.require_user(requested_by)

        def work(c):
            return self._replace_request_tx(release_id, mask_set_id, node_id, slot, name, data,
                                            declared_sha256, requested_by, reason, c), 201
        return self.idempotent(op_id, "replacement.request",
                               {"set": mask_set_id, "node": node_id, "slot": slot, "name": name,
                                "by": requested_by, "reason": reason,
                                "sha256": sha256_hex(data)}, work)[0]

    def _assert_set_not_exposing(self, c, set_id):
        row = c.execute(
            "SELECT l.id,l.status FROM mask_lot l WHERE l.mask_set_id=? AND l.status IN "
            "('EXPOSING','EXPOSED') LIMIT 1", (set_id,)).fetchone()
        if row:
            raise MaskError("EXPOSURE_STARTED",
                            f"lot {row['id']} 已开始曝光，节点永久封存，禁止原地替换；"
                            "只能创建 delta set 与返工计划", 409, {"lot": row["id"]})

    def _replace_request_tx(self, release_id, set_id, node_id, slot, name, data,
                            declared_sha256, by, reason, c=None):
        with self.s.using_tx(c) as c:
            s = c.execute("SELECT * FROM mask_set WHERE id=?", (set_id,)).fetchone()
            if not s:
                raise MaskError("SET_NOT_FOUND", f"mask set 不存在: {set_id}", 404)
            if s["release_id"] != release_id:
                raise MaskError("SET_RELEASE_MISMATCH", "mask set 不属于该发行", 409)
            node = c.execute("SELECT * FROM mask_node WHERE id=?", (node_id,)).fetchone()
            if not node:
                raise MaskError("NODE_NOT_FOUND", f"谱系节点不存在: {node_id}", 404)
            if node["mask_set_id"] != set_id:
                raise MaskError("NODE_SET_MISMATCH", "节点不属于该 mask set", 409)
            self._assert_set_not_exposing(c, set_id)
            if node["status"] == "SEALED":
                raise MaskError("NODE_SEALED", "节点已封存，只能走 delta 返工", 409)
            cur = c.execute(
                "SELECT * FROM mask_node_slot WHERE node_id=? AND slot=?", (node_id, slot)
            ).fetchone()
            if not cur:
                raise MaskError("SLOT_NOT_IN_NODE", f"节点不含槽位 {slot}", 404)
            old = c.execute("SELECT * FROM mask_artifact WHERE id=?",
                            (cur["artifact_id"],)).fetchone()
            # 同内容替换无意义
            if sha256_hex(data) == old["sha256"]:
                raise MaskError("REPLACEMENT_NO_CHANGE",
                                "新构件与当前构件摘要完全相同，无需替换", 409)
            art = self._add_artifact_tx(release_id, old["kind"], name, data, declared_sha256,
                                        by, cur["layer_no"], allow_version=True, c=c)
            rid = self._new_id("RPL")
            c.execute(
                "INSERT INTO mask_replacement(id,mask_set_id,node_id,slot,old_artifact_id,"
                "new_artifact_id,requested_by,status,reason,created_at)"
                " VALUES(?,?,?,?,?,?,?,'PENDING',?,?)",
                (rid, set_id, node_id, slot, old["id"], art["id"], by, reason, utcnow()))
            self._audit(c, "replacement.request", rid, by,
                        detail={"set": set_id, "node": node_id, "slot": slot})
            return dict(c.execute("SELECT * FROM mask_replacement WHERE id=?", (rid,)).fetchone())

    def approve_replacement(self, replacement_id: str, role: str, user: str) -> dict:
        if role not in ("ME", "LO"):
            raise MaskError("BAD_REQUEST", "批准角色必须是 ME(制造工程师) 或 LO(版图负责人)",
                            400)
        other_role = "LO" if role == "ME" else "ME"
        # 先在事务内判定同一自然人：即使该用户不具备当前角色，只要他已以另一角色签过，
        # 首要拒绝原因是“批准者不能是同一自然人”（穿透角色的禁令）。
        with self.s.tx() as c:
            r0 = c.execute("SELECT * FROM mask_replacement WHERE id=?",
                           (replacement_id,)).fetchone()
            if not r0:
                raise MaskError("REPLACEMENT_NOT_FOUND", f"替换申请不存在: {replacement_id}",
                                404)
            signed_other = r0["lo_user"] if role == "ME" else r0["me_user"]
            if signed_other == user:
                self.s.audit(c, "replacement.approve.denied", replacement_id, user,
                             result="DENIED", reason="APPROVER_CONFLICT",
                             detail={"role": role})
                raise MaskError("APPROVER_CONFLICT",
                                "两名批准者不能是同一自然人（制造工程师与版图负责人）", 409)
        need = "MANUFACTURING_ENGINEER" if role == "ME" else "LAYOUT_OWNER"
        u = self.require_user(user, need)
        with self.s.tx() as c:
            r = c.execute("SELECT * FROM mask_replacement WHERE id=?",
                          (replacement_id,)).fetchone()
            if r["status"] != "PENDING":
                raise MaskError("REPLACEMENT_CLOSED", f"替换申请已 {r['status']}", 409)
            if role == "ME":
                if r["me_user"]:
                    raise MaskError("ALREADY_APPROVED", "制造工程师已批准", 409)
                c.execute("UPDATE mask_replacement SET me_user=?,me_at=? WHERE id=?",
                          (user, utcnow(), replacement_id))
            else:
                if r["lo_user"]:
                    raise MaskError("ALREADY_APPROVED", "版图负责人已批准", 409)
                c.execute("UPDATE mask_replacement SET lo_user=?,lo_at=? WHERE id=?",
                          (user, utcnow(), replacement_id))
            self._audit(c, "replacement.approve", replacement_id, user,
                        detail={"role": role, "user_name": u["name"]})
            r = c.execute("SELECT * FROM mask_replacement WHERE id=?",
                          (replacement_id,)).fetchone()
            if r["me_user"] and r["lo_user"]:
                return self._execute_replacement(c, r)
            return dict(r)

    def _execute_replacement(self, c, r) -> dict:
        """双签齐备：再次确认未曝光 → 产生 REVISION 谱系节点并重算下游排程。"""
        self._assert_set_not_exposing(c, r["mask_set_id"])
        now = utcnow()
        old_node = c.execute("SELECT * FROM mask_node WHERE id=?", (r["node_id"],)).fetchone()
        # 新节点继承旧节点全部槽位，仅替换一个构件
        seq = c.execute("SELECT MAX(seq) m FROM mask_node WHERE mask_set_id=?",
                        (r["mask_set_id"],)).fetchone()["m"] + 1
        nid = self._new_id("NODE")
        new_art = c.execute("SELECT * FROM mask_artifact WHERE id=?",
                            (r["new_artifact_id"],)).fetchone()
        c.execute(
            "INSERT INTO mask_node(id,mask_set_id,seq,kind,label,status,reason,created_by,"
            "created_at) VALUES(?,?,?,'REVISION',?,'ACTIVE',?, ?,?)",
            (nid, r["mask_set_id"], seq,
             f"修正版 R{seq}（{r['slot']} 替换）", f"replace {r['slot']}", r["requested_by"], now))
        for sr in c.execute("SELECT * FROM mask_node_slot WHERE node_id=?", (r["node_id"],)):
            aid = r["new_artifact_id"] if sr["slot"] == r["slot"] else sr["artifact_id"]
            c.execute("INSERT INTO mask_node_slot(node_id,slot,artifact_id,layer_no) VALUES(?,?,?,?)",
                      (nid, sr["slot"], aid, sr["layer_no"]))
        # 谱系/排程边：新节点接管旧节点在依赖 DAG 中的位置。
        # 旧节点的入边（父→旧）改挂到新节点；旧节点的出边（旧→子）也改挂到新节点。
        # 旧节点不再参与排程 DAG（其窗口已随取代全部取消）；
        # 「修正版替代谁」的血缘由 mask_replacement.node_id→new_node_id 承载。
        old_parents = [pr["parent_node_id"] for pr in c.execute(
            "SELECT parent_node_id FROM mask_node_edge WHERE child_node_id=?",
            (r["node_id"],))]
        old_children = [cr["child_node_id"] for cr in c.execute(
            "SELECT child_node_id FROM mask_node_edge WHERE parent_node_id=?",
            (r["node_id"],))]
        c.execute("DELETE FROM mask_node_edge WHERE parent_node_id=? OR child_node_id=?",
                  (r["node_id"], r["node_id"]))
        for pid in old_parents:
            c.execute("INSERT OR IGNORE INTO mask_node_edge(parent_node_id,child_node_id) VALUES(?,?)",
                      (pid, nid))
        for child in old_children:
            c.execute("INSERT OR IGNORE INTO mask_node_edge(parent_node_id,child_node_id) VALUES(?,?)",
                      (nid, child))
        c.execute("UPDATE mask_node SET status='SUPERSEDED' WHERE id=?", (r["node_id"],))

        # 重算下游排程：旧节点及其后代（=新节点接管后的全部下游）PLANNED 窗口取消。
        # 未曝光才允许替换，故这些节点不存在 EXPOSED 窗口。
        old_descendants = self._descendants(c, r["node_id"])
        affected = {r["node_id"]} | old_descendants
        cancelled = []
        for w in c.execute(
                "SELECT * FROM mask_window WHERE state='PLANNED' AND node_id IN (%s)" %
                ",".join("?" * len(affected)), tuple(affected)):
            c.execute("UPDATE mask_window SET state='CANCELLED' WHERE id=?", (w["id"],))
            cancelled.append({"window_id": w["id"], "lot_id": w["lot_id"], "node_id": w["node_id"],
                              "slot": w["slot"], "machine_id": w["machine_id"],
                              "start_ts": w["start_ts"], "end_ts": w["end_ts"],
                              "reason": "SUPERSEDED_BY_REVISION"})
        c.execute("UPDATE mask_replacement SET status='DONE',new_node_id=? WHERE id=?",
                  (nid, r["id"]))
        # lot 跟随到最新节点
        c.execute("UPDATE mask_lot SET current_node_id=? WHERE mask_set_id=?",
                  (nid, r["mask_set_id"]))
        self._audit(c, "replacement.execute", r["id"], actor=r["requested_by"],
                    detail={"new_node": nid, "me": r["me_user"], "lo": r["lo_user"],
                            "cancelled_windows": len(cancelled)})
        out = dict(c.execute("SELECT * FROM mask_replacement WHERE id=?", (r["id"],)).fetchone())
        out["new_node"] = self.node_detail(nid, c)
        out["reschedule_required"] = cancelled
        return out

    def list_replacements(self, set_id=None) -> list[dict]:
        sql = "SELECT * FROM mask_replacement"
        args = ()
        if set_id:
            sql += " WHERE mask_set_id=?"; args = (set_id,)
        return [dict(r) for r in self.s.q_all(sql + " ORDER BY created_at", args)]

    # ============ 曝光后 delta 返工 ============
    def create_rework(self, lot_id: str, reason: str, by: str, changes: list[dict],
                      op_id: str | None = None) -> dict:
        """changes: [{slot, name, data:bytes, declared_sha256?}]；仅曝光后可用。"""
        self.require_user(by, "MANUFACTURING_ENGINEER")
        if not changes:
            raise MaskError("BAD_REQUEST", "返工计划至少包含一个变更槽位", 400)

        def work(c):
            return self._rework_tx(lot_id, reason, by, changes, c), 201
        return self.idempotent(op_id, "rework.create",
                               {"lot": lot_id, "reason": reason, "by": by,
                                "changes": [{"slot": x["slot"], "name": x["name"],
                                             "sha256": sha256_hex(x.get("data", b""))}
                                            for x in changes]}, work)[0]

    def _rework_tx(self, lot_id, reason, by, changes, c=None):
        with self.s.using_tx(c) as c:
            lot = c.execute("SELECT * FROM mask_lot WHERE id=?", (lot_id,)).fetchone()
            if not lot:
                raise MaskError("LOT_NOT_FOUND", f"lot 不存在: {lot_id}", 404)
            if lot["status"] not in ("EXPOSING", "EXPOSED"):
                raise MaskError("EXPOSURE_NOT_STARTED",
                                "lot 尚未开始曝光；未曝光的单构件修改应走双签替换", 409)
            if not lot["mask_set_id"]:
                raise MaskError("LOT_NOT_BOUND", "lot 未绑定 mask set", 409)
            parent_set = c.execute("SELECT * FROM mask_set WHERE id=?",
                                   (lot["mask_set_id"],)).fetchone()
            tip = c.execute("SELECT * FROM mask_node WHERE id=?",
                            (lot["current_node_id"],)).fetchone()
            parent_slots = set(self._node_slots(c, tip["id"]).keys())
            seen = set()
            for ch in changes:
                if ch["slot"] not in parent_slots:
                    raise MaskError("SLOT_NOT_IN_NODE",
                                    f"delta 只能修改封存节点已有槽位，{ch['slot']} 不在其中", 404)
                if ch["slot"] in seen:
                    raise MaskError("BAD_REQUEST", f"槽位 {ch['slot']} 重复出现", 400)
                seen.add(ch["slot"])
            ndelta = c.execute(
                "SELECT COUNT(*) n FROM mask_set WHERE release_id=? AND kind='DELTA'",
                (parent_set["release_id"],)).fetchone()["n"] + 1
            sid = self._new_id("SET")
            now = utcnow()
            c.execute("INSERT INTO mask_set(id,release_id,name,kind,created_at,created_by)"
                      " VALUES(?,?,?,'DELTA',?,?)",
                      (sid, parent_set["release_id"], f"{parent_set['name']}-D{ndelta}", now, by))
            nid = self._new_id("NODE")
            c.execute("INSERT INTO mask_node(id,mask_set_id,seq,kind,label,status,reason,"
                      "created_by,created_at) VALUES(?,? ,1,'DELTA',?,? ,?, ?,?)",
                      (nid, sid, f"{parent_set['name']} 返工 delta D{ndelta}", reason,
                       "rework", by, now))
            for ch in changes:
                art = self._add_artifact_tx(parent_set["release_id"], "layout", ch["name"],
                                            ch["data"], ch.get("declared_sha256"), by,
                                            int(ch["slot"][1:]), allow_version=True, c=c)
                c.execute("INSERT INTO mask_node_slot(node_id,slot,artifact_id,layer_no) VALUES(?,?,?,?)",
                          (nid, ch["slot"], art["id"], int(ch["slot"][1:])))
            c.execute("INSERT INTO mask_node_edge(parent_node_id,child_node_id) VALUES(?,?)",
                      (tip["id"], nid))
            rwid = self._new_id("RW")
            c.execute(
                "INSERT INTO mask_rework(id,lot_id,sealed_node_id,delta_set_id,delta_node_id,"
                "reason,requested_by,status,created_at) VALUES(?,?,?,?,?,?,?,'READY',?)",
                (rwid, lot_id, tip["id"], sid, nid, reason, by, now))
            self._audit(c, "rework.create", rwid, by,
                        detail={"lot": lot_id, "delta_set": sid, "slots": list(seen)})
            out = dict(c.execute("SELECT * FROM mask_rework WHERE id=?", (rwid,)).fetchone())
            out["delta_set"] = self.mask_set_detail(sid, c)
            return out

    def list_reworks(self) -> list[dict]:
        return [dict(r) for r in self.s.q_all(
            "SELECT * FROM mask_rework ORDER BY created_at")]

    # ============ 审计 ============
    def audit_log(self, entity=None, action=None, op_id=None, limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM mask_audit WHERE 1=1"
        args = []
        if entity:
            sql += " AND entity=?"; args.append(entity)
        if action:
            sql += " AND action=?"; args.append(action)
        if op_id:
            sql += " AND op_id=?"; args.append(op_id)
        rows = self.s.q_all(sql + " ORDER BY seq DESC LIMIT ?", args + [limit])
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.pop("detail_json"))
            out.append(d)
        return out

    # ============ 崩溃恢复 ============
    def recover_pending_ops(self) -> dict:
        """进程异常退出后，把停留在 PENDING 的操作编号标记为 INTERRUPTED 并留痕。

        语义：
        - 业务写入与 DONE 在同一事务提交，因此崩溃时业务要么已随 COMMIT 生效
          （此时不可能是 PENDING），要么整体回滚；PENDING 一定代表业务未生效；
        - 标记后客户端可以用**原操作编号**安全重试：窗口/构件的唯一约束和
          内容寻址会再次兜底，绝不产生重复占用或重复实体；
        - 打包作业的续传由 ExportService.recover() 独立负责。
        """
        recovered = []
        with self.s.tx() as c:
            rows = c.execute("SELECT * FROM mask_op WHERE status='PENDING'").fetchall()
            for r in rows:
                c.execute("UPDATE mask_op SET status='INTERRUPTED' WHERE op_id=?",
                          (r["op_id"],))
                self.s.audit(c, "op.recover", None, None, "OK", "INTERRUPTED", r["op_id"],
                             {"kind": r["kind"]})
                recovered.append(r["op_id"])
        return {"interrupted_ops": recovered, "count": len(recovered)}
