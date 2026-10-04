"""导入器：校验 GDS/OASIS、层映射、die/scribe、工艺角、晶圆厂 recipe，
规范化后生成稳定交付编号；不一致逐条定位到具体构件。"""
from __future__ import annotations

import json
import secrets
from typing import Any

from .domain import (DomainError, canonical_hash, delivery_number,
                     parse_layer_inventory, scan_gds_layers, LayoutScanError)
from .store import CasError, Store, utcnow

ROLE_RANK = {"MASTER": 0, "CORRECTED": 1, "DERIVED": 2}
ROLE_GDS = {"GDS", "OASIS"}
ROLE_DOCS = {"LAYERMAP", "RECIPE"}


def finding(severity: str, code: str, message: str, **locator):
    return {"severity": severity, "code": code, "message": message,
            "locator": dict(locator)}


class Importer:
    def __init__(self, store: Store):
        self.s = store

    # ------------------------------------------------------------------
    def run(self, packet: dict, actor: str) -> dict:
        """执行一次发行导入；返回 {release_id,status,delivery_no,findings,...}。

        成功与失败都落库（INVALID 也留痕，可追溯）。同规范化内容重复导入
        直接返回既有发行与 mask set，不复制任何实体。
        """
        findings: list[dict] = []
        entries, meta = self._parse_packet(packet, findings)

        # 逐构件校验（即使前面失败也尽量多收集定位信息）
        member_rows, layermap, recipe, inventory = self._check_entries(entries, findings)

        if recipe is not None:
            self._check_recipe_meta(meta, recipe, findings)
            masks = self._check_recipe_graph(recipe, findings)
            self._check_layermap(layermap, recipe, masks, inventory, findings)
            self._check_mask_files(entries, masks, findings, member_rows)
        if layermap is not None and inventory is not None:
            self._check_inventory_coverage(layermap, inventory, findings)

        valid = not any(f["severity"] == "error" for f in findings)

        build = {
            "release_name": meta.get("release_name"),
            "die_width_um": meta.get("die", {}).get("width_um"),
            "die_height_um": meta.get("die", {}).get("height_um"),
            "scribe_um": meta.get("scribe_um"),
            "corner": meta.get("corner"),
            "fab": meta.get("fab"),
            "foundry_recipe_id": meta.get("foundry_recipe_id"),
            "members": sorted(member_rows, key=lambda r: (r["role"], r["logical_name"])),
        }
        chash = canonical_hash(build)

        with self.s.tx() as c:
            existing = c.execute("SELECT * FROM release WHERE canonical_hash=?",
                                 (chash,)).fetchone()
            if existing:
                self.s.audit(c, actor, "release.reimport", existing["id"],
                             detail={"delivery_no": existing["delivery_no"]})
                return self._result(existing, replayed=True)

            rid = "REL-" + secrets.token_hex(6)
            # 同名异物：同发行名不同规范化内容 → 隔离等待处置
            name_collision = c.execute(
                "SELECT delivery_no FROM release WHERE name=? AND status IN ('VALID','QUARANTINED')"
                " ORDER BY imported_at DESC LIMIT 1",
                (meta.get("release_name"),)).fetchone()
            status = "VALID"
            if valid and name_collision:
                status = "QUARANTINED"
                findings.append(finding(
                    "error", "RELEASE_NAME_COLLISION",
                    f"发行名 {meta.get('release_name')} 已属于 {name_collision['delivery_no']}，"
                    "同名异物隔离等待处置",
                    type="release", id=meta.get("release_name"),
                    existing_delivery_no=name_collision["delivery_no"]))
                valid = False
            if not valid and status == "VALID":
                status = "INVALID"

            c.execute(
                "INSERT INTO release(id,name,status,delivery_no,canonical_hash,die_width_um,"
                "die_height_um,scribe_um,corner,fab,foundry_recipe_id,layer_count,"
                "findings_json,spec_json,imported_by,imported_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rid, meta.get("release_name"), status, None, chash,
                 meta.get("die", {}).get("width_um"), meta.get("die", {}).get("height_um"),
                 meta.get("scribe_um"), meta.get("corner"), meta.get("fab"),
                 meta.get("foundry_recipe_id"),
                 len(layermap.get("mappings", [])) if layermap else 0,
                 json.dumps(findings, ensure_ascii=False),
                 json.dumps(build, ensure_ascii=False, sort_keys=True),
                 actor, utcnow()))
            for m in member_rows:
                c.execute(
                    "INSERT OR REPLACE INTO release_artifact(release_id,role,logical_name,sha256)"
                    " VALUES(?,?,?,?)",
                    (rid, m["role"], m["logical_name"], m["sha256"]))

            set_row = None
            if status == "VALID":
                set_row = self._create_master_set(c, rid, build, recipe, actor)
                c.execute("UPDATE release SET delivery_no=? WHERE id=?",
                          (set_row["delivery_no"], rid))
            elif name_collision:
                qid = "QRN-" + secrets.token_hex(5)
                c.execute(
                    "INSERT INTO quarantine(id,logical_name,sha256,existing_sha,kind,size,"
                    "reason,blob_path,detected_by,detected_at,status)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (qid, meta.get("release_name"), chash,
                     None, "RELEASE", 0, "RELEASE_NAME_COLLISION", "-",
                     actor, utcnow(), "PENDING"))
            self.s.audit(c, actor, "release.import", rid,
                         detail={"status": status, "findings": len(findings)})
            row = c.execute("SELECT * FROM release WHERE id=?", (rid,)).fetchone()
            return self._result(row, findings_override=findings,
                                set_id=set_row["id"] if set_row else None,
                                set_delivery=set_row["delivery_no"] if set_row else None)

    # ------------------------------------------------------------------
    def _parse_packet(self, packet: Any, findings: list[dict]) -> tuple[list[dict], dict]:
        if not isinstance(packet, dict):
            raise DomainError("INVALID_PACKET", "导入包必须是 JSON 对象", 400)
        meta_keys = ("release_name", "die", "scribe_um", "corner", "fab", "foundry_recipe_id")
        meta = {k: packet.get(k) for k in meta_keys}
        if not isinstance(meta["release_name"], str) or not meta["release_name"].strip():
            findings.append(finding("error", "INVALID_PACKET", "缺少 release_name",
                                    type="packet", field="release_name"))
        die = packet.get("die")
        if not isinstance(die, dict):
            findings.append(finding("error", "INVALID_DIE", "die 必须是 {width_um,height_um}",
                                    type="packet", field="die"))
        else:
            for k in ("width_um", "height_um"):
                if not isinstance(die.get(k), (int, float)) or die[k] <= 0:
                    findings.append(finding("error", "INVALID_DIE",
                                            f"die.{k} 必须为正数", type="die", id=k))
        if not isinstance(packet.get("scribe_um"), (int, float)) or packet["scribe_um"] <= 0:
            findings.append(finding("error", "INVALID_SCRIBE", "scribe_um 必须为正数",
                                    type="scribe", id="scribe_um"))
        for key in ("corner", "fab", "foundry_recipe_id"):
            if not isinstance(meta[key], str) or not meta[key]:
                findings.append(finding("error", "INVALID_PACKET", f"缺少 {key}",
                                        type="packet", field=key))
        entries = packet.get("entries")
        if not isinstance(entries, list) or not entries:
            findings.append(finding("error", "INVALID_PACKET", "entries 必须是非空数组",
                                    type="packet", field="entries"))
            return [], meta
        seen_roles: dict[str, str] = {}
        for i, e in enumerate(entries):
            if not isinstance(e, dict):
                findings.append(finding("error", "INVALID_PACKET",
                                        f"entries[{i}] 必须是对象", type="entry", index=i))
                continue
            role, name, sha = e.get("role"), e.get("logical_name"), e.get("sha256")
            if not isinstance(role, str) or not role:
                findings.append(finding("error", "INVALID_PACKET",
                                        f"entries[{i}].role 缺失", type="entry", index=i))
                continue
            if not isinstance(name, str) or not name:
                findings.append(finding("error", "INVALID_PACKET",
                                        f"entries[{i}].logical_name 缺失",
                                        type="entry", role=role))
                continue
            if not isinstance(sha, str) or len(sha) != 64:
                findings.append(finding("error", "INVALID_PACKET",
                                        f"entries[{i}].sha256 必须是 64 位十六进制",
                                        type="entry", id=name))
                continue
            if role in seen_roles:
                findings.append(finding("error", "DUPLICATE_ROLE",
                                        f"角色 {role} 出现多次：{seen_roles[role]} 与 {name}",
                                        type="entry", id=name, role=role))
            seen_roles[role] = name
        if not any(r in seen_roles for r in ROLE_GDS):
            findings.append(finding("error", "MISSING_LAYOUT",
                                    "缺少 GDS 或 OASIS 版图构件", type="packet"))
        if all(r in seen_roles for r in ROLE_GDS):
            findings.append(finding("error", "MULTIPLE_LAYOUTS",
                                    "GDS 与 OASIS 不能同时作为主版图", type="packet"))
        if "LAYERMAP" not in seen_roles:
            findings.append(finding("error", "MISSING_LAYERMAP", "缺少层映射构件",
                                    type="packet"))
        if "RECIPE" not in seen_roles:
            findings.append(finding("error", "MISSING_RECIPE", "缺少晶圆厂 recipe 构件",
                                    type="packet"))
        return entries, meta

    # ------------------------------------------------------------------
    def _check_entries(self, entries, findings):
        """逐构件：登记状态、CAS 实体验证、摘要重算、layermap/recipe 解析、版图层扫描。"""
        member_rows, layermap, recipe, inventory = [], None, None, None
        for e in entries:
            role, name, sha = e["role"], e["logical_name"], e["sha256"].lower()
            loc = {"type": "entry", "id": name, "role": role}
            art = self.s.q_one("SELECT * FROM artifact WHERE sha256=?", (sha,))
            if art is None:
                qrow = self.s.q_one(
                    "SELECT status FROM quarantine WHERE sha256=? ORDER BY detected_at DESC",
                    (sha,))
                if qrow and qrow["status"] == "PENDING":
                    findings.append(finding("error", "ARTIFACT_QUARANTINED",
                                            f"构件 {name} 是同名异物，正隔离等待处置", **loc))
                elif qrow and qrow["status"] == "REJECTED":
                    findings.append(finding("error", "ARTIFACT_REJECTED",
                                            f"构件 {name} 已被隔离处置拒绝", **loc))
                else:
                    findings.append(finding("error", "ARTIFACT_NOT_REGISTERED",
                                            f"构件 {name}（{sha[:12]}…）未登记，请先上传内容",
                                            **loc))
                continue
            if art["status"] == "QUARANTINED":
                findings.append(finding("error", "ARTIFACT_QUARANTINED",
                                        f"构件 {name} 处于隔离状态", **loc))
                continue
            if not self.s.verify_blob(sha):
                findings.append(finding("error", "DIGEST_TAMPERED",
                                        f"构件 {name} 存储内容与登记摘要不一致（疑似篡改）",
                                        **loc, expected=sha))
                continue
            member_rows.append({"role": role, "logical_name": name, "sha256": sha})

            if role == "LAYERMAP":
                layermap = self._load_json(sha, name, "层映射", findings, loc)
            elif role == "RECIPE":
                recipe = self._load_json(sha, name, "晶圆厂 recipe", findings, loc)
            elif role == "GDS":
                try:
                    inventory = sorted(set(scan_gds_layers(self.s.get_blob(sha))))
                except LayoutScanError as ex:
                    findings.append(finding("error", "GDS_PARSE_ERROR",
                                            f"GDS 解析失败：{ex}", **loc))
                    inventory = []
                declared = e.get("layer_inventory")
                if declared is not None:
                    try:
                        declared = parse_layer_inventory(json.dumps(declared))
                    except (LayoutScanError, json.JSONDecodeError):
                        findings.append(finding("error", "INVENTORY_BAD_FORMAT",
                                                "随包 layer_inventory 格式错误", **loc))
                    else:
                        if inventory is not None and set(declared) != set(inventory):
                            findings.append(finding(
                                "error", "INVENTORY_MISMATCH",
                                f"声明层清单与 GDS 实扫不符：缺 "
                                f"{sorted(set(inventory) - set(declared))}，多 "
                                f"{sorted(set(declared) - set(inventory))}", **loc))
                        inventory = declared if inventory is None else inventory
            elif role == "OASIS":
                declared = e.get("layer_inventory")
                if not isinstance(declared, list) or not declared:
                    findings.append(finding("error", "LAYOUT_INVENTORY_MISSING",
                                            "OASIS 必须随附 layer_inventory 层清单", **loc))
                else:
                    try:
                        inventory = parse_layer_inventory(json.dumps(declared))
                    except (LayoutScanError, json.JSONDecodeError):
                        findings.append(finding("error", "INVENTORY_BAD_FORMAT",
                                                "layer_inventory 格式错误", **loc))
        return member_rows, layermap, recipe, inventory

    def _load_json(self, sha, name, label, findings, loc):
        try:
            obj = json.loads(self.s.get_blob(sha))
        except (json.JSONDecodeError, UnicodeDecodeError) as ex:
            findings.append(finding("error", "MALFORMED_JSON",
                                    f"{label} {name} 不是合法 JSON：{ex}", **loc))
            return None
        return obj

    # ------------------------------------------------------------------
    def _check_recipe_meta(self, meta, recipe, findings):
        rid = meta.get("foundry_recipe_id")
        if recipe.get("recipe_id") != rid:
            findings.append(finding("error", "RECIPE_MISMATCH",
                                    f"包 recipe_id={rid} 与 recipe 内 {recipe.get('recipe_id')} 不符",
                                    type="recipe", field="recipe_id"))
        if recipe.get("fab") != meta.get("fab"):
            findings.append(finding("error", "RECIPE_MISMATCH",
                                    f"包 fab={meta.get('fab')} 与 recipe 内 {recipe.get('fab')} 不符",
                                    type="recipe", field="fab"))
        corners = recipe.get("corners", [])
        if not isinstance(corners, list) or meta.get("corner") not in corners:
            findings.append(finding("error", "CORNER_NOT_IN_RECIPE",
                                    f"工艺角 {meta.get('corner')} 不在 recipe 允许列表 {corners}",
                                    type="recipe", field="corners"))

    def _check_recipe_graph(self, recipe, findings) -> dict[str, dict]:
        masks = recipe.get("masks")
        if not isinstance(masks, list) or not masks:
            findings.append(finding("error", "RECIPE_NO_MASKS", "recipe 缺少 masks",
                                    type="recipe"))
            return {}
        out: dict[str, dict] = {}
        for m in masks:
            name = m.get("name") if isinstance(m, dict) else None
            if not name:
                findings.append(finding("error", "RECIPE_BAD_MASK", "mask 缺少 name",
                                        type="recipe"))
                continue
            if name in out:
                findings.append(finding("error", "RECIPE_DUPLICATE_MASK",
                                        f"mask {name} 重复定义", type="mask", id=name))
                continue
            role_type = m.get("role_type")
            if role_type not in ROLE_RANK:
                findings.append(finding("error", "RECIPE_BAD_ROLE",
                                        f"mask {name} 的 role_type={role_type} 非法",
                                        type="mask", id=name))
                role_type = role_type or "MASTER"
            layer = m.get("layer")
            if not isinstance(layer, str) or not layer:
                findings.append(finding("error", "RECIPE_BAD_LAYER",
                                        f"mask {name} 缺少 layer", type="mask", id=name))
            deps = m.get("depends_on", [])
            if not isinstance(deps, list):
                findings.append(finding("error", "RECIPE_BAD_DEPS",
                                        f"mask {name} 的 depends_on 必须是数组",
                                        type="mask", id=name))
                deps = []
            out[name] = {"name": name, "role_type": role_type,
                         "layer": layer, "depends_on": deps}

        # 依赖存在性 + 先后次序（MASTER→CORRECTED→DERIVED 不可倒置）
        for name, m in out.items():
            for dep in m["depends_on"]:
                if dep not in out:
                    findings.append(finding("error", "DEPENDENCY_UNKNOWN_MASK",
                                            f"mask {name} 依赖不存在的 {dep}",
                                            type="mask", id=name, dependency=dep))
                    continue
                if ROLE_RANK[out[dep]["role_type"]] > ROLE_RANK[m["role_type"]]:
                    findings.append(finding(
                        "error", "DEPENDENCY_INVERSION",
                        f"依赖倒置：{m['role_type']} {name} 排在 {out[dep]['role_type']} {dep} 之前",
                        type="mask", id=name, dependency=dep))
            if m["role_type"] == "MASTER" and m["depends_on"]:
                findings.append(finding("error", "DEPENDENCY_INVERSION",
                                        f"主版 {name} 不应有前置依赖",
                                        type="mask", id=name))
            if m["role_type"] in ("CORRECTED", "DERIVED"):
                chain = self._reachable_masters(m, out)
                if chain is None:
                    findings.append(finding("error", "DEPENDENCY_INVERSION",
                                            f"{m['role_type']} {name} 的依赖链存在环",
                                            type="mask", id=name))
                elif not chain:
                    findings.append(finding("error", "MISSING_MASTER",
                                            f"{m['role_type']} {name} 的依赖链上游缺少主版",
                                            type="mask", id=name))
                # 修正版/派生层允许对应与主版不同的层（OPC、派生层各自有自己的层），
                # 约束的只是先后次序，不约束层号相同。
        # 环检测（全局，确保主版→修正版→派生层有确定先后次序）
        self._topo_order(out, findings)
        return out

    def _reachable_masters(self, m, masks):
        seen, stack = set(), list(m["depends_on"])
        masters = []
        while stack:
            cur = stack.pop()
            if cur in seen:
                return None          # 环
            seen.add(cur)
            if cur not in masks:
                continue
            if masks[cur]["role_type"] == "MASTER":
                masters.append(cur)
            stack.extend(masks[cur]["depends_on"])
        return masters

    def _topo_order(self, masks, findings) -> list[str]:
        """Kahn 拓扑排序；同层按 (角色次序, 名称) 保证确定结果。"""
        indeg = {n: 0 for n in masks}
        dependents: dict[str, list[str]] = {n: [] for n in masks}
        for n, m in masks.items():
            for d in m["depends_on"]:
                if d in masks:
                    indeg[n] += 1
                    dependents[d].append(n)
        ready = sorted([n for n, d in indeg.items() if d == 0],
                       key=lambda n: (ROLE_RANK[masks[n]["role_type"]], n))
        order = []
        while ready:
            n = ready.pop(0)
            order.append(n)
            for child in dependents[n]:
                indeg[child] -= 1
                if indeg[child] == 0:
                    ready.append(child)
            ready.sort(key=lambda x: (ROLE_RANK[masks[x]["role_type"]], x))
        if len(order) != len(masks):
            cyc = sorted(set(masks) - set(order))
            findings.append(finding("error", "DEPENDENCY_INVERSION",
                                    f"mask 依赖存在环：{cyc}", type="recipe",
                                    cycle=cyc))
        return order

    # ------------------------------------------------------------------
    def _check_layermap(self, layermap, recipe, masks, inventory, findings):
        if not isinstance(layermap, dict) or not isinstance(layermap.get("mappings"), list):
            findings.append(finding("error", "LAYERMAP_BAD_FORMAT",
                                    "层映射必须含 mappings 数组", type="layermap"))
            return
        map_layers, seen_pairs = set(), set()
        for i, mp in enumerate(layermap["mappings"]):
            if not isinstance(mp, dict):
                findings.append(finding("error", "LAYERMAP_BAD_FORMAT",
                                        f"mappings[{i}] 必须是对象", type="layermap", index=i))
                continue
            ll, mk = mp.get("layout_layer"), mp.get("mask")
            if not isinstance(ll, str) or not isinstance(mk, str):
                findings.append(finding("error", "LAYERMAP_BAD_FORMAT",
                                        f"mappings[{i}] 需要 layout_layer 与 mask",
                                        type="layermap", index=i))
                continue
            if (ll, mk) in seen_pairs:
                findings.append(finding("warning", "LAYERMAP_DUPLICATE",
                                        f"映射 {ll}→{mk} 重复",
                                        type="layer", id=ll, mask=mk))
            seen_pairs.add((ll, mk))
            map_layers.add(ll)
            if mk not in masks:
                findings.append(finding("error", "LAYERMAP_MASK_NOT_IN_RECIPE",
                                        f"层映射引用的 {mk} 不在 recipe 中",
                                        type="layer", id=ll, mask=mk))
            elif masks[mk]["layer"] != ll:
                findings.append(finding(
                    "error", "MASK_LAYER_MISMATCH",
                    f"层映射 {ll}→{mk} 与 recipe 中 {mk} 的层 {masks[mk]['layer']} 不一致",
                    type="mask", id=mk, layer=ll))
        # recipe 中每个 mask 的层都必须有层映射覆盖
        for name, m in masks.items():
            if m["layer"] and (m["layer"], name) not in seen_pairs:
                findings.append(finding("error", "MISSING_LAYER_MAPPING",
                                        f"recipe 的 mask {name}（{m['layer']}）缺少层映射",
                                        type="mask", id=name, layer=m["layer"]))

    def _check_inventory_coverage(self, layermap, inventory, findings):
        inv = set(inventory)
        mapped = {mp["layout_layer"] for mp in layermap["mappings"]
                  if isinstance(mp, dict) and isinstance(mp.get("layout_layer"), str)}
        for ll in sorted(mapped - inv):
            findings.append(finding("error", "LAYERMAP_LAYER_NOT_IN_LAYOUT",
                                    f"层映射的 {ll} 在 GDS/OASIS 中不存在（缺层/拿错版）",
                                    type="layer", id=ll))
        for ll in sorted(inv - mapped):
            findings.append(finding("warning", "UNMAPPED_LAYOUT_LAYER",
                                    f"版图层 {ll} 未被任何 mask 使用",
                                    type="layer", id=ll))

    def _check_mask_files(self, entries, masks, findings, member_rows):
        provided = {e["role"][5:]: e for e in entries
                    if isinstance(e.get("role"), str) and e["role"].startswith("MASK:")}
        # member_rows 里只保留了通过校验的条目
        ok_masks = {r["role"][5:]: r for r in member_rows if r["role"].startswith("MASK:")}
        for name in masks:
            if name not in provided:
                findings.append(finding("error", "MISSING_MASK_FILE",
                                        f"recipe mask {name} 缺少构件文件",
                                        type="mask", id=name))
            elif name not in ok_masks:
                pass  # 构件级错误已在 _check_entries 定位
        for extra in sorted(set(provided) - set(masks)):
            findings.append(finding("warning", "EXTRA_MASK_FILE",
                                    f"构件 {provided[extra]['logical_name']} 不对应 recipe 中的 mask",
                                    type="mask", id=extra))

    # ------------------------------------------------------------------
    def _create_master_set(self, c, release_id, build, recipe, actor) -> dict:
        masks = {m["name"]: m for m in recipe["masks"]}
        order = self._topo_order(masks, [])
        dno = delivery_number(c.execute(
            "SELECT canonical_hash FROM release WHERE id=?", (release_id,))
            .fetchone()[0])
        lineage_id = "LIN-" + secrets.token_hex(5)
        set_id = "ST-" + secrets.token_hex(6)
        layers_spec = [masks[n] for n in order]
        c.execute(
            "INSERT INTO mask_set(id,delivery_no,release_id,lineage_id,kind,seq,title,"
            "order_json,layers_json,created_by,created_at,status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (set_id, dno, release_id, lineage_id, "MASTER", 1,
             f"{build['release_name']} 主版",
             json.dumps(order, ensure_ascii=False),
             json.dumps(layers_spec, ensure_ascii=False, sort_keys=True),
             actor, utcnow(), "ACTIVE"))
        for n in order:
            m = masks[n]
            row = c.execute(
                "SELECT logical_name,sha256 FROM release_artifact WHERE release_id=? AND role=?",
                (release_id, f"MASK:{n}")).fetchone()
            c.execute(
                "INSERT INTO set_member(set_id,mask_name,role_type,layer,sha256,logical_name)"
                " VALUES(?,?,?,?,?,?)",
                (set_id, n, m["role_type"], m["layer"], row["sha256"], row["logical_name"]))
            for dep in m["depends_on"]:
                c.execute("INSERT INTO set_edge(set_id,src,dst,reason) VALUES(?,?,?,?)",
                          (set_id, dep, n, "recipe.depends_on"))
        return {"id": set_id, "delivery_no": dno}

    def _result(self, row, *, replayed=False, findings_override=None,
                set_id=None, set_delivery=None) -> dict:
        findings = findings_override or json.loads(row["findings_json"] or "[]")
        errors = sum(1 for f in findings if f["severity"] == "error")
        warnings = sum(1 for f in findings if f["severity"] == "warning")
        if set_delivery is None and row["delivery_no"]:
            sr = self.s.q_one("SELECT id FROM mask_set WHERE delivery_no=?",
                              (row["delivery_no"],))
            set_id = sr["id"] if sr else None
            set_delivery = row["delivery_no"]
        return {
            "release_id": row["id"],
            "release_name": row["name"],
            "status": row["status"],
            "replayed": replayed,
            "delivery_no": set_delivery,
            "mask_set_id": set_id,
            "canonical_hash": row["canonical_hash"],
            "error_count": errors,
            "warning_count": warnings,
            "findings": findings,
        }
