# HTTP 接口契约

基础路径 `http://<host>:8080`，除内容上传与包下载外全部 JSON。
错误统一：

```json
{ "error": "CODE", "message": "可读说明", "detail": { "...": "定位信息" } }
```

## 通用头

| 头 | 说明 |
|---|---|
| `X-Person-Id` | 操作自然人 id（`u_mei/u_tao/u_disp1/u_disp2/u_admin`），缺失 → 401 `UNAUTHORIZED` |
| `X-Op-Id` | 可选，**原操作编号**；同编号安全重试，冲突/过期见下 |

操作编号语义：同编号+同载荷已提交 → 回放首次响应（`replayed:true`）；
同编号不同载荷 → 409 `OP_PAYLOAD_CONFLICT`；裁决中 → 409 `OP_PENDING`；
过期 → 410 `OP_EXPIRED`。失败裁决（如抢占输家）未过期内重放同一结论
（`detail.replayed=true`）。

## 内容（构件）

### POST /api/content
原始字节上传（非 JSON）。请求头：`X-Logical-Name`、`X-Kind`（GDS/OASIS/LAYERMAP/RECIPE/OTHER）、
可选 `X-Sha256`（不符 → 422 `DIGEST_MISMATCH`）。
返回 `{sha256,size,logical_name,dedup,quarantined[,quarantine_id]}`。
同内容 → `dedup:true`；同名不同内容 → `quarantined:true` 并进入隔离区。

### GET /api/artifacts
已登记构件（含实时 CAS 摘要核验 `verified`）。

### GET /api/artifacts/{sha256}?name=
构件关系：别名、所属发行（角色/交付编号）、所在 mask set 成员关系——可追溯链路。

## 发行导入

### POST /api/imports
```json
{
  "release_name": "CHIP-A", "corner": "TT_0p90_25C", "fab": "FAB12",
  "foundry_recipe_id": "FAB12-RCP-7",
  "die": {"width_um": 5000, "height_um": 3000}, "scribe_um": 80,
  "entries": [
    {"role": "GDS",      "logical_name": "a.gds",        "sha256": "…"},
    {"role": "OASIS",    "logical_name": "a.oas",        "sha256": "…",
     "layer_inventory": ["L100.0"]},
    {"role": "LAYERMAP", "logical_name": "a.layers.json","sha256": "…"},
    {"role": "RECIPE",   "logical_name": "rcp.json",     "sha256": "…"},
    {"role": "MASK:M_MAIN", "logical_name": "m.gds",     "sha256": "…"}
  ]
}
```
GDS 与 OASIS 二选一；OASIS 必须随附 `layer_inventory`。
返回 `{release_id,status: VALID|INVALID|QUARANTINED,delivery_no,replayed,
error_count,warning_count,findings[]}`，每条 finding：
`{severity:error|warning,code,message,locator}`。

### POST /api/demo-packet
合成一份完整合法资料（真 GDSII + 层映射 + recipe），返回可直接 POST 到 /api/imports 的 packet。

### GET /api/releases · GET /api/releases/{id}
发行列表 / 详情（含构件角色、die/scribe/corner、全部核验结论）。

## Mask set / 谱系

### GET /api/sets?lineage=
谱系节点列表（MASTER/REVISION/DELTA，ACTIVE/SUPERSEDED/SEALED）。

### GET /api/sets/{id 或 MS-编号}
节点详情：`order`（曝光先后次序）、`members`（mask/角色/层/构件 sha）、
`edges`（依赖边与原因）、封存时间。

## 曝光机 / 窗口 / lot

### POST /api/tools · GET /api/tools
`{name}`（DISPATCHER）。

### POST /api/lots · GET /api/lots
`{display_name}`（DISPATCHER）。

### POST /api/lots/{id}/bind
`{set}`：同一 lot 绑定一个当前 set；有未完成窗口时 `LOT_WINDOWS_PENDING`；
已曝光 lot 仅允许绑定同谱系 DELTA（`DELTA_LINEAGE_MISMATCH`/`LOT_EXPOSED`）。

### POST /api/windows
`{tool_id,set,mask,start_ts,end_ts,lot_id?}`（ISO-8601 UTC，半开区间）。
- mask 不在 set → `MASK_NOT_IN_SET`；时间倒置 → `BAD_TIMESTAMP`；
- 同机时间重叠 → 409 `WINDOW_OVERLAP`，`detail.winner_op_id` 给出唯一赢家；
- 封存/被取代节点 → `SET_SEALED_INPLACE` / `SET_SUPERSEDED`。

### POST /api/windows/{id}/expose
执行曝光。lot 未绑定该 set → `LOT_NOT_BOUND`；前置 mask 未曝光 →
409 `DEPENDENCY_NOT_EXPOSED`（`detail.requires`）。首次曝光把节点置 `SEALED`。

### POST /api/windows/{id}/cancel
取消 RESERVED 窗口（已曝光不可取消）。

### GET /api/windows?tool=&set=&state=

## 曝光前替换（双签）

### POST /api/replacements
`{set,mask,new_sha,reason}`（ME/STEWARD）→ `{replacement_id,status:PENDING,requires:[ME,STEWARD]}`。
封存后 → `SET_SEALED_INPLACE`；新构件未登记/隔离/摘要不符/层不适用 → 对应拒收。

### POST /api/replacements/{id}/approve
两次不同自然人、分别覆盖 ME 与 STEWARD。第一签返回 PENDING；
第二签返回 `{status:EXECUTED,new_set_id,new_delivery_no,migrated_windows[]}`，
旧节点 SUPERSEDED、窗口/lot 迁移。同一自然人再签 → `APPROVAL_SAME_PERSON`。

### POST /api/replacements/{id}/reject · GET /api/replacements?status=

## 曝光后 Delta / 返工

### POST /api/deltas（ME）
`{set,changes:[{mask_name,new_sha}],note}`，set 必须已 SEALED（否则 `SET_NOT_SEALED`）。
返回 `{delta_set_id,delivery_no,base_delivery_no,changed_masks}`，base 保持 SEALED。

### POST /api/rework-plans（ME）
`{lot_id,delta,note}`：lot 须已曝光，delta 须与 lot 当前 set 同谱系。

### GET /api/rework-plans

## 只读交付包

### POST /api/packages
`{set}`（幂等；已有 READY 直接复用 `reused:true`；崩溃后自动续建）。
构建时任一构件摘要被篡改 → `DIGEST_TAMPERED`/`PACKAGE_BUILD_FAILED`。

### GET /api/packages · GET /api/packages/{id}
### GET /api/packages/{id}/download
返回确定性未压缩 tar（`MANIFEST.json` + `masks/<mask>/<file>`，成员均 0444），
响应头 `X-Package-Sha256`；下载前重算文件摘要，不符 → `PACKAGE_TAMPERED`。

`MANIFEST.json` 含：`delivery_no,mask_set_id,kind,release_name,die,scribe_um,
corner,fab,foundry_recipe_id,exposure_order,dependencies,masks[],read_only,
manifest_sha256`。

## 隔离处置 / 审计

### GET /api/quarantine?status=
同名构件/同名发行隔离项。

### POST /api/quarantine/{id}/resolve（ADMIN）
`{decision: ACCEPT_AS_ALIAS|REJECT, new_name?}`；接受同名发行后自动补建 mask set
并把发行置 VALID。

### GET /api/arbitrations
资源裁决记录（resource_key、区间、winner_op_id、loser_op_id、decided_at）。

### GET /api/audit?limit=&target=&op=
全部操作日志（资料、占用、批准、谱系、打包、恢复）。

### GET /api/people · POST /api/people（ADMIN）
自然人列表 / 新建 `{id,name,roles[]}`（ME/STEWARD/DISPATCHER/ADMIN）。
