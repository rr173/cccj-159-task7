# 光罩投片交付中心（Mask Tape-out Delivery Center）

接收某次芯片发行的 **GDS/OASIS、层映射、die 尺寸、scribe line、工艺角与晶圆厂 recipe**，
校验一致性后生成**可追溯的 mask set**，并编排曝光窗口与 wafer lot 生命周期。
**零第三方依赖**：Python 3.11 标准库（`http.server` + `sqlite3`）+ 原生 JS 前端。

## 能力总览

1. **资料导入与校验**：文件摘要（SHA-256）上传即验，版图层 ↔ 层映射 ↔ recipe ↔
   工艺角四方对应，每个不一致都定位到**具体构件**（文件名/槽位/层号），结论留痕。
2. **规范化与稳定交付编号**：完整资料规范化后得到 `MS-<指纹前12位>`；重复导入复用编号、
   **不复制任何 blob 实体**（内容寻址存储）；同名异物进入隔离区等待处置，未处置不得规范化。
3. **三种入口**：浏览器页面、HTTP JSON API、命令行。
4. **谱系编排**：主版 MASTER / 修正版 REVISION / 派生层 DERIVED / 曝光后返工 DELTA，
   节点间先后次序强制（父节点版图层未排程不得排子节点，禁止依赖倒置、防环）。
5. **曝光窗口与 lot**：每台曝光机时间段（半开区间）排他；同一 lot 只能有一个当前
   mask set；两名调度员并发抢占，**单事务裁决唯一赢家**，输家得到明确原因码，
   且允许用**原操作编号安全重试**（幂等重放返回同一窗口）。
6. **未曝光双角色替换**：制造工程师（ME）+ 版图负责人（LO）两个**不同自然人**批准后
   才能替换单个构件；产生新 REVISION 谱系节点，下游 PLANNED 窗口全部取消重排。
7. **曝光后封存**：任一 lot 开始曝光，当前 mask set 节点**永久封存（SEALED）**，
   只能创建 delta set 与返工计划。
8. **晶圆厂只读交付包**：ZIP + 目录，含逐构件 SHA-256 的 MANIFEST（含自摘要）、
   `artifacts/*`、README，成品降权只读；打包前重算全部摘要，**篡改即拒绝**。
9. **持久化与崩溃恢复**：资料、占用、批准、谱系、窗口、操作日志全部 SQLite 落盘；
   进程退出后重启自动续完未完成打包，并把残留的 PENDING 操作裁决标记 INTERRUPTED，
   可用原编号安全重试。

## 明确拒绝的七类异常（均有原因码 + 审计留痕）

| 攻击/失误 | 原因码 | 裁决时机 |
|---|---|---|
| 摘要被篡改 / 传输损坏 | `DIGEST_MISMATCH` | 上传即拒，实体不入库；导出前再复验 |
| 缺层 / 层映射缺失 / 工艺角缺失 | `MISSING_LAYER` `RECIPE_LAYER_NOT_MAPPED` `UNMAPPED_LAYOUT_LAYER` `CORNER_ARTIFACT_MISSING` `MISSING_COMPONENT` | FINALIZE 核验，定位到构件 |
| 依赖倒置 / 谱系环 | `DEPENDENCY_INVERSION` `LINEAGE_CYCLE` `WINDOW_ORDER_VIOLATION` | 派生/替换/排程 |
| 窗口重叠（机器时间排他） | `WINDOW_OVERLAP` | 单事务裁决，唯一赢家 |
| 过期 / 复用的操作编号 | `OP_EXPIRED` `OP_FINGERPRINT` | 每个带 op_id 的写操作 |
| 越权替换 / 同一人双签 | `FORBIDDEN` `APPROVER_CONFLICT` | 批准动作发生时 |
| 曝光后的原地改写 | `EXPOSURE_STARTED` `NODE_SEALED` `LOT_EXPOSURE_STARTED` | 替换/排程/改绑 |
| 同 lot 绑定第二个当前 set | `LOT_ALREADY_BOUND` | 改绑 |
| 同名异物未处置 | `QUARANTINE_PENDING` | FINALIZE 核验 |

## 快速开始

```bash
# 启动服务（默认 0.0.0.0:8081，SQLite 落盘 data/mask.db）
python3 -m app.mask_api --db data/mask.db --port 8081

# 浏览器
open http://localhost:8081/            # 资料上传 / 构件关系 / 核验结论
open http://localhost:8081/schedule    # lot / 曝光窗口 / 双签替换 / 返工 / 抢占裁决
open http://localhost:8081/fab         # 只读交付包导出与下载

# CLI 端到端演示（临时目录：导入→核验→交付编号→主版→排程→曝光→拒绝改写→delta→只读包）
python3 -m app.mask_cli demo

# 全部测试（43 个：38 领域不变量 + 4 HTTP 端到端 + 1 崩溃恢复，含真实并发）
python3 -m unittest tests.test_mask tests.test_mask_api -v
```

CLI 常用命令：`release / upload / verify / finalize / make-set / lot-create /
lot-bind / book / expose / replace-request / replace-approve / rework / export /
recover / audit`（`--help` 查看参数；所有写操作支持 `--op-id`）。

## 目录结构

```
app/
  mask_store.py    SQLite schema、内容寻址 blob、单写锁事务（BEGIN IMMEDIATE）、种子用户/曝光机
  mask_service.py  领域核心：解析/校验/规范化指纹/同名隔离/谱系/双签替换/窗口裁决/幂等编号/恢复
  mask_export.py   只读交付包：QUEUED→PACKAGING→DONE/FAILED、原子落盘、崩溃续传、篡改拒绝
  mask_api.py      stdlib HTTP REST + 三个页面路由
  mask_cli.py      命令行 + 端到端 demo
web/
  mask.html / mask.js                  资料上传、构件关系图、核验、隔离区
  mask_schedule.html / mask_schedule.js  lot、窗口时间线、并发抢占、双签替换、返工、裁决表
  mask_fab.html / mask_fab.js          导出作业、MANIFEST、审计
tests/
  test_mask.py     38 个领域不变量（含 3 线程并发唯一赢家、摘要篡改、封存、delta、恢复）
  test_mask_api.py 4 个真实 socket HTTP 端到端（含并发抢占与 ZIP 下载）
```

## 数据模型（要点）

- `mask_blob`：内容寻址（SHA-256 主键），任何资料全库只落一份，原子 rename 写入。
- `mask_artifact(release_id, slot, version)`：构件槽位（`L01..`、`layermap`、`recipe`、
  `die`、`scribe`、`CORNER:<name>`）；同槽位新版本用于替换/返工，同名跨槽位/跨发行
  不同内容进 `mask_quarantine`。
- `mask_release`：COLLECTING→FINALIZED；`normalized_fingerprint` 唯一锚定首个规范发行，
  重复导入共享 `delivery_no`。
- `mask_node` + `mask_node_edge`：MASTER/REVISION/DERIVED/DELTA 谱系 DAG，节点状态
  ACTIVE/SUPERSEDED/SEALED；替换血缘由 `mask_replacement.node_id→new_node_id` 承载。
- `mask_window`：机器半开区间 `[start,end)`；`mask_arbitration` 记录每次抢占的
  WIN/LOSE、资源、调度员、原因、op_id，唯一赢家可追溯。
- `mask_replacement`：ME/LO 两签（不同自然人），DONE 后挂 new_node_id 并列下游重排。
- `mask_op`：操作编号幂等台账（PENDING/DONE/REJECTED/INTERRUPTED），与业务同事务提交。
- `mask_export`：可恢复打包作业；`mask_audit`：只追加操作日志。

## 幂等与并发正确性

- 所有写事务在**单把进程锁**内以 `BEGIN IMMEDIATE` 串行；窗口重叠、lot 改绑等冲突在
  事务内判定，输家随事务回滚并写 `mask_arbitration(LOSE)`。
- `mask_op` 的 PENDING 登记与业务写入、DONE 标记在**同一事务**：业务回滚则编号立即
  释放，绝不毒化；提交成功后来者读到 DONE 返回首次结果（`replayed:true`）。
- 进程崩溃只可能留下 PENDING（业务未生效）：启动 `recover_pending_ops()` 标 INTERRUPTED，
  客户端用**原 op_id** 重试即接管；窗口 `op_id` 唯一约束与内容寻址保证不重复。

## REST API 摘要

详见 [API.md](API.md) 的「光罩投片交付中心 API」一节，前缀 `/api/mask`，页面
`/`、`/schedule`、`/fab`。错误统一 `{"error","message","detail"}`。
