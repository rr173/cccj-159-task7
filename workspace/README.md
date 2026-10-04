# 芯片设计 ECO 与签核基线服务

面向芯片设计团队的工程变更（ECO）冻结、验证矩阵调度、双角色签核与不可变发布基线服务。
**零第三方依赖**：仅使用 Python 3.11 标准库（`http.server` + `sqlite3`）+ 原生 JS 前端。

## 要解决的问题

设计团队提交 ECO 时冻结 **网表 / 约束 / 受影响模块 / 验证矩阵**，系统按依赖图触发
**时序 STA、功耗、形式验证、版图 DRC**（及非必需 Lint）。只有满足：

1. 全部**必需检查针对同一条冻结基线**通过（每条结果带输入指纹）；
2. **双角色签核**（时序负责人 + 方法学负责人，且必须是两个不同的人；
   支持管理员配置**临时代理签核**，但代理未生效/已过期/已撤销一律在签核动作发生时拒绝，
   同一自然人即使经两条代理链也不得完成双签）；

才能形成一条新的**不可变发布基线**。

系统对四类高频异常给出确定性裁决，**任何情况下旧结果都不得跨基线拼接复用**：

| 场景 | 行为 |
|---|---|
| 验证结果迟到（基线已刷新/作废） | run 标记 `SUPERSEDED`，迟到提交以 `STALE_SUPERSEDED` 拒收并留痕 |
| 基础约束更新途中到来 | 在验 ECO → `REBASE_REQUIRED`，全部旧检查与签核作废；约束更新期间若有发布中 ECO 则直接拒绝，冻结世界 |
| 两个 ECO 修改重叠模块 | 模块锁互斥，后来单 `QUEUED` 明确排队；可由 CCB 裁决 `MERGE` 合并（逐模块 TARGET/SOURCE 赢家），合并使冻结纪元 +1 并整轮重跑 |
| 发布中断 | 两阶段发布：阶段1提交 `RELEASING`（可在其后崩溃），阶段2原子写入新基线；中断期间禁止中止 ECO / 更新约束，`resume` 幂等恢复 |
| 已发行版本事故 | 质量负责人登记批次/原因/证据后，命中版本及全部后代原子标为不可信；trunk 回退到最近可信祖先，未发行 ECO 转回待重新对齐，隔离/恢复推进信任代次，旧检查和旧签核一律重跑重签 |

## 防串用的核心机制：冻结指纹 + 纪元

- **快照**：冻结时固化 `{网表, 约束, 受影响模块, 验证矩阵}`，整体 SHA-256 摘要（16hex）。
- **检查作用域指纹**：每条 check_run 绑定其输入作用域（netlist / sdc / modules + 固定矩阵）
  的指纹。Runner 从 `/inputs` 拉取冻结输入后**自行计算指纹**（不偷看期望值），随结果回传。
- **三重拒收**：`FINGERPRINT_MISMATCH`（输入被改/拿错基线）、`STALE_SUPERSEDED`
  （纪元已变，结果迟到）、`ALREADY_SUBMITTED`（重复提交）。所有拒收进 `rejected_result` 审计表。
- **冻结纪元 freeze_epoch**：rebase / 合并扩张均令纪元 +1，旧 run 整批 `SUPERSEDED`，
  旧签核因 `(epoch, overall_fp)` 不再匹配而失效。
- **依赖图**：`LAYOUT_DRC` 依赖 `TIMING_STA`+`POWER_ANALYSIS`，前置未 PASS 时保持
  `BLOCKED`，提前提交以 `DEPENDENCY_BLOCKED` 拒收；前置 FAIL 不会解锁下游。

## 审核前电路影响闭包

创建 ECO 时系统根据**版本化拓扑**（模块实例关系、时钟域、约束引用、强制策略）和变更起点
自动计算影响闭包，操作页为 `/impact`：

- 输出**必须复验的实例/模块集合、检查类型和每条传播边解释**；跨时钟边生成 `CDC_VERIFY`，
  接口契约边生成 `INTERFACE_CONTRACT_CHECK`，时钟树和约束引用分别生成对应复验项。
- 快照绑定 `topology_version/topology_fingerprint/change_summary/result_fingerprint`，
  并写入冻结快照整体指纹；相同输入返回原快照。
- 设计人员可排除可选候选，但**每个排除项必须填写理由**；变更起点、跨时钟后继、接口契约
  后继、约束引用节点和策略强制节点不能排除。普通节点若切断强制路径，返回带完整路径的
  `MANUAL_EXCLUSION_CONFLICT`。
- 人工排除不原地修改自动结论，而是追加闭包 revision；`impact_latest` 只保留一个当前版本，
  并发重算由单事务和唯一约束裁决。审计同时保存 `impact.auto` 与 `impact.override`。
- 关系图发布新版本后，旧闭包标记为拓扑过期，FROZEN ECO 立即转 `REBASE_REQUIRED`、检查作废、
  签核失效；旧闭包不得冻结或发布。
- 环、缺失节点、超大闭包、多实例歧义、强制排除和路径冲突均返回原因码、上下文和可执行
  `action`。

## 验证执行租约协调（Runner 层）

多 Runner 并发从验证矩阵领取检查时，由独立的租约层（`app/leases.py`）协调执行权，
操作页见 `/ops`，API 前缀 `/api/leases`：

- **只发就绪任务**：待领池只含 FROZEN ECO 上 `PENDING`（依赖前置已 PASS）的检查；
  显式领取 `BLOCKED` 任务以 `DEPENDENCY_NOT_READY` 拒绝。
- **领取幂等 + 原子单赢家**：`POST /api/leases/claims` 携带 `idempotency_key`，相同键
  重放返回**首次**授权（`replayed:true`，不新增代次/事件）；领取在单个
  `BEGIN IMMEDIATE` 事务内裁决，唯一索引兜底，并发领取同一任务只有一个成功，其余
  `LEASE_HELD_BY_OTHER`（含持有者与剩余秒数）。
- **续租/完成/释放/接管**：`renew` 延长 TTL；`complete` 携带 `gen + lease_token +
  fingerprint` 回传结果；`release` 主动让出；TTL 过期后其他 runner 可 `takeover`，
  **租约代次 +1** 并返回新凭据，旧持有者的续租/结果立即以 `STALE_LEASE_GEN` 拒收
  （重跑产生新 run 后，旧代次迟到结果同样被拒，记 `STALE_SUPERSEDED`）。
- **不可伪造凭据**：token = `HMAC-SHA256(server_secret, run_id:gen:runner_id)`
  截断 16hex，仅在领取/接管响应中分发一次；库内只存 SHA-256 摘要。服务密钥落盘
  `lease_meta`，重启后旧凭据对未过期租约仍有效。伪造/篡改 token → 403
  `LEASE_BAD_CREDENTIAL`。
- **拒绝全留痕**：租约层拒绝写 `lease_event(REJECT)`（`/api/leases/audit` 可按
  run / 事件类型 / 原因码查询），看板 `recent_rejects` 同步展示。
- **落盘与重启恢复**：租约、幂等键、事件全部 SQLite 落盘；启动 `recover()` 恢复未过期
  HELD 租约、回收过期租约为 EXPIRED，并对账 run 已在租约层之外结束/作废的租约
  （COMPLETED/INVALIDATED）；运行期每次租约操作还会惰性回收，无需后台线程。
- **不绕过 ECO 门禁**：租约凭据校验与 `submit_result` 在**同一个数据库事务**内执行，
  接管后的结果仍必须通过原服务的冻结指纹（`FINGERPRINT_MISMATCH`）、纪元作废
  （`STALE_SUPERSEDED`）、依赖门禁（`DEPENDENCY_BLOCKED`），FAIL 仍只能走既有
  `rerun`，双签与两阶段发布约束完全不变；ECO 侧 `rejected_result` 与租约侧审计双侧留痕。

## 已发行版本事故隔离

质量负责人可对已发行基线登记故障批次、根因和证据，操作页为 `/quarantine`，
API 前缀 `/api/quarantine`。系统在同一 SQLite `BEGIN IMMEDIATE` 事务中裁决整条谱系：

- **受影响谱系**：以命中基线为根，沿 `parent_id` 标记全部后代；基线和后代均写入
  `UNTRUSTED`，trunk 原子回退到最近可信祖先。未发行 ECO（FROZEN / QUEUED /
  REBASE_REQUIRED）转回 `REBASE_REQUIRED`，发布中的 ECO 取消并同样重新对齐；
  旧 check_run 全部 `SUPERSEDED`、旧签核 `voided`、HELD 租约 `INVALIDATED`。
- **两阶段可恢复**：登记请求先落 `quarantine_incident(status=PENDING)` 与
  `REGISTERED` 日志，再执行隔离；`AFTER_REGISTER` 崩溃后，相同请求或启动
  `recover()` 只恢复首次裁决。待恢复期间，同谱系新发行/冻结/约束更新均以
  `QUARANTINE_PENDING` 拒绝，保证隔离与新发行按同一谱系原子串行裁决。
- **请求幂等**：相同 `{命中版本,批次,原因,证据}` 或显式 `idempotency_key` 重放
  返回首次事故（`replayed:true`），不会第二次迁移状态。
- **信任代次 trust_generation**：隔离代次写入基线、ECO、冻结快照、检查作用域指纹和
  发布基线；恢复可信再推进一代。因此恢复后仍处于流程中的 ECO 必须重新冻结、整轮
  重跑、重新双签，任何旧检查结果和旧签核都不能跨隔离代次复用。
- **双角色恢复**：恢复需质量负责人和发布负责人两个不同自然人确认；隔离期间若出现
  新发行基线（`revision > guard_revision`），返回 `RESTORE_FORK_DETECTED`，
  双角色确认也不能恢复。恢复后 trunk 指回原谱系末端，并以新信任代次重新开线。
- **操作页/审计**：`/quarantine` 展示受影响谱系、当前可信祖先、待处理变更、
  事故确认状态和 `quarantine_journal` 落盘日志；所有 REGISTER/ISOLATE/RESTORE
  事件同步写 `audit_log`。

## 快速开始

```bash
# 启动服务（默认 0.0.0.0:8080，SQLite 落盘 data/eco.db，租约默认 TTL 600s）
python3 -m app.api --db data/eco.db --port 8080 --lease-ttl 600

# 浏览器打开签核工作台
open http://localhost:8080
# Runner 验证执行租约操作页（待领/持有者/剩余时间/接管/审计）
open http://localhost:8080/ops
# 电路影响闭包操作页（拓扑版本、传播解释、人工排除、审计）
open http://localhost:8080/impact
# 已发行版本事故隔离操作页（谱系、可信祖先、待处理变更、双角色恢复、审计）
open http://localhost:8080/quarantine

# 启动独立的设计签名封装服务（默认 8090，SQLite + 内容寻址 blob 落盘）
python3 -m app.envelope_api --db data/envelope.db --port 8090
# 浏览器打开信封谱系/签名状态/校验结果页
open http://localhost:8090/envelopes
# CLI 端到端演示（临时目录内创建、双签、封口、发布、导出并离线验真）
python3 -m app.envelope_cli --db data/envelope.db demo

# 命令行跑完 A/B/C/D 四个异常场景演示（内存库）
python3 -m app.demo

# 全部测试（109 个：原 ECO/租约/API/影响闭包 98 个 + 事故隔离 11 个，含 HTTP 端到端）
python3 -m unittest discover -s tests -v
```

## 目录结构

```
app/
  store.py    SQLite schema/连接/种子基线 R0/检查目录(依赖与作用域)/租约与租约审计表
  service.py  领域核心：冻结指纹、影响闭包绑定、依赖调度、排队合并、双签门禁、临时代理签核授权、两阶段发布、差异包
  impact.py   版本化电路拓扑、影响闭包传播、跨时钟/接口/约束/策略强制节点、人工排除与审计
  quarantine.py 已发行版本事故隔离：两阶段落盘恢复、谱系后代裁决、信任代次、双角色恢复防新分叉
  leases.py   验证执行租约协调：幂等领取(原子单赢家)、续租、代次+HMAC凭据完成、超时接管、重启恢复
  runner.py   模拟验证 Runner（自行算指纹；可演示迟到/篡改）
  envelope_store.py 签名封装 SQLite schema、内容寻址 blob 与崩溃恢复元数据
  envelope.py       发布信封：分块上传、内容哈希、Merkle 包含证明、Ed25519 多方签名、离线验真、原子发布
  ed25519.py        零第三方依赖的 RFC 8032 Ed25519 签名/验签
  envelope_cli.py   封装、上传、签名、发布、验真、导出 CLI
  envelope_api.py   stdlib HTTP REST + `/envelopes` 页面
  api.py      stdlib HTTP REST 路由（ECO + 租约两组 API）
  demo.py     四场景端到端演示
web/
  index.html  签核工作台（代理配置、ECO 队列、门禁矩阵、签核、差异包、拒收留痕）
  app.js      零依赖 JS；浏览器端用 WebCrypto 复算 Runner 指纹
  ops.html    Runner 租约操作页（待领任务、持有者与剩余时间、超时接管、接管历史、拒绝审计）
  ops.js      租约领取/续租/完成/释放/接管；token 仅领取时分发，localStorage 保存授权
  impact.html 电路影响闭包操作页（拓扑版本、闭包候选、传播边解释、人工排除、审计）
  impact.js   零依赖 JS；发布拓扑、计算闭包、提交带理由排除并展示可操作错误
  quarantine.html 已发行版本事故隔离操作页（受影响谱系、可信祖先、待处理变更、双角色恢复、审计）
  quarantine.js   零依赖 JS；登记事故、恢复中断裁决、提交双角色恢复确认
  envelopes.html 设计签名发布信封页面（谱系、签名状态、校验结果、审计）
  envelopes.js   零依赖 JS；支持浏览器 Ed25519 签名与信封/发布查询
tests/
  test_service.py     24 个领域不变量测试
  test_delegation.py  18 个临时代理签核测试
  test_leases.py      22 个租约协调不变量测试（并发单赢家/幂等/代次凭据/接管/重跑迟到/重启恢复）
  test_impact.py      14 个影响闭包测试（传播/强制节点/排除冲突/环/缺节点/超大闭包/动态门禁/并发单当前版本）
  test_quarantine.py  10 个事故隔离测试（后代隔离/幂等/发布并发/落盘恢复/双角色恢复/防新分叉/信任代次作废）
  test_api.py         10 个真实 socket HTTP 测试（含租约领取-接管-完成、事故隔离/恢复端到端）
  test_envelope.py       9 个发布信封领域不变量（并发同内容、续传、撤权、签名者/根密钥轮换、篡改、恢复/同名冲突）
  test_envelope_api.py   2 个真实 HTTP 端到端测试（双签发布离线验真、分块续传页面）
```

## ECO 状态机

```
DRAFT ──freeze(无锁冲突)──▶ FROZEN ──双签+发布──▶ RELEASING ──阶段2──▶ RELEASED
  │                           │ ▲                                      
  │                           │ │ rebase(refreeze, epoch+1)            
  │      基础约束更新          ▼ │                                      
  │                    REBASE_REQUIRED                                  
  │ freeze(模块被占)                                                      
  ├──────────────────────▶ QUEUED ──合并裁决──▶ (源)MERGED / (目标留在 FROZEN, epoch+1)
  └──abort─▶ ABORTED        │                                           
        阻塞解除且未被合并 ──┴──▶ REBASE_REQUIRED（必须基于最新基线重冻结）
```

## REST API 摘要

详见 [API.md](API.md)。主要端点：

- `POST /api/ecos` · `POST /api/ecos/{id}/freeze|abort|signoff|release|release/resume`
- `GET  /api/ecos/{id}/checks/{type}/inputs`（Runner 拉冻结输入）
- `POST /api/ecos/{id}/checks/{type}/results|rerun`
- 验证执行租约：`POST /api/leases/claims` ·
  `POST /api/leases/runs/{run_id}/renew|complete|takeover|release` ·
  `GET  /api/leases/board|audit|runs/{run_id}`（操作页 `/ops`）
- `POST /api/ecos/{src}/merge-into/{tgt}` · `POST /api/constraints`
- 电路影响闭包：`GET/POST /api/impact/topology` · `POST /api/impact/compute` ·
  `POST /api/impact/snapshots/{id}/exclusions` · `GET /api/impact/audit`（操作页 `/impact`）
- 已发行版本事故隔离：`POST /api/quarantine/incidents` ·
  `POST /api/quarantine/incidents/{id}/recover` ·
  `POST /api/quarantine/incidents/{id}/restore-confirm` ·
  `GET /api/quarantine/board|incidents|audit`（操作页 `/quarantine`）
- 临时代理签核（管理员）：`POST /api/admin/delegations` ·
  `POST /api/admin/delegations/{id}/revoke` · `GET /api/current-signers`
- `GET  /api/workbench` · `GET /api/baselines/diff?from=&to=` · `.../diff.zip`
- `POST /api/admin/reset`（演示数据重置）

所有错误形如 `{"error":"CODE","message":"...","detail":{...}}`，拒收原因码见 API.md。

## 临时代理签核

负责人休假/缺位时，管理员可为两种签核角色配置临时代理（工作台面板 ①，或
`POST /api/admin/delegations`）：

- 指定**代理人**、被代理负责人（可选，仅展示来源）、**生效/失效时间**（UTC ISO-8601）；
  可随时**撤销**。相同 `(角色, 代理人, 生效, 失效)` 重复提交**幂等**，不产生重复有效记录
  （部分唯一索引 + 应用层去重），时间窗重叠返回 409。
- 服务端**只在签核动作发生时**校验授权：拒绝未生效（`DELEGATION_NOT_STARTED`）、
  已过期（`DELEGATION_EXPIRED`）、已撤销（`DELEGATION_REVOKED`）、角色/人不符的代理；
  拒绝写 `audit_log(signoff.denied)`。
- **同一自然人禁止双角色签核**的禁令穿透代理：即使持有两个角色的有效代理，第二签仍被
  `DUAL_ROLE_CONFLICT` 拒绝。
- 已完成的代理签核在记录中固化**当时身份与代理链**（`signoff_kind=DELEGATE`、
  `delegation_id`、`auth_chain`：授权人/被代理人/有效期/校验时刻），长期保留供审计
  （差异包 `verification/signoffs.json` 同步包含）；ECO 重新冻结（rebase/合并/新基线发布）
  仍将旧签核标记失效（`voided_at`），新纪元必须重签。
- 工作台展示每角色**当前可签人员、代理来源与有效期**，并在 ECO 卡片提供"代理签核"按钮。

## 独立设计签名封装服务

`envelope_api.py` 提供与 ECO 服务隔离的发布信封服务，用于把待发布变更的
**网表、约束、模块清单、签核记录**组装成内容寻址信封。

- **内容寻址**：规范化 JSON（键排序、无空白、UTF-8）后计算内容 SHA-256；
  `envelope_id == content_hash`。并发封装相同内容只落一个有效信封，多个会话指向同一 ID。
- **分块上传与续传**：元数据、上传状态、分块索引和每块 SHA-256 全部 SQLite 落盘；
  blob 按哈希内容寻址。重复块幂等，同序号不同内容返回 `CHUNK_CONFLICT`，
  查询上传可返回 `missing_indexes`，进程重启后继续补齐并完成。
- **多方签名、撤权历史与密钥轮换**：签名者公钥由服务根密钥签发注册表事件；
  `REGISTER/REVOKE` 均带时间。签名者轮换会撤销旧 KID，根轮换由新旧根交叉签名同一事件，
  离线方可沿根链追溯历史。验真按 `signed_at` 判断当时授权状态，因此撤权/轮换后
  **历史签名仍有效，新签名被拒绝**；签名记录中的 signer/role 若被篡改也会拒绝。
- **离线验真**：导出 ZIP 包含 `MANIFEST.json / SIGNATURES.json / TRUST.json /
  PROOFS.json / artifacts/*`。离线校验重算构件、分块、内容哈希、Merkle root、
  根签名注册表与每条签名，无需访问服务。
- **原子发布**：先事务性写 `PUBLISHING` 发布名，再生成发布收据并原子 rename；
  启动 `recover()` 幂等完成中断发布。同名不同内容以 `NAME_CONTENT_CONFLICT` 拒绝
  并写审计；同名同内容幂等。
- **篡改留痕**：内容、摘要、分块、签名或签名者注册表不一致时验真返回具体原因，
  并写 `envelope_audit(result=REJECTED/INVALID)`。
- **页面/CLI/REST**：页面 `/envelopes`；CLI `python3 -m app.envelope_cli --help`；
  API 前缀 `/api/envelope`。

## 差异包

`GET /api/baselines/diff.zip?from=B-R1&to=B-R3` 产出：

```
manifest.json                 # 完整结构化差异
constraints/sdc.before|after.json
modules/<m>.before.v / .after.v / .diff   # 逐模块 unified diff
verification/matrix.json      # 目标基线的验证矩阵定义
verification/results.json     # 实际通过的检查结果（含 result_fp/expected_fp）
verification/signoffs.json    # 双角色签核记录
README.txt
```

差异包可独立审计：模块变更、约束 delta、每条检查是否针对目标基线指纹通过、双签是否齐备。
