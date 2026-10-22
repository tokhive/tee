# TokenHive `tokhive` 分支安全审计报告

- **审计对象**：本仓库迁移前的原 TEE 代码，即旧仓库 `tokhive` 分支的 `` 目录（现已并入本仓库根）
- **审计基线**：`6b9fd3400ee4512ec15b6f8ed42e957a3bbbbd82`（HEAD，2026-09-19）
- **触发线索**：commit `ead770949b358226d313c8e6afd92142cc31c2d1`（tee: retire the connections a rotation leaves behind）——**RA-TLS 密钥轮换（epoch）与已建立连接的生命周期不匹配**，属于「状态跨 epoch / 生命周期 / 资源配对」这一类。本报告专门排查同类问题，以及 DoS、计费不公平/偷钱、常规安全漏洞。
- **方法**：逐文件读源码（code-level verification），不依赖文档或记忆；所有结论附 `file:line`。**未改动任何代码**。

---

## 0. 结论摘要

| 级别 | 数量 | 主题 |
|---|---|---|
| 高 | 3 | 慢读者可无期限占用 Hub 资源（DoS）；默认信任根不安全 + relay 默认无认证；开放模式使租户级控制可绕过 |
| 中 | 5 | 报价/调度低估按量费；单笔无上限默认；隧道无心跳；配额表满即拒绝；序号存储每任务全量重写 |
| 低 | 8 | 输入侧字节未交叉校验；去重窗口重置；目录/策略无认证；agent key 无速率限制；信封无重放/有效期；Audit 线性放大；帧缓冲无上界；响应整段缓存 |

**最重要的一条**：`cmd/hub/serve.go` 的用户侧响应（SSE 与 WebSocket 两条路径）**都没有写超时**，且会话在被超时切断时会阻塞在 `<-downDone`。一个完成握手后不再读取响应的客户端，可以把 Hub 的 goroutine、该租户的 in-flight 槽、以及后端的 provider 连接**一直占住**。

---

## 1. 高严重度

### H1 — 慢读者可无限期占用 Hub goroutine / in-flight 槽 / provider 连接（DoS）

**位置**
- `cmd/hub/serve.go:201-209`（`newHubServer`：`WriteTimeout` 故意为 0）
- `cmd/hub/serve.go:228-387`（`userHandler`，SSE 路径）
- `cmd/hub/serve.go:603-645`（`sessionHandler`，WebSocket 路径）
- `hub/realtime.go:382-492`（`relaySession`，尤其 `475-491`）

**问题**：两条用户路径都不对「写回客户端」设期限。
- SSE：`onChunk` 直接 `w.Write(chunk)`（`serve.go:310`）。客户端停止读取后，TCP 发送窗口填满，`Write` 阻塞；`AttemptTimeout`（默认 3m，`main.go:88`）只作用于 TEE 派发上下文，**无法解除已经阻塞在客户端写上的 goroutine**。
- WebSocket：`sessionHandler` 只对**第一帧**设了 5s 读期限并随后清除（`serve.go:616-618`），从未调用 `SetWriteDeadline`。downlink goroutine 在 `link.Write`（`sessionLink.Write` → `conn.WriteMessage`，`serve.go:791`）上阻塞。会话超时时，`relaySession` 的 `ctx.Done()` 分支执行 `_ = tunnel.Close()` 后 **`<-downDone`**（`realtime.go:476-480`）；但 downlink goroutine 卡在 `link.Write`，永远不会给 `downDone` 发信号 → handler 永久阻塞。`defer conn.Close()`（用户 socket）永远不执行。

**影响**：一个能完成握手、之后不读响应的客户端（无需真实凭证——见 H3 开放模式）即可把每个连接的 goroutine、`MaxInflightPerTenant` 槽、以及 TEE/agent 的 provider 连接长期占住。这是最接近「拒绝服务」的可复现路径。

**修复建议**：对用户连接使用写期限（`http.ResponseController.SetWriteDeadline`，或 WS 的 `SetWriteDeadline`）并随每个 chunk 滚动刷新；让 `link.Write` 返回错误时结束会话；`relaySession` 不要无超时地 `<-downDone`（加 select + 超时或在 `tunnel.Close` 后直接放弃该 goroutine 并结算已有计数）。

> 置信度：高。已确认全仓无 `SetWriteDeadline` 作用于用户侧（`grep SetWriteDeadline` 仅命中 `transport/relay.go` 的内部 `streamConn`）。

### H2 — 默认配置的信任根不安全 + 反向 relay 默认无认证（安全）

**位置**
- `cmd/hub/main.go:96`：`-allowed-platforms` 默认 `"simulated"`
- `cmd/hub/main.go:104`：`-tee-verify` 默认 `"pin"`
- `cmd/hub/main.go:90`：`-relay-key` 默认 `""` → `RelaySecret` 为空
- `cmd/hub/main.go:91`：`-tenant-keys` 默认 `""` → 开放模式
- `cmd/hub/main.go:484-491`：`pin` 模式且未给 `-mtls-ca` 时返回 `nil` TLS 配置 → **明文 HTTP，完全不认证 TEE**
- `platform/simulated/simulated.go:52,239-260`：`simulated` 的 `CheckEvidence` 只校验固定常量测量值 `...dead`；模拟签名器源码公开，**任何人都能伪造被接受的收据**
- `hub/agenthttp.go:211-216`：`len(h.relaySecret) > 0` 才校验，空即放行

**问题**：出厂默认组合起来是「不认证 TEE + 接受可伪造的模拟 attestation + relay 端点开放」，即一台**无信任根**的 Hub。`/v1/relay` 一旦开放，任何能连到 Hub 的人都能把任意流桥进**任一在线 agent 的隧道**（`agenthttp.go:227-244`，`relayStream` 不校验 `req.Host`），形成经由卖家 IP 的出口代理。缓解仅来自卖家 agent 自己的 `AllowedTargets` 白名单（`provider/agent.go:502-518`，精确匹配）——即攻击者可命中卖家被允许的那些上游，并耗尽卖家 relay 容量（`DefaultMaxRelayConns = 64`）。

**修复建议**：生产必须 `-allowed-platforms aws-sev-snp -expected-app snp-app:<sha256> -tee-verify attestation -relay-key <secret> -tenant-keys <map>`；建议对生产关键项做**启动期 fail-closed**（例如检测到 `simulated` 或空 relay key 时拒绝在 serve 模式启动，除非显式 `-dev`）。

> 置信度：高（默认值可核）。严重度取决于部署是否使用默认值——默认即不安全是设计取向，但缺少 fail-closed 使误用代价很高。

### H3 — 开放模式下租户级控制可被「换 key」绕过（DoS + 计费公平）

**位置**：`cmd/hub/serve.go:95-112`（`tenantResolver.resolve`）；`hub/quota.go`、`hub/budget.go`、`hub/flight.go` 全部以 `tenant` 为键。

**问题**：`keys` 为空时，`resolve` 直接把请求头 `X-TokenHive-Key` 当作 tenant 返回。于是 Quota（`quota.go`）、Budget（`budget.go`）、MaxInflightPerTenant（`flight.go`）这三个**唯一的租户级限制**，都可以通过每次换一个 key 来获得全新配额——等价于全部失效。默认（无 `-tenant-keys`）即如此。

**影响**：单方可无限并发、无限累计消费、并绕过公平份额控制去占满共享 provider 的连接池；同时这是「无认证」——任何非空 key 都是合法租户。

**修复建议**：生产必须配置 `-tenant-keys` 并辅以账户/余额模型（`prepaid-balances` 分支的方向）。若必须支持开放模式，应在每 IP/连接维度另设一道与 key 无关的速率与并发上限。

> 置信度：高。

---

## 2. 中严重度

### M1 — 报价与调度用「单 MB 底价」，低估按量费用，可能让买家付更多（计费公平）

**位置**：`hub/schedule.go:144-154`（`bookPrice`）、`75-121`（`providersForModel` 排序）、`hub/pricing.go:79-122`（`Price`）、`cmd/hub/serve.go:407-427`（`/v1/models` 展示 `bookPrice`）

**问题**：`bookPrice = PerRequestMicros + Premium(model) + PerMegabyteMicros`（恰好 1 MiB 的底价）。而真实账单是 `ceil((RequestBytes+delivered)/1MiB)*PerMB + PerRequest + Premium`。对**大响应**，真实费用随 `PerMB` 线性增长，而报价与排序仍只看那 1 MiB 底价。举例：卖方 A（`per_request=0, per_mb=1`）底价 1，卖方 B（`per_request=2, per_mb=0`）底价 2 → 调度选 A；若响应 1 GiB，买家付 A ≈1024，而 B 只需 2。**买家既被调到了更贵的 provider，又被 `/v1/models` 展示了严重低估（甚至差数量级）的价格**，而买不到原始 rate card（per-MB 对买家不可见）。

**说明**：代码注释把 volume floor 描述为「防止隐藏 per-MB 价」的缓解（`rates.go:46-47`、`schedule.go:127-139`），但该缓解只覆盖「最小任务」的底价，未覆盖大响应下的成本；`MaxJobMicros` 注释本身也承认「hidden per-megabyte price」这一风险。

**修复建议**：让报价/排序带上对响应规模的**上界估计**（如用 `Spec.MaxResponseBytes` 计算 volume 项），或至少把 per-MB 明细暴露给买家；把 `MaxJobMicros` 设为必填。

> 置信度：高（算术可复现）。

### M2 — 单笔计费上限默认关闭（计费）

**位置**：`cmd/hub/main.go:80`（`-max-job-micros` 默认 0）；`hub/hub.go:557-570` 的 `maxJob` 逻辑在其为 0 时不生效。

**问题**：`MaxRateMicros = 1<<40`（`rates.go:24`），单组件报价上限约 1.1e6 单位；无 `MaxJobMicros` 时，一张恶意/失误的卡可产生巨额账单，`Budget` 只在**事后**按累计扣减（且是 check-then-record，见 `budget.go:28-32`，并发可超冲 `in-flight × MaxJobMicros`）。

**修复建议**：生产强制设 `-max-job-micros`；`New()` 时对「有 Budgets 但无 MaxJobMicros」已报错（`hub.go:284-286`），可把该断言扩展到「serve 模式 + 有任何 rate card」。

### M3 — 反向隧道无心跳，半开连接被视为在线（可用性/DoS）

**位置**：`tunnel/ws.go:28-31`（只设 `ReadLimit`，无 ping/pong、无 deadline）；`hub/agentnet.go:200-208`（`register`）、`cmd/hub/serve.go:101-184`（`serveAgentTunnel` 以控制流关闭作为下线依据）

**问题**：agent 断电/掉线但 TCP 未 RST 时，Hub 的读循环阻塞在 `ReadMessage`，agent 仍被视为 online（`onlineProviders`），新任务被路由到**死隧道** → 502/截断；credential 也不被撤销。检测只依赖 OS TCP keepalive（默认约 2 小时）。

**修复建议**：给 WS 加 ping/pong 心跳与读期限；超时即 `deregister` + `revokeCredential`。TEE relay 与 agent 隧道同样适用。

### M4 — 配额/并发表满即拒绝新租户（DoS）

**位置**：`hub/quota.go:136-142`（`admit` 满则拒绝）、`hub/flight.go:83-93`（同类）

**问题**：表满时拒绝**新**租户（有意不驱逐，见注释），于是一个能用大量不同 tenant 名（开放模式下即换 key）的调用方，可以在一个窗口内把表填满，从而**锁死所有新租户**。

**修复建议**：与 H3 一样，生产固定租户集；或对「新建租户」这一行为本身设独立全局速率限制。

### M5 — TEE 序号存储每个任务全量重写（吞吐 DoS / 性能）

**位置**：`tee/seqstore.go:123-134`（`Next` → `flushLocked`）、`151-161`（marshal 整个 map + 写临时文件 + rename，无 fsync）

**问题**：每次 `Next` 都在单锁下把**整张计数表**序列化落盘。provider 多、并发高时串行化为瓶颈；同时 `rename` 无 fsync，掉电窗口内的持久性弱于其「必须先持久化再返回」的契约（`seqstore.go:32-36`）。

**修复建议**：改为按 provider 追加/预分配（如每 provider 一文件、追加 + 批量 flush），明确 fsync 语义。

---

## 3. 低严重度

| ID | 位置 | 问题 | 建议 |
|---|---|---|---|
| L1 | `hub/hub.go:541-544`、`pricing.go:90-93` | 响应侧用 `relayedBytes` 夹紧（买家实收），但**输入侧直接取收据的 `RequestBytes`**，未与 Hub 实际发送的 `len(body)` 交叉校验。理论上 TEE 可虚报输入量多收买家费用。 | Hub 侧 `RequestBytes = min(receipt.RequestBytes, len(body))`，与响应侧对称 |
| L2 | `hub/hub.go:617-628` | `claimSettlement` 表达 `1<<18` 时**整体重置**，去重窗口重启。JobID 为 16 字节随机，实际不可行，但语义上撤掉了「一 JobID 只结算一次」的强保证。 | 用有界 LRU/时间窗替代整体清空；记录重置事件 |
| L3 | `cmd/hub/serve.go:183-184, 407-427` | `/v1/models`、`/v1/policies` 无认证，泄露 provider 名、模型、价格与部署策略。 | 视需要加 key 或限流 |
| L4 | `hub/agenthttp.go:45-59` | AgentGate 认证失败无速率限制，agent key 可被在线暴力尝试（key 高熵则影响有限）。 | 失败计数 + 退避 |
| L5 | `tee/inbox.go:129-166`（`IssuedAt` 未被使用）；`hub/credentials.go` / `agentnet.go:66-68` | 凭据信封无有效期/重放保护；TEE 重启换 inbox key 后，Hub 仍附旧信封，任务持续失败直到 agent 重新注册。 | 校验/回传 `IssuedAt`；TEE 换 key 时通过 Hub 广播使旧信封失效并触发重注册 |
| L6 | `hub/store.go:177-181` | `Audit` 从 1 到 `MaxSeq` 线性扫描并构造 `Missing` 切片，大 `MaxSeq` 时 operator 侧时间/内存放大。 | 只枚举已存在的间隔，不遍历整个区间 |
| L7 | `hub/wsframe.go:69-127` | `WsFrameDecoder.buf` 无上界；虽有 `SessionMaxDownBytes` 兜底，但该值为 0 时无界。 | 对解码缓冲设上限，超限按 terminal 处理 |
| L8 | `hub/tee.go:231-279` | `readSSE` 把整段响应缓存进 `Result.Chunks`（结算需要），内存随 `并发 × MaxResponseBytes` 增长。 | 结算用流式哈希增量校验（`StreamingHasher` 已具备），避免整段驻留 |

---

## 4. 与 `ead7709` 同类的「生命周期 / 跨 epoch」候选

`ead7709` 修的是：轮换后旧 epoch 证书上的连接仍在服务，导致「收据 key 与承载连接证书不同 epoch」。同类排查结果：

1. **M3/H1 的连接无期限、无心跳**是同一根源的另一面：连接的生命周期管理与「谁在一个连接的整个寿命内负责」不清。反向隧道、TEE relay、用户 SSE/WS 三处都靠 TCP 超时兜底。
2. **Hub 侧未见显式的「收据 ↔ 承载连接证书」绑定断言**。当前信任链是：mTLS 校验对端证书（pin 或 `VerifyRATLSPeer`，`cmd/hub/main.go:484-519`）+ `attest.Verifier` 校验收据 attestation 的平台/`ExpectedApp`/`policy_hash`（`attest/attest.go:138-199`）。二者都钉到同一 app，但**没有一处把 `receipt.Attestation.KeyID` 与承载该收据的 TLS 连接证书的 SPKI 做等值比较**——而 `internal/mtls/mtls.go:172-176` 的注释恰好说「SPKI 就是 receipt KeyID」。`ead7709` 的 commit message 亦称「the Hub does（bind）」，因此这里存在**文档与实现不一致**，建议确认：若确无该断言，则跨 epoch 配对只由 TEE 侧 `guard` 保证，换用其它 verifier 即失效。**建议在 Hub 侧显式断言二者相等**（这也让 `ead7709` 的前置假设在 Hub 侧成立）。
3. **`Session.Receipt` 有意用当前 signer**（`tee/service.go:840-895`），使长会话收据与承载连接可跨 epoch；这与 commit 的「第三个 case」一致，但意味着**verifier 必须显式接受会话的这一例外**，否则长会话会周期性因 epoch 不符被拒。属设计点，建议在 Hub 侧对 `StatusCode==101` 的会话收据放宽/单独路径处理，并测试覆盖「会话跨越一次轮换」。

> 第 2 点置信度：中（基于通读；可能绑定逻辑在其他未纳入本轮的文件，如 `shared` 包）。第 1、3 点置信度：高。

---

## 5. 已验证扎实、**未发现**问题的部分（避免误报）

- **策略引擎**：host 形状/端口规范化、逐段路径前缀匹配（防 `/v1/chat` → `/v1/chat-backdoor`）、header 白名单 + 保留头、query 白名单、stream 开关、限额取 min（`policy/authorize.go`、`policy/policy.go`）。
- **spec 校验**：`ValidateProviderName` 仅允许 `[a-z0-9_-]`（封死路径穿越）、host 形状、路径穿越段、控制字符、禁头、nonce/expiry/limit（`jobs/spec.go`）。
- **定价算术**：全程 `addChecked/mulChecked` 溢出检查、`saturatingAdd` 饱和、佣金向下取整、响应量按实收夹紧、体积向上取整（`pricing.go`、`commission.go`、`ledger.go`）。
- **收据校验链**：签名 key 必须等于收据声明的 key（`proof/receipt.go:391`），canonical 编码拒绝非规范重写，`attest.Verifier` 强制平台白名单 + `policy_hash` + `ExpectedApp`（`attest.go:138-199`、`sevsnp/verifier.go:35-84`）。
- **凭据保密**：X25519 + AES-GCM 混合加密、绑定 `KeyID` 与 provider、provider 不匹配即拒（`tee/inbox.go`）；Hub 只存密文（`hub/credentials.go`，0600 权限 + 名称校验）。
- **边界**：`/v1/execute` 8 MiB + 30s 读期限（`tee/rpc.go:51-63,106-141`）；用户请求体 16 MiB + 30s（`serve.go:44,229`）；隧道帧长上界 + 单流缓冲上界 + 流数上界（`tunnel/tunnel.go:45-57,245-248`）；WS 消息读上限（`tunnel/ws.go:37`）。
- **并发/一致性**：ledger 快照一致性、`register/deregister` 以 mux 身份比较防互相注销（`agentnet.go:200-223`）、`claimSettlement` 去重、`pricing` 与结算共用同一 `card` 源（`hub.go:392-398`）。

---

## 6. 建议修复优先级

1. **H1**：用户侧写期限 + 会话超时不再阻塞（`serve.go` / `realtime.go`）——最直接可复现的 DoS。
2. **H2**：生产信任根与 `-relay-key` 的 fail-closed 校验（`cmd/hub/main.go`）。
3. **H3**：强制 `-tenant-keys`（并接入 prepaid 余额模型）。
4. **M1/M2**：报价与调度纳入响应规模上界；`MaxJobMicros` 生产必填。
5. **M3**：隧道 ping/pong + 读期限。
6. **第 4 节第 2 点**：确认并在 Hub 侧显式绑定「收据 KeyID ↔ 连接证书 SPKI」。
7. 其余低危项按 CI/运维成本择机收敛。

---

*本报告为静态审计结论；标注「置信度」处若需，可进一步以最小 PoC（本地 simulated TEE + 一个不读响应的客户端）复现 H1，以两个不同 key 复现 H3。*
