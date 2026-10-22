# TokenHive 架构：反向隧道连接与本地全栈仿真

日期：2026-09-03
状态：当前架构定稿

定位：本文是 TokenHive 当前架构的集中描述——连接如何建立、由谁持有、经过哪几跳、各组件的最低职责是什么。本文只描述系统现状，不保留任何历史改动的足迹。回执体系与 CBOR 键号、部署白名单与定价权、配额与账本、三层测试法这些已定案的内容继续有效，本文在涉及时给出它们的现状与位置，不逐一重复其推导。

---

## 0. 术语约定

首次出现时给出全称，后文直接使用缩写。TEE（Trusted Execution Environment）即可信执行环境；TLS（Transport Layer Security）为传输层安全协议；WebSocket 为在单条 TCP 连接上提供全双工通信的应用层协议；SSE（Server-Sent Events）为服务器推送事件流；CBOR（Concise Binary Object Representation）为确定性二进制编码（RFC 8949）；ALPN（Application-Layer Protocol Negotiation）为 TLS 的应用层协议协商扩展；mTLS 为双向认证的 TLS。JobSpec 为 Hub 交给 TEE 的作业描述；RateCard（费率卡）为按 provider 记录的定价数据；Receipt 为 TEE 签发的带证据的作业回执；ProviderSeq 为 TEE 内的单调序号；attestation（远程证明）为 TEE 向外部证明自身代码与配置身份的证据机制。

---

## 1. 部署形态：Provider 在家庭网络，反向隧道

TokenHive 的 Provider（AI 服务商配额贡献者）运行在自己的家庭网络里，位于 NAT 之后，不能被外网拨入。因此连接的方向被整体颠倒：**Provider Agent 主动拨向 Hub 并保持一条长连接；Hub 永不拨向 Agent。**这条 Agent 先行建立的连接是系统的枢纽。

上游服务商看到的源 IP 是 Provider Agent 的出口地址——这是产品成立的根本：TEE 的请求经由贡献者的出口到达 AI 服务商，贡献者因为出借出口而获得报酬。因为该出口不可被外网直连，Agent 必须先拨入 Hub 才能被寻址，也就带出了反向隧道的必要性。

端到端的一条请求链路如下。TEE 需要向某个 Provider 的上游发起连接时，它拨向 Hub 的中继端点开一条流；Hub 把这条流桥接进该 Provider 在线 Agent 的反向隧道；Agent 在其隧道上收到开流请求后，拨向它允许的上游 host；TEE 在这条流之上完成与上游的 TLS 握手并全程持有。

```text
User ─HTTP/SSE 或 WS─► Hub ─┬─ /v1/execute（请求模式）─► TEE ──┐
                            └─ /v1/session （流模式）─► TEE ──┤
                                                        ┌──────┴──────┐
                                                        │   Hub  中继  │  /v1/relay（TEE 拨入）
                                                        └──────┬──────┘
                                                        ┌──────┴──────┐
                                                        │  Agent 隧道  │  /v1/agent（Agent 拨入）
                                                        └──────┬──────┘
                                                                 ▼
                                                          上游 AI 服务商（OpenAI）
```

连接的所有权是本图的关键。TEE 到上游的 TCP 连接与 TLS 会话由 TEE 独占持有、跨请求长存；Hub 与 Agent 都只搬运这条连接的加密字节，永不接触 TLS 密钥；Hub 侧不存在任何到上游服务商或到 Agent 的出站连接。

两种数据面模式共享同一套数据面。请求模式承载 HTTP 请求—响应型 API（如 /v1/chat/completions 的 SSE 流式补全）；流模式承载 WebSocket 型上游（如 Realtime 类全双工会话）。两种模式都走同一条反向隧道，差别只在连接上承载的字节组织方式。

---

## 2. 反向隧道的实现：多路复用隧道

许多条并发的 TEE↔上游连接同时流经一条 Agent↔Hub 长连接，因此这条连接必须能多路复用。实现是 tokenhive/tunnel 包：一个自定的分帧协议，在单条全双工字节流上承载多条独立断开的双向字节流（Stream）。

分帧为 13 字节头（kind 一字节、8 字节流 ID、4 字节长度）加载荷。三类 frame：KindOpen 打开一条新流（载荷为打开端携带的不透明元数据，接收端把新流连同元数据交给其 open handler）；KindData 携带流上的载荷字节；KindClose 结束一条流。一条流对应一个 TEE 需要的独立字节管道；读测序由一个分发 goroutine 统一做，写侧由一把锁串行化，保证并发写不交错。

流的身份在两端免碰撞：Low 端在 ID 空间下半分配，High 端在上半分配，双方各自单调递增。每条流有独立的接收缓冲上限，消费端读不过来时只重置这一条流（不会拖住其它流）；任一侧主动关闭后，另一侧的读在排空缓冲后返回 io.EOF。多路复用器整体关闭时各流以 io.EOF 收尾，底层连接失败时则以可区分的错误收尾（见第 10 节）。

传输层适配是可替换的：生产用 WebSocket（tokenhive/tunnel/ws.go 把连接包装成连续字节流，一条 binary 消息对应一次 Write，读侧把消息拼接为连续流），测试可用 net.Pipe。分帧协议本身对载荷内容不敏感，因此它既承载控制流（Agent 注册、开流元数据）也承载数据流。

---

## 3. 组件与职责分界

各组件的最低职责是系统的稳定面，本节是集中陈述。

**TEE（TEE 进程）**：只负责建立并保持到上游的连接，以及作为连接上的字节层。具体是：凭证注入、Policy 白名单判定、JobSpec 结构校验与 body_hash 绑定、TLS 记录层、HTTP/1.1 请求序列化与响应分帧读取、流式摘要与回执签名、ProviderSeq 单调序号、连接（Channel）生命周期管理。TEE 对流式会话只做 TLS 加解密、双向字节计量与下行明文摘要，不解析任何 WebSocket 帧。TEE 不可见 model、不可见 tenant、不可见任何账务字段——JobSpec 是纯粹的「要执行的 HTTP 请求」描述（键 1–15，其中键 15 是随作业携带的加密凭证信封，见第 7 节）。

**Hub**：持有全部需要理解业务语义的逻辑。用户面 API（/v1/chat/completions、/v1/messages、/v1/responses、/v1/session、/v1/models 模型目录）、模型到 Provider 的最低在线价调度、配额、计价与佣金、账本、回执审计、usage（token 用量）解析、重试与故障回退。Hub 还承担反向隧道的两端服务器角色（见第 4 节）：Agent 拨入的注册门（AgentGate）与 TEE 拨入的中继端点（TeeRelay）。Hub 只持有加密的凭证信封（见第 7 节，键 15），永不见明文 token、不接触 TLS 密钥。

**Provider Agent（tokenhive/provider）**：纯粹的反向隧道客户端。拨向 Hub 的 AgentGate 并保持一条多路复用 WebSocket；注册上线后，对 Hub 在隧道上打开的每条中继流，拨向一个固定的允许列表（allowlist）之内的上游 host，然后双向复制字节。Agent 不读取所搬运的字节——TEE 与上游之间的 TLS 会话端到端加密，Agent 只看到自己并未参与会话的一段密文。隧道断开后 Agent 按指数退避重连（起点 1s、封顶 30s，连接成功后重置），每次等待带随机抖动：退避保证单个 Agent 不会以固定速率猛打一个宕掉的 Hub，抖动保证"同一时刻一起掉线"的机群不会在同一时刻一起回来形成锁步尖峰。注册时可**可选声明**自己的上游能服务哪些模型（见第 4 节）；从 CLI 不带 `-models` 启动即视为配置了自动发现：Agent 在拨 Hub 之前向上游惯例的 `/v1/models` 端点拉取一次模型清单，**拉取失败或列表为空即报错并拒绝上线**——一个无法证明自己能服务什么的 Agent 绝不静默地以"服务一切"注册。注册消息未携带模型清单的 Agent（内嵌 provider 包、不配置自动发现的形态），Hub 视为服务任何模型。

**上游服务商**：只看到 Provider 的出口 IP 与其发来的请求，不知 Hub 与 TEE 的存在。

职责呈现为一条清晰的界：TEE 是连接的建立者与保持者、字节的搬运者与计量者；Hub 是语义的持有者（调度、计价、帧语义）；Agent 是密文的纯转发者。Provider 的凭证只在 TEE 手里，密钥不出 TEE，计价与资源边界全部落在 Hub 侧账本上。

---

## 4. Hub 的反向隧道服务器

Hub 侧维护两个 WebSocket 端点，这是它作为「NAT 背后贡献者和 TEE 的汇合点」的存在方式。两端的处理逻辑在 tokenhive/hub/agenthttp.go 与 agentnet.go。

**AgentGate（/v1/agent）**：Agent 拨入以在线。握手时校验 Agent 预设的共享密钥（agentKeyMatches 做常数时间比较，任何与该 provider 在 Hub 密钥表（-agent-keys）中的密钥不匹配的握手中断），随后把连接包成多路复用隧道，等待 Agent 的第一条控制流。控制流的开流元数据是 AgentRegister——它声明为哪个 provider 出口、可选展示名、可选的自我报价（SelfPrice）、**可选的模型清单（Models）**，以及**密封在 `Credential` 里的 token**：Agent 从 Hub 的 /v1/credential-key 拉取 TEE 收件公钥，把自己的 token 加密成凭证信封（tee.EncryptCredential）后随注册上报，Hub 只把密文信封存入凭证库、永不见明文。每个 agent 每次拨入都要取一次收件公钥，因此 Hub **只合并在途的拉取**：同一时刻到达的调用共用一个到 TEE 的往返，结果分发给全部等待者后即丢弃，下一个调用者仍重新读 TEE。之所以不做 TTL 缓存：收件密钥在 TEE 每次重启时轮换，缓存会在重启后的整个 TTL 窗口内把已作废的公钥发给每一个重连的 agent，它们封出的信封新 TEE 根本打不开——反而把一次重启拖成更长的故障。Models 是软能力提示：非空时该 Agent 只作为这些模型的候选；为空则该 Agent 服务任何模型。Hub 随后用部署白名单按 host+path 预检该 Agent 的上游（`Policy.AllowsRoute`，覆盖 Hub 暴露的全部路由），不通过即拒绝其上线——卖家"卖什么"由自己声明，但"能不能连"由部署决定。控制流保持打开期间该 Agent 视为在线；控制流一旦关闭，Agent 从调度器离线、隧道拆除，Hub 同时从凭证库撤销该 provider 的信封。Agent 未声明自价时接受 Hub 为该 provider 声明的平台默认价；若 provider 无平台默认价，该 Agent 无法注册。

在线注册表（agentRegistry）以 provider 为主键：同一 provider 任一时刻只有一个在线 Agent，后注册者顶掉先前者并关闭其隧道（杜绝同一 provider 的双重身份与陈旧隧道）。每个在线 Agent 连同其有效价与声明的模型清单一起登记，调度器只把新工作路由到此刻在线且（若声明了清单）清单含该模型者。

**TeeRelay（/v1/relay）**：TEE 拨入以承载出站。TEE 的每条流以 RelayOpen 元数据打开，声明要走的 provider 与上游 host；Hub 查在线注册表拿到该 provider 的 Agent 隧道，以同名的上游 host 作为 UpstreamOpen 打开一条中继流，然后把两条对向复制。中继只搬密文。如果该 provider 当前无在线 Agent，Hub 直接关闭这条流（没有专门的哨兵错误，与任何一次普通流关闭不可区分），调用方（transport）视为普通连接失败并交给下一个候选 provider。

两个端点的 WebSocket 升级均使用传入的 Upgrader（跨进程/测试共享）。生产环境 Hub 与 TEE、以及 Hub 与 Agent 之间应置于受信网络边界之内（TeeRelay 尤其应落在与其余 Hub↔TEE 通道相同的 mTLS 后；见第 9 节）。

---

## 5. TEE 侧的出站路径

TEE 的出站不知道任何 Agent 地址；它只有一个 Hub 中继端点。tokenhive/transport 拆成两层。

ChannelManager（transport/channel.go）持有连接驻留语义：以 (provider, host) 为键的通道池，空闲连接在窗口内不关闭（连接「一直保持」由此落实），同一时刻一条 HTTP/1.1 连接承载一个在途请求，异常后整体作废不再复用半开连接。它满足 tee.Transport 与 tee.SessionOpener 两个接口，tee.Service 主体流程（校验 → 授权 → 注入 → 执行 → 摘要 → 签回执）与 /v1/execute 线格式不因连接模型而变。

Relay（transport/relay.go）是 ChannelManager 的拨号器：持有与 Hub TeeRelay 的一条持久多路复用隧道，把每条 (provider, host) 拨号变成隧道上的一条流，以 net.Conn 的表面（streamConn）交还给 TEE，让 TLS 握手照常在 TEE 内完成。隧道掉线则重建一次并重试该流。TLS 永远在 TEE 内终止——Hub 与 Agent 看到的都是这条 TLS 会话的密文。

ChannelConfig 的 egress 配置：RelayURL（经 Hub 中继，生产形态与本地仿真均如此）；不设 RelayURL 时 ChannelManager 直连 req.Host（仅用于嵌入式 transport 测试与同机模拟）。无论走隧道还是直连，TLS 都在 TEE 内终止，隔离性相同。

**连接池与时间语义**。池以 (provider, host) 为键：空闲连接在 IdleTimeout 窗口（默认 5 分钟）内驻留复用，后台回收器按窗口一半的周期清扫过期连接（不依赖新请求驱动）；每键并发上限默认 32，超限的获取排队等空位（尊重 ctx 取消）。ALPN 锁 HTTP/1.1，一条连接同一时刻只承载一个在途请求；半开连接整体作废、绝不回池复用，零字节写入的失败重拨一次（未上线的字节不重复花费）。流式会话（OpenSession）不池化，由打开者独占使用后关闭。每条流的读写 deadline（SetDeadline/SetReadDeadline/SetWriteDeadline）以关闭该流强制执行、不影响兄弟流，代号计数器保证「清零 deadline」能作废已在途的旧回调，边界处完成的交换不会拿到一条随即被关的连接；会话握手期受 ctx deadline 约束，建立后解除，改由会话自身空闲看门狗管辖。

---

## 6. 业务规则：最低在线价调度与账务

调度、计价、账务全部在 hub 包内，全部可在 ScriptedTEE 毫秒级单测中验证，不经网络。

**最低在线价调度**。用户只声明 model，不声明 provider。providersForModel 产出候选：**供应 = 此刻持有一条在线隧道的 Agent**——离线即退出候选，挂单（自报价）随之消失，绝不回落到市场默认价继续调度（一个无人持有隧道的 provider 不该收到任何新作业）。按有效价（PerRequestMicros 加该 model 的加价）升序排列，同价按 provider 名破序使顺序成为供应的纯函数。在线 Agent 的自报价即其有效价（h.card 同时供调度与结算读取，报价与实收不漂移）。唯一的例外是**不承载 Agent 注册的 Hub**（未配置 -agent-keys，如仅对脚本替身的嵌入业务测试）：它没有"在线"概念，直接用静态市场表做供应，让单测在不引入真实隧道的前提下验证定价与排序。ExecuteForModel 按序尝试，失败回退次低价；一旦某 provider 的首个字节已被透传给用户，即视为已绑定该 provider，不再中途切换（避免两份回执拼凑一个用户不可解析的响应）。

**声明的模型 = 软能力过滤**。Agent 注册时可声明 Models；声明过的 Agent 只作为清单内模型的候选（发一个它上游没有的模型只会白买一次拒绝），未声明的 Agent 服务任何模型。当某模型不在任何在线 Agent 的清单里时，请求以"无 Provider 服务该模型"拒绝，而不是朝每个 provider 各打一枪。买家的**模型目录 `GET /v1/models`** 就建立在这份声明之上：列出所有在线 Agent 声明过的模型，每行带调度器此刻实际会派发的最低在线价与对应 provider；目录完全由 Hub 内存中的在线注册表算出，**不向任何 Agent/上游发起探测**（买家的浏览动作不产生任何询价流量）。可选 `?q=` 子串查询在目录上做大小写不敏感的包含匹配，供买家按精确 ID 或名称片段（"deepseek" 命中 "deepseek-pro"/"deepseek-flash"）检索。

**计价与佣金**。买家应付 = 卖家价 ×（1 + 佣金率）。沿用整数微单位与溢出检查（溢出报错不回绕）。账本（Ledger）记录 dispatched/verified/settled 计数、以及按 provider 的收入口径与 Hub 佣金口径；Provider 始终拿到自己费率卡上的全额，佣金单独追踪。计费按**实际转发字节**而非 cap 或回执总量：TEE 整块拒绝越过 MaxResponseBytes 的 chunk，回执的 ResponseBytes 含从未转发的溢出量，转发流由回执 StreamHash 绑定，故用 Hub 转发流长度计价（首个 chunk 即超限时计零）。截断只挣流量费（无固定费与加价），完整 2xx 才挣固定费，4xx/5xx/失败按零。回执先落库后入账：store 失败即零费用，买家重试不二次付费；调度把计价为正的尝试视为最终（付费截断后不再回退，避免一题两付）。会话上行比对只拒「回执声称多于 Hub 计数」的方向，收尾尾巴不整场作废；Hub 自行截断的会话按「断流 0 计价」。全部 Agent 离线时报 503（ErrNoProvidersOnline）而非 404。

**配额与回执**。配额在派发前检查，被拒请求不消耗 ProviderSeq——否则节流会在 provider 序列上穿孔，与 Hub 隐藏执行不可区分。回执在一切结算前验签与字节比对（MatchesStream 对先在足，流式摘要与 Hub 实际转发字节必须一致），对不上的回执一律不结算。

**结束证据与故障归因是两件事（未决）**。回执的 Completion 只说「这次传输是否完整」，不说「谁的错」。「平台（Hub/TEE）故障不收费、Agent（卖家）故障可收费、买家故障可收费」这条规则因此不能由完成标志落地：把被砍断的传输签成 Truncated 只是去掉固定费与加价、按已交付字节收流量费，而「不收费」要求的是整笔不结算，两者不是同一个动作。归因需要另外的材料。

**请求路径已经闭合**。分帧、流重置（ErrStreamReset）、载体失败（ErrTunnelFailed）三者都会变成非 EOF 错误，所以被中途砍断的 2xx 只能签 Truncated（首个字节都没送出的情况签 CompletionFailed，价格为 0），不存在「被砍断却按完整收费」的口子。

**会话路径仍未闭合，且有四处**。会话的流上没有分帧，「provider 的字节流结束」本身就是健康会话的结束方式，TEE 手里唯一的中断证据只剩传输层异常，于是：

1. `tee/session.go` 的 `pumpDownlink` 在向 Hub 写失败时静默返回 nil（其注释自述 "A Hub that vanished mid-stream aborts the relay silently"），回执照签 Complete。多数情况下回执要写回的正是那条已死的链路，于是回执丢失、Hub 报 ErrNoReceiptForSession 而不结算——结果符合「平台故障不收费」，但这是链路顺手拦住的，不是规则在起作用；若断的只是单向（写端坏、读端尚可），回执照样送达且写的是 Complete，就是全额收。
2. TEE 的会话空闲看门狗只关 Hub 链路、不碰 provider 流，多数情况下回执签不出来而结算不了；但「5 分钟没有数据」既可能是买方走人（可收）也可能是平台链路静默死掉（不可收），看门狗本身分不出来。
3. Agent 的 relay-idle 看门狗是干净关闭：回执 Complete、会话 WS 尚活、全额收。按「卖家故障可收」这是期望行为；但若真实原因是平台链路先静默死掉、Agent 只是收尾，归因就反了。
4. `Session.Write`（上行）失败完全不标记 truncated：`relaySession` 只 break，随后 `ss.Close()` 让 pump 那次未完成的读拿到由本地关闭造成的干净 EOF（正好落在 TLS 记录边界上是 io.EOF，落在记录中间才是 ErrUnexpectedEOF），回执于是常签 Complete 而会话 WS 尚活 → 全额收；而同一场故障若由下行先发现，走的是 ErrTunnelFailed → Truncated → 只收流量费。**同一场故障，谁先发现、以及 TLS 记录边界，决定买方付全额还是只付流量费。**

**归因材料在 Hub 手里，不在 TEE 手里**。Hub 有两个一手信号：自己这条 relay/session 链路出错（relErr != nil），以及在途会话所属 Agent 的隧道被注销（agents.deregister 的返回值）。缺的是「在途会话 → 所属 Agent」的对应关系；而 TEE 不该承担归因——职责最小化下它连 tenant 与 model 都不认识。要把三分法落地，应由 Hub 用自己的信号判断，而不是让回执多带一个它证明不了的字段。

**两个待定的业务问题**。其一，平台故障「不收费」还缺卖方侧条款：不结算意味着卖方也拿不到钱，而它上游已经为已交付的 token 付过费；现有 Truncated 规则（已交付字节挣流量费）是一种折中，要不要为平台故障额外补偿卖方是业务决定。其二，「卖家故障可收」要说清收谁：平台对卖家没有罚没手段（没有保证金、没有扣款接口），唯一杠杆是少付，所以它实际的含义是「买方照付 + 卖方照拿」。最后一条界碑：不要为绕开这些口子去放宽 Completion 检查——那会把「被砍断」重新洗成「完整」，方向正好相反。

---

## 7. JobSpec 与键号现状

JobSpec（tokenhive/jobs/spec.go）是 Hub 交给 TEE 的作业描述，其哈希签进回执，供 provider 事后核对凭证用途。它是「凭证使用授权」的载体，不携带任何网络拓扑或账务元数据。

现有键号连续编号 1–15：1 Version、2 JobID、3 Provider、4 Method、5 Host、6 Path、7 Query、8 Headers、9 BodyHash、10 Nonce、11 ExpiresAt、12 MaxResponseBytes、13 Stream、14 Session、15 Credential。没有空缺。键随规格的演进重新连续编号是刻意的：键号属于线格式的一部分，一旦发布不可重用或重编号；当前连续 1–15 是发布时点的确定性快照。其中键 3 是**卖家 Agent 的身份**（一个 Agent 一个名字、一把 key，同时是回执归属、单调序号与 relay 配对的键），不是上游——上游由部署白名单按 host+path 约束。

Session（键 14，omitempty）标记流式 WebSocket 型会话请求：置位时 TEE 对上游做 HTTP Upgrade 握手而非普通请求，然后中继一条不透明双向字节管道。握手的帧与内容语义（掩码、分片、关闭握手、JSON）全部归 Hub；TEE 只搬运、计量、摘要。会话作业的 body 必须为空——它是一次握手，没有载荷。

---

## 8. 本地全栈仿真（harness）

仿真的目标是一条命令拉起完整链路在本机（Apple silicon）验证全部结构性设计，无需任何真实模型。组件与端口沿用：mockprovider（TLS，自建测试 CA）18080、其平文 /stats 18081（探测不扰动所报告的值）；faketee 18090；TEE 进程若干（18095、18096、18097、18098、18099、18091 等）；cmd/hub serve 默认 18085（同时挂载用户 API、/v1/agent 门、/v1/relay 中继）。状态统一落 .sim 目录（可用环境变量重定向）。

仿真的装配原则：cmd/hub serve 以 -agent-keys（per-provider 密钥表）与 -relay-key 启动，同时挂载 AgentGate 与 TeeRelay；Provider Agent 以 -hub、-key（本 provider 的密钥）、-provider、-targets 拨入；真实 TEE 以 -relay ws://…/v1/relay -relay-key 出站。三个角色（hub、agent、tee）的 CLI 参数即反向隧道拓扑的可读表达。仿真不要求证明的正确性（simulated 适配器的既定立场：证据字段结构与真实报告一一对应，只换信任根不换代码路径），但业务代码路径与真实 TEE 完全一致。

harness 场景矩阵覆盖：正常流、策略拒绝、provider 故障（401/429/truncate）、跨重启 ProviderSeq 续增、序列空洞审计、配额、真实 TEE 经反向隧道 + tap 抓包断言（Agent 只见密文、零凭证命中）、Agent 中途被杀优雅失败、epoch 轮换、超尺寸响应截断、连接驻留（N 请求恰一条上游 TCP 连接、断流后作废并重拨）、流模式会话、最低价调度与抽成、Agent 不带 -models 自动发现（经仿真 CA 拉上游 /v1/models）并登记模型目录、买家按精确/子串搜索目录、Hub↔TEE mTLS（TEE 发布 RA-TLS 证书、Hub 钉住且出示客户端身份、错钉/平文均被拒）。三层测试法不变：fake TEE 毫秒级业务测试、真 TEE 进程可信属性测试、接缝测试。一键运行入口为 bash tokenhive/harness/harness.sh；go test ./tokenhive/... 跑单元与跨包测试。

---

## 9. 安全边界与加固项

系统当前的安全边界按职责划定，并保留若干明确的加固项。

TEE 持有的凭证与 TLS 密钥不出 TEE；Agent 只看到密文，LaaS 无从越权读取注入头；JobSpec 无账务字段，TEE 无从泄露 model/tenant；回执的流式摘要 + body_hash 绑定 + ProviderSeq 单调性构成 provider 事后核对凭证未被越权使用的四段证据链（出口一致性、Policy 白名单绑定 attestation、回执签名与字节摘要、凭证用途自证）。

Hub 的 AgentGate 以共享密钥为门，拒斥未持密者的拨入。Gate 现在按 per-provider 密钥表（-agent-keys）校验：每个 provider 只能用自己的密钥拨入，注册因此绑定到该 provider，任何卖家都无法冒名注册他人（顶掉其在线隧道并截获流量）；不存在全局共享密钥。同时 Hub 要求 TEE 以 -relay-key 认证中继拨入，中继要求认证、不是开放代理。

Hub 的 TeeRelay 依赖网络边界自证（受信的 Hub↔TEE 通道）。任何能连到该端点的调用方凭 provider+host 可开一条到某在线 Agent allowlist 内主机的流；防线目前只有 Agent 的 allowlist。应把 TeeRelay 与其余 Hub↔TEE 通道放在同一 mTLS 之后（Upstream 加固项 2，与既有「生产启用 mTLS」的部署边界一致）。

切换真实云 TEE 的核对清单照旧效仿：签名 Epoch 由平台适配器提供，Hub↔TEE 启用 mTLS，attestation evidence 取回接口补齐，Channel 的 TLS 根证书换为系统根。平台适配器现状：**AWS SEV-SNP（sevsnp）** 是唯一真实路径，编译进 `-tags sevsnp` 构建，也是云上部署的唯一支持平台；本地仿真（simulated）默认编译进所有构建；**阿里云（alicloud）与腾讯云（tencent）为预留骨架**——平台标识与 fail-closed 验证器（收据一律以 `ErrAttestationNotImplemented` 拒绝）已就绪，待远程证明验证实现后即可启用。

---

## 10. 风险与边界

**手工 HTTP/1.1 的分帧风险**。请求侧自写部分只有序列化（无自动行为恰是安全属性），响应分帧交给 http.ReadResponse 由标准库消化；截断、超尺寸、chunked 有既有场景兜底，连接驻留补充 Keep-Alive 复用与作废重建的专项断言。

**仅支持 HTTP/2 的上游不可用**。ALPN 锁 1.1 是显式连接模型的前提；主流 AI API 兼容 1.1，h2 多路复用留待后续。

**长连接与故障的组合**。断流后半开连接必须整体作废；Agent 被杀时 TEE 签发 completion=failed 回执，进程不挂起。

**空闲窗口取值**。过短则「连接一直保持」名存实亡，过长则占用 Provider 出口资源；默认数分钟、可配置，真实运营按 Provider 意愿调整。

**流积压：重置与关闭必须可区分**。单流入站缓冲超过上限（8 MiB）即重置该流，而不去停顿共享读循环：一条慢流不能让整条隧道、乃至其它租户的流一起停摆。重置与关闭在两端都必须可区分——被重置的流，其读者排干已缓冲字节后拿到 `ErrStreamReset`（不是 `io.EOF`），对端收到带重置原因的关闭帧，且该原因能穿过 Hub 与 Agent 的桥接（桥接中有一侧 copy 以错误结束时，另一端以重置而非干净关闭收尾）。原因是回执语义：把被截断的传输当成完整结束，等于为从未送达的字节签名并计费；反过来，调用方自己的 `Close` 与重置竞争时也携带重置原因，不会把截断洗成完整。真正的干净结束（对端主动关闭、进程收摊）仍然以 `io.EOF` 收尾。隧道整体塌掉时（载体读写出错，或对端发来编帧无法接受的帧），其上每一流以 `ErrTunnelFailed` 收尾——读者与写者都是——同样不能与干净结束混淆：会话那条路上的流自身没有任何分帧，这是它能给出的唯一中断证据，把它抹平成一次关闭就等于允许把被砍断的会话按完整会话结算。