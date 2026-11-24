# 住宅出口：VLESS TCP 入口

日期：2026-11-24
状态：已实现（Hive 侧接入外壳；Bee 与 TEE 零改动）
相关：[`residential-egress-market.md`](residential-egress-market.md) §2.6

## 1. 为什么加这个入口

买家手里常见的客户端是 Xray、sing-box、mihomo（Clash Meta）和 v2rayN，它们把 `vless://` 链接和订阅当成一等公民，而"HTTP CONNECT + `Proxy-Authorization`"要么需要手工填写，要么根本没有入口。为了不让"用哪个客户端"成为试用门槛，Hive 另开一个 VLESS TCP 监听面。

**只换接入外壳。** 两条入口在 Hive 内汇合到同一个 `egress.Service`：租约、目标策略、字节上限、并发流上限、卖家域名规则全部共用。买家不能靠"换一个入口"多用一个字节，卖家也不需要知道买家走的是哪条外壳（只在 `BEE_DEBUG` 的诊断行里看到 `entry`）。

## 2. 协议与服务端行为

VLESS 只有实现（Xray），没有 RFC。服务端接受的请求形状就是所有客户端都会发的那一种：

```text
version(1) uuid(16) addon_len(1) addons(n) command(1) port(2) atyp(1) address(m)
```

- `version` 必须为 0；其它值直接关连接。
- `addons` 被跳过（本实现不使用）。
- `command` 只接受 1（TCP）。2（UDP）与 3（Mux.Cool）在握手阶段就关闭连接——UDP 的理由见主文档 §2.2，Mux 与既有隧道复用重复，且会让错误模型翻倍。
- `atyp` 支持 IPv4 / IPv6 / 域名，但**IP 字面量会被目标策略拒绝**：买方客户端若自行解析域名并发 IP，Hive 不会把它交给 Bee 再解析一次。
- 成功时返回两字节响应头 `00 00`，随后是原始字节流；失败时**不写任何字节**，直接关闭——这正是 VLESS 表达"拒绝"的方式。

与 CONNECT 的差异只有一处流程：响应头在卖家 Bee 接受该流之后才发出，这样买家不会往一条不存在的隧道里灌数据。

## 3. 身份：UUID 从租约令牌派生

VLESS 的凭据是 16 字节 UUID，而 Hive 的签名租约令牌远长于 16 字节，装不进去。因此：

```text
uuid = HMAC-SHA256(HIVE_EGRESS_KEY, "vless|" + lease_token)[0:16]
       （置 UUIDv4 版本/变体位，输出 8-4-4-4-12）
```

- Hive 在创建租约时计算 UUID，并维护 `UUID → 租约` 的内存索引（与租约表同生命周期）。
- UUID 等价于"这条租约的代理口令"：买家本来就持有令牌，UUID 不额外泄露任何东西。反过来，泄漏的 UUID 也只能用到该租约释放、过期或用尽为止。
- Bee 不参与：它继续只验签租约令牌。
- UUID 不进日志、不进审计记录；查询租约接口会返回它，因为买家需要它来配置客户端。

## 4. 策略与计量（与 CONNECT 完全一致）

| 项 | 规则 |
|---|---|
| 端口 | 仅 80 / 443 |
| 目标 | 不接受 IP 字面量；域名由 Bee 解析，并按标记拒绝私网、环回、CGNAT、保留段 |
| 卖家规则 | 域名后缀黑白名单照旧，最长后缀优先，`bps: 0` 表示拒绝 |
| 字节 | 同一条租约的字节上限，两条入口共享；达到上限即关闭 |
| 并发 | 同一条租约的流上限，两条入口共享 |
| 租约 | 释放、过期即失效，正在跑的流由定时器关闭 |

## 5. 传输与部署

VLESS 自身不加密。公网入口必须是 **VLESS over TLS**，证书由 Hive 持有；明文监听只用于本机或内网联调。

| 变量（Hive） | 含义 |
|---|---|
| `HIVE_EGRESS_VLESS_ADDR` | 监听地址，例如 `0.0.0.0:8443`；不设则不开 VLESS 入口 |
| `HIVE_EGRESS_VLESS_CERT` / `HIVE_EGRESS_VLESS_KEY` | TLS 证书与私钥；必须**同时**设置，否则启动失败 |
| `HIVE_EGRESS_VLESS_PUBLIC` | 写进链接的 `host:port`（可带端口；省略端口时链接用 443） |
| `HIVE_EGRESS_VLESS_SNI` | 可选，TLS 客户端校验证书用的主机名，默认取 `PUBLIC` 的主机部分 |

约束与检查：

- `HIVE_EGRESS_VLESS_ADDR` 需要 `HIVE_EGRESS_KEY`，否则 Hive 拒绝启动。
- `HIVE_EGRESS_VLESS_PUBLIC` 需要 `HIVE_EGRESS_VLESS_ADDR`，否则链接会指向一个没人监听的地址，`hive config check` 报失败。
- 不设 `HIVE_EGRESS_VLESS_PUBLIC` 时，控制台与订阅**不输出** `vless://` 链接（入口可以是私有的）。
- 端口是独立监听面：证书轮换、防火墙与 CDN 规划都要单独考虑它，不要假设它和 443 的站点同一个入口。

## 6. 买家侧

| 端点 | 结果 |
|---|---|
| `GET /v1/egress/subscription?format=vless` | base64 编码的 `vless://` 列表，一行一条，订阅客户端直接导入 |
| `GET /v1/egress/subscription?format=clash&transport=vless` | mihomo 配置，`type: vless` 代理组 |
| `GET /v1/egress/subscription`（默认） | 原有的 CONNECT HTTP 代理组，保持不变 |
| `GET /v1/egress/leases/{id}/link` | 单条租约的 `vless://` 链接、到期时间、字节上限、并发上限 |

链接形状：

```text
vless://<uuid>@<host:port>?encryption=none&security=tls&type=tcp&sni=<sni>#tokhive-<lease>
```

## 7. 已知缺口与不做的事

- **没有半关闭**：隧道仍是双向 `KindClose`，客户端发完请求 `shutdown(SHUT_WR)` 会同时结束响应。这是 CONNECT 入口就存在的缺口（主文档 §2.1），不是 VLESS 引入的；VLESS 客户端更容易触发它，因为浏览器会大量复用连接。
- **没有 UDP / QUIC**：命令 2 被拒绝。QUIC 的正确位置是 MASQUE（主文档 §2.2）。
- **没有 REALITY / XTLS Vision**：不做流量伪装，也不做同机 splice，理由见主文档 §2.3。
- **没有多路复用**：一个 VLESS 连接 = 一条隧道流。浏览器会开很多连接，因此每条租约的流上限（默认 8）在 VLESS 下更容易被打满；要提升并发，买更大的 session block 或多买几条租约。
- **单个监听面**：不做端口跳跃、不做回落（fallbacks）。
- **协议无标准**：只有实现，客户端升级可能出现字段差异，因此验收需要覆盖 Xray、sing-box、mihomo 三家，而不是只测一家。

## 8. 验收清单

1. `hive config check` 在四种组合下的结果：全空、只有 `ADDR`、`ADDR`+`PUBLIC`、`ADDR`+`PUBLIC`+证书对。
2. 明文监听 + 内网客户端：握手、双向回显、目标策略（非 80/443、IP 字面量）、UDP 命令拒绝。
3. TLS 监听 + 真实客户端（Xray / sing-box / mihomo）：导入订阅、访问 443 站点、确认字节计量与租约上限一致。
4. 同一条租约在两条入口之间共享并发与字节：CONNECT 占满流后 VLESS 被拒，反之亦然。
5. 租约释放后旧 UUID 立即失效；过期后正在跑的流被定时器关闭。
6. 订阅三种格式的解析：base64 列表、mihomo VLESS 组、单条 link。
