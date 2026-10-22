# 让 Hub 适配新 TEE：需要改的只有一处

> 目的：新 TEE 允许**一次请求跨越一次证书轮换**（在途交换由新 epoch 的 key 签名）。
> 生产 Hub 目前把收据绑到「承载它的那条 TLS 连接」上，会把这种收据判成 `invalid_evidence`。
> 本文给出最小改动。补丁见同目录 `hub-teeclient-pairing.patch`。

生产 Hub 的仓库是 `tokhive-mvp`，进程 `hive` 跑在 `~/tokhive-mvp`，TEE 客户端在
`hive/internal/teeclient/client.go`。

---

## 1. 结论

| 项 | 是否需要动 |
| --- | --- |
| `hive/internal/teeclient/client.go` | **要改**（把「收据 key == 连接证书 SPKI」换成「验收据自带的报告」） |
| `TEE_REVISION` / `.cache/reclaim-tee` | **不用动**。当前 pin 的 `c6a0980` 里 `platform/sevsnp.Verifier`、`platform.EvidenceVerifier`、`proof.Receipt.Identity()` 都已存在 |
| `go.mod` | 不用动（`sevsnp` 与已有依赖同一个 module） |
| TEE 侧 | 不用动 |

Hub 要改的**只有一个文件、一个函数**：`(*Client).attested`。其余是同文件的
字段/调用点/注释，以及同包的测试。

---

## 2. 现在的检查是什么

`hive/internal/teeclient/client.go`：

```go
// line 381
func (c *Client) attested(a *proof.AttestationRef, channel *tls.ConnectionState) error {
	...
	key, err := x509.MarshalPKIXPublicKey(channel.PeerCertificates[0].PublicKey)
	keyID := sha256.Sum256(key)
	if a.ApplicationID != c.expectedApp || !bytes.Equal(a.PublicKeyDER, key) || !bytes.Equal(a.KeyID, keyID[:]) {
		return ErrInvalidEvidence
	}
```

读法：**收据里签名的 key，必须等于这条连接握手时那张证书的 SPKI**。等价于要求
「一次请求开工时与结束时用的是同一把 TEE key」。轮换落在请求中间时，这条必然失败
——旧 epoch 的连接、新 epoch 的签名——于是 `attested` 返回 `ErrInvalidEvidence`，
`executionFailure` 把它翻成买家可见的 `invalid_evidence`，并且 `recycleNow()`
把连接标记作废。

（这条检查本身没有错：它用「握手时已用 `-expected-app` 验过的证书」来间接证明
「收据的 key 属于被度量的镜像」。问题只在于它借道连接，而连接是固定在握手那一刻的。）

---

## 3. 要改成什么

用**收据自带的 SEV-SNP 报告**证明 key 属于 pinned 镜像，而不是用连接。

`-evidence`（`TEE_EVIDENCE`，默认 **true**）让每份收据内嵌完整报告，报告里
`report_data` 绑定的正是签名 key 的 SPKI、PCR8 是镜像度量。于是「验报告」这件事
一次同时给出：① 这把 key 是硬件证明过的；② 它属于 `snp-app:<hex>` 这个镜像。
后者是跨 epoch 恒定的（轮换换 key、不换镜像），所以跨轮换的收据可以被独立验证，
无需与任何连接对齐。

改动清单（补丁已含）：

| 位置 | 改动 |
| --- | --- |
| `Client` 结构体 | 新增 `evidence platform.EvidenceVerifier` |
| `New` | 填 `evidence: sevsnp.Verifier{ExpectedApp: expectedApp}` |
| `newClient`（本地验收路径） | `evidence` 保持 nil；注释说明该分支比对 pinned 模拟身份，不验报告 |
| `(*Client).attested` | 签名改为 `attested(r proof.Receipt) error`；删掉 `channel` 与 x509/sha256 的 SPKI 计算；改判为 `a.ApplicationID == c.expectedApp` + 收据必须带报告 + `c.evidence.CheckEvidence(id)` |
| `(*Client).verify` | 去掉 `channel` 参数；改为 `c.attested(r)`；删掉 `c.recycleNow()` |
| `(*Client).recycleNow` | 删除（它只服务于那条配对失败） |
| `ExecuteStream` | `c.verify(...)` 不再传 `response.TLS` |
| 导入 | 去掉 `crypto/tls`、`crypto/x509`，加 `tokenhive/platform/sevsnp` |
| `connectionLifetime` 注释、`New` 注释、`attested` 注释 | 改写为「收据绑 enclave，不绑连接」 |
| `client_test.go` | 把 `TestReceiptsAreHeldToTheServingConnection` 换成 `TestReceiptsAreHeldToTheirEnclaveNotTheirConnection`；`channelCertificate` → `epochSPKI`；删掉 cadence 测试里 `recycleNow` 那一段；加 `evidenceStub`（单测造不出真 SEV-SNP 报告，sevsnp 自己的包测试负责真验证据） |

**为什么不能只删掉那三行比较**：`a.ApplicationID` 是收据自己声明的字符串，而签名
key 本身不受任何约束。只删比较、留下 `ApplicationID == expectedApp`，任何一把 key
都能签出一份声明 `snp-app:<pinned>` 的可计费收据 —— 等于收据可无限伪造。必须走
上面那条证据路径，它比原检查**更强**（原来只跑到「连接证书被验过」，现在是「这份
收据自己的报告被验过」）。

---

## 4. 两个部署前提（不改代码，但必须成立）

1. **`TEE_EVIDENCE` 必须为 true**（`tee -evidence`，默认 true）。改成 false 时收据
   只带 `EvidenceHash`，而 Hub 没有按 hash 取证据的 Fetcher，会一律判
   `invalid_evidence`。补丁在 `attested` 里对此 fail-closed（`len(id.Evidence) == 0`
   直接拒），所以出错时是明确的拒绝，不是静默放行。
2. Hub 仍然必须走 pinned mTLS 通道（`HIVE_TEE_*` 那套 `Deployment.HTTPClient()`），
   这一点补丁没有放宽：握手依旧按 `-expected-app` 验。

---

## 5. 落地步骤

在 Hub 机（`ubuntu@10.0.1.151`）上：

```bash
cd ~/tokhive-mvp
git apply /path/to/hub-teeclient-pairing.patch       # 若已 commit 过该文件，用 git apply -3
go build -o bin/hive ./hive/cmd/hive                 # 或 make build
go test ./hive/internal/teeclient/                   # 应全绿
```

补丁是针对 Hub 当前 HEAD（`cc1dcbb`）下的 `client.go`/`client_test.go` 生成的。

重启（现状是 tmux 会话 `tokhive` 里的裸进程，没有 systemd 单元）：

```bash
tmux capture-pane -t tokhive:0.0 -p | tail -5        # 找到 PID
kill <pid>                                           # Ctrl-C 对这个进程无效
tmux send-keys -t tokhive:0.0 'set -a; . /etc/tokhive/hive.env; set +a; HIVE_DEBUG=1 ./hive' Enter
```

重启后应看到三行自证：`TEE deployment configured …`、`TEE inbox key key_id=…`、
`Relay serves plaintext … sources=<tee-ip>/32`。

---

## 6. 这条线已经不存在：Hub 已按 §3 改完（2026-10-15 核对）

本节原来写的是「保持 `TEE_REQUEST_TIMEOUT` 与 Hub 客户端超时都 < 4 分钟，Hub 一行
都不用改」。那条线今天不再适用：**生产 Hub 已经换成验收据自带的证据**，跨轮换的收据
会被正常接受。只读核对（Hub 机 10.0.1.151，`~/tokhive-mvp` @ `2d2c863`）：

| 项 | 实测 |
| --- | --- |
| `(*Client).attested` 签名 | `attested(receipt proof.Receipt) error`，**不再收 `*tls.ConnectionState`** |
| 运行中的 `/etc/tokhive/hive` | 含 `receipt carries no inline attestation evidence`；旧配对失败串出现 **0** 次 |
| TEE 客户端超时 | `teeHTTPTimeout = 16 * time.Minute`（`internal/teeclient/deployment.go`）|
| 执行预算 | `defaultExecutionBudget = 15 * time.Minute`（`internal/service/inference.go`）|

§3 那张改动清单按历史记录看即可，补丁不用再打。

现在约束两边的是另一条：**15 分钟执行预算必须严格大于 `TEE_REQUEST_TIMEOUT`**。谁先
放弃谁决定这一单能不能结算。TEE 先切，留下的是 truncated 收据，Hub 仍按已交付字节
计费；Hub 先切，断掉的是一条字节已经到买家的连接，provider 干过的活什么都结算不了。
`crosshost.py` 因此注入 `TEE_REQUEST_TIMEOUT=14m`，常量注释里写着同一条推理。

---

## 7. 可选：补上对 TEE 503 的一跳重试

新 TEE 在「请求落到了一条已被轮换作废的连接上」时回 `503` +
`X-TokenHive-Epoch-Retired: 1`（`tee.EpochRetiredHeader`）。Hub 目前没有识别这个头：
`ExecuteStream` 只判 `response.StatusCode != 200 || media != "text/event-stream"`，
于是直接返回 `invalid TEE execution response`。

这条路径很窄（TEE 会主动关闭被轮换的旧连接，空闲连接被关闭时 `net/http` 自己会
重拨），但真遇上是买家可见的失败。若要补，位置就是 `ExecuteStream` 里
`c.http.Do(req)` 之后：**同一次调用内**按 `req.Close = true` 换新连接重试一次，
仅当状态码为 503 且该头存在时。这块**不包含在本次补丁里**。
