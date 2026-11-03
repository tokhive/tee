# 从零部署 TEE：运维移交手册

本文是移交给运维的从零部署手册，覆盖四件事：造信任根、造证书、打镜像、起机密实例。读者不需要读过本仓库的其它文档，但需要一台 Linux 构建机和 AWS 权限。

适用范围：双机部署，一台普通机器跑 Hub（仓库 `tokhive-hive`），一台 SEV-SNP 机密实例跑 TEE。本仓库只交付 TEE 侧；Hub 的代码与进程管理在另一个仓库。

## 0. 先理解三套材料，别混

| 材料 | 内容 | 谁在用 | 生成次数 |
| --- | --- | --- | --- |
| Secure Boot 信任根 | `PK.key`、`KEK.key`、`R.key` 及对应证书/ESL/`aws-uefi-data.b64` | 固件验 UKI 签名；Hub 验固件事件日志 | 一次 |
| mTLS 证书 | `hub-ca`、`hub-cert/key`、`mp-ca`、`mp-cert/key` | TEE 验 Hub 客户端证书；TEE 验 mock provider | 一次 |
| 白名单 | `policy/whitelist.json` → `policy.cbor` | TEE 逐请求执行；Hub 按同一份字节准入 | 每次改规则 |

两条不可逆的线，先记住：

1. **mTLS 的 CA 只生成一次。** 它被烘进 AMI 的 bundle（`/run/bundle/mtls/hub-ca.pem`），之后重建 CA 会让已注册的 AMI 静默失效。
2. **R 轮换必须同时重编 Hub。** Hub 的 release 公钥是编译期 `//go:embed` 的（`shared/secure_boot.go`），不是运行期配置。只换 TEE 不换 Hub，attestation 一定被拒。

## 1. 构建机与云前置

构建机：Linux amd64，能跑 Docker。以下命令以 Ubuntu 为例：

```bash
sudo apt-get update
sudo apt-get install -y openssl efitools docker.io qemu-utils python3-venv
# 另需：AWS CLI（v1、v2 均可）、Go 1.27.3+、GNU tar

# uefivars 装进独立 venv，再软链到 /usr/local/bin。
# Ubuntu 24.04 的系统 Python 受 PEP 668 保护，直接 pip install 会被
# externally-managed-environment 拒绝；装到用户目录又常常因为
# ~/.local/bin 不在 PATH 而找不到命令。
sudo python3 -m venv /opt/uefivars
sudo /opt/uefivars/bin/pip install -q uefivars
sudo ln -sf /opt/uefivars/bin/uefivars /usr/local/bin/uefivars
uefivars --help >/dev/null && echo "uefivars ok"
```

如果已经跑过 `pip install uefivars` 但 `command -v uefivars` 为空，先定位它装到哪：

```bash
python3 -m pip show -f uefivars | grep -E 'Location|bin/'
```

脚本在 `~/.local/bin` 时把该目录加进 PATH（`export PATH="$HOME/.local/bin:$PATH"`）即可；若报 `externally-managed-environment`，说明被 PEP 668 拦下，按上面的 venv 方式重装，不要用 `--break-system-packages` 绕过。

确认 Docker 可用（构建要在容器里做 UKI 组装）：

```bash
docker info
```

AWS 侧：

- 区域用 `eu-west-1`（`cloudtest/config.py` 的 `DEFAULT_REGION`）。
- 实例类型用 `c6a.large`。代码默认值是 `m6a.large`，**必须在 `cloudtest/.env` 显式覆盖**，否则会按默认值起机。
- 执行身份附加 `cloudtest/snp/iam/aws-snp-policy.json`。若用 IAM 用户：

```bash
aws iam put-user-policy --user-name <你的用户> --policy-name TokenHive-SNP-Test \
  --policy-document file://cloudtest/snp/iam/aws-snp-policy.json
```

- VM Import 服务角色 `vmimport` 只需建一次：

```bash
aws iam create-role --role-name vmimport \
  --assume-role-policy-document file://cloudtest/snp/iam/vmimport-trust-policy.json
aws iam put-role-policy --role-name vmimport --policy-name vmimport \
  --policy-document file://cloudtest/snp/iam/vmimport-role-policy.json
```

配置文件（两份都不进版本库）：

```bash
cp deploy/.env.example deploy/.env
cp cloudtest/.env.example cloudtest/.env
```

`deploy/.env` 至少写：

```text
AWS_SNP_REGION=eu-west-1
GCP_PROJECT=placeholder          # AWS 路径不用于构建，但脚本要求非空
```

`cloudtest/.env` 至少写：

```text
TOKENHIVE_USER=<唯一值，例如你的名字>
TOKENHIVE_REGION=eu-west-1
TOKENHIVE_INSTANCE_TYPE=c6a.large
```

`TOKENHIVE_USER` 没有默认值，留空会直接拒绝运行；它同时是删除安全边界的另一半（`user` tag），不能随便填。

## 2. 从零造 Secure Boot 信任根

**只在还没有任何 AMI 时做这一步。** 一旦有镜像在跑，轮换 R 就要连同 Hub 一起重编（见 §11）。

所有命令在 `deploy/secure-boot/` 内执行：

```bash
cd deploy/secure-boot

for k in PK KEK R; do
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $k.key
  chmod 600 $k.key
  openssl req -new -x509 -key $k.key -out $k.crt.pem -sha256 -days 3650 \
    -subj "/CN=TokenHive $k"
  openssl x509 -in $k.crt.pem -outform DER -out $k.crt.der
  openssl pkey -in $k.key -pubout -out $k.pub.pem
  cert-to-efi-sig-list -g "$(cat GUID.txt)" $k.crt.pem $k.esl
done

# R 是 db 里的签名者，Hub 的验证锚就是它的公钥
cp R.pub.pem ../../shared/secure_boot_release_pub.pem
```

`GUID.txt` 沿用仓库固定值，不要重新随机：变量身份变了，事件日志里的条目也跟着变。

**手工核对公钥同步**（`snp-build.sh` 不会替你校验，它只检查 `R.pub.pem` 是否存在）：

```bash
openssl pkey -pubin -in R.pub.pem -outform DER | openssl dgst -sha256
openssl pkey -pubin -in ../../shared/secure_boot_release_pub.pem -outform DER | openssl dgst -sha256
```

两行必须相同。不同就直接停：构建能过，但 Hub 会在运行期以 `event log does not prove an R-only post-separator Secure Boot policy` 拒绝 TEE。

最后重建 UEFI 变量存储：

```bash
# 有旧 store 就以它为容器；没有就用发行版的 OVMF_VARS.fd（路径随包而异）
if [ -f aws-uefi-data.b64 ]; then
  uefivars -i aws -o edk2 -I aws-uefi-data.b64 -O vars.fd
else
  cp /usr/share/OVMF/OVMF_VARS.fd vars.fd
fi

# -i aws / -o aws 内部自己处理 base64：输入输出都是 .b64 文本。
# 不要再 base64 -d，也不要再 base64 -w0，否则会二次编解码。
uefivars -i edk2 -o aws -I vars.fd \
  --PK PK.esl --KEK KEK.esl --db R.esl -O aws-uefi-data.b64
```

命令应打印 `Replacing PK` / `Replacing KEK` / `Replacing db`。想再确认，跑 `uefivars -i aws -o json -I aws-uefi-data.b64`，输出里应只有 PK、KEK、db 三条变量。

`--PK/--KEK/--db` 会覆盖这三个变量。从零部署三份都用新 ESL；只轮换 R 时，PK/KEK 用原值。

私钥保管：

- `PK.key`、`KEK.key`、`R.key` 只存离线密钥库，至少两份、不同介质。
- 证书、`.crt.der`、`.pub.pem`、`.esl`、`GUID.txt`、`aws-uefi-data.b64` 是公开材料，留在仓库。
- `R.key` 是发布签名私钥，丢了就造不出同身份的新镜像；没泄露就没有安全问题，但恢复要轮换 R 并重编 Hub（见 §11）。

## 3. 从零造 mTLS 证书

在仓库根执行：

```bash
go run ./cloudtest/snp/gencerts cloudtest/snp/.certs
```

生成六个文件：

```text
hub-ca.pem  hub-cert.pem  hub-key.pem     # Hub ↔ TEE 的 mTLS 身份
mp-ca.pem   mp-cert.pem   mp-key.pem      # mock provider 的 TLS 身份
```

两个 CA 会随 bundle 进 AMI；`hub-key.pem`、`mp-key.pem` 是秘密。**这一套只生成一次**，生成后立刻备份 `.certs/`。之后任何重建都不能删掉它再跑 `gencerts`：新的 CA 和已注册 AMI 里的旧 CA 对不上，TEE 会拒绝 Hub 的客户端证书。

如果确实要轮换 CA，做法是重造 `.certs/`、重打 AMI、重部署 Hub，三者一起换，不能只换一边。

## 4. 白名单

唯一来源是 `policy/whitelist.json`。构建时 `crosshost.sh build` 的 `ensure_policy` 会跑：

```bash
go run ./cmd/tee -emit-policy-dir <目录>
```

把文档转成 `policy.cbor` 再打进 bundle。白名单被 loader 一起测量，所以**改白名单等于改镜像**：`snp-app:` 摘要会变，Hub 的 `-expected-app` 也要跟着改。TEE 内没有运行期改写白名单的路径。

## 5. 构建 bundle 与 AMI

先提交代码，再构建。bundle 摘要包含 vcs revision，脏工作区会让摘要不可归属：

```bash
git status --short          # 应为空
cd cloudtest/snp
./crosshost.sh build        # 约 10-18 分钟
```

如果 `snapshot.ubuntu.com` 经代理大量 502，先在 `deploy/.env` 设 `SNP_APT_MIRROR=aliyun` 重跑；它只影响基础镜像的构建源，不改信任根与 bundle 摘要。生产可复现构建应切回 `snapshot`。

构建做的事：

1. 生成/复用 `.certs/` 与 `policy.cbor`；
2. `pack.sh` 打确定性 bundle（文件排序、owner/group 固定、mtime 固定为 `2025-01-01`）；
3. `snp-build.sh` 在 Docker 里组装两层镜像，用 `R.key` 签 UKI，注册 AMI；
4. `run.sh build` 交叉编译 `hub`、`agent`、`mockprovider`、`tee`。

产出四样，全部要记录：

```text
snp-app:<sha256>                     # 应用身份，Hub 必须 pin
cloudtest/bin/bundles/<sha256>.tar   # 与摘要对应的归档，deploy 要靠它取白名单
AMI snp-tokenhive（带 snp-app 标签） # 起机用
cloudtest/bin/{hub,agent,mockprovider,tee}
```

构建日志里的 `AMI <id> (snp-tokenhive) registered` 是成功标志。

## 6. 启动 TEE（双机：Hub 在另一台机器）

首次起机：

```bash
cd cloudtest/snp
TOKENHIVE_TEE_TIMING=summary \
  ./crosshost.sh up --tee-only --host-ip <Hub 私网 IP>
```

- `--tee-only`：只起机密实例，不创建普通主机、不起 Hub。
- `--host-ip`：Hub 的**私网**地址（TEE 视角）。省略会落到占位 relay，任务永远发不出去。
- `--new`：只在换机时加。它会让旧实例保留为 `superseded`，新实例起来后再回收；首次起机不需要。
- `TOKENHIVE_TEE_TIMING=summary`：每 30 秒一行聚合，适合长期运行。`full` 是逐请求一行，只适合有界排查。

起机后，在 Hub 侧改三项并重启：

```text
HIVE_TEE_ENDPOINT=https://<TEE 私网 IP>:18090
HIVE_TEE_EXPECTED_APP=snp-app:<构建输出的摘要>
HIVE_RELAY_ALLOWED_CIDRS=<TEE 私网 IP>/32
```

重启方式按 Hub 仓库的实际部署；当前部署是 `systemctl restart tokhive-hive`。改文件不重启不生效。

验收：

```bash
./crosshost.sh verify
# 从 Hub 机或同一安全组内执行；18092 只对组内成员放行
curl http://<TEE 私网 IP>:18092/timing
```

串口应出现：

```text
Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
SEV: SNP running at VMPL0
secureboot: Secure boot enabled
Loaded X.509 cert 'TokenHive R: ...'
extended PCR 8 with app_sha256
app pid=<n> uid=65532 broker pid=<n>
```

Hub 日志应出现 attestation 通过、`expected-app` 匹配、relay 建立。

## 7. 换机（零停机）

顺序不能反：先起新机，再改 Hub，最后删旧机。反了就是 Hub 指向死地址。

```bash
# 1) 起新 TEE，旧机保留
TOKENHIVE_TEE_TIMING=summary \
  ./crosshost.sh up --tee-only --new --host-ip <Hub 私网 IP>

# 2) 改 Hub 三项并重启，确认新 TEE 可用

# 3) 只回收被 `--new` 标记为 superseded 的旧机
./crosshost.sh down --superseded
```

`down --superseded` 会先确认当前 TEE 已记录且在运行，再按记录逐个核对双 tag；它从不按 tag 枚举。Hub 是否真的切过去了，它看不到，所以第 2 步必须人工确认。

## 8. 拆除与安全边界

```bash
./crosshost.sh down --dry-run     # 只列出会删什么
./crosshost.sh down --tee-only    # 只删 crosshost.json 记录的那台 TEE
./crosshost.sh down --superseded  # 只删换机遗留的旧机
```

**不要跑裸 `down`。** 它按 `tokenhive-TEE: true` 与 `user: <值>` 删除该用户名下所有 cloudtest 实例；如果 Hub 也带同一组 tag，它会一起消失。Hub 独立部署时永远用 `--tee-only`。

## 9. 交接清单

| 物品 | 位置 | 性质 | 交接要求 |
| --- | --- | --- | --- |
| `PK.key` / `KEK.key` / `R.key` | `deploy/secure-boot/` | 秘密 | 离线密钥库，两份异地；绝不进 git |
| PK/KEK/R 证书、ESL、`GUID.txt`、`aws-uefi-data.b64` | 同上 | 公开 | 随仓库交接 |
| `shared/secure_boot_release_pub.pem` | `shared/` | 公开 | 必须与 `R.pub.pem` 同 SPKI |
| `cloudtest/snp/.certs/` | `.certs/` | 含秘密 | 备份；CA 只此一份 |
| `cloudtest/bin/bundles/<digest>.tar` | `bin/bundles/` | 公开 | 保留与在跑 TEE 匹配的那份 |
| `cloudtest/crosshost.json` | `cloudtest/` | 状态 | 含 `tee.app_hash`、实例 ID，随部署保留 |
| `deploy/.env`、`cloudtest/.env` | 各自目录 | 含秘密 | 密码库；不入库 |
| AMI ID + `snp-app` 标签 | AWS | 状态 | 记入部署台账 |

## 10. 验收与排障速查

| 现象 | 先看哪里 | 结论 |
| --- | --- | --- |
| Hub 拒 TEE，`R-only ... policy` | 两处 R 公钥 sha256 | §2 的公钥没同步，或换了 R 没重编 Hub |
| `up` 报 `carries no snp-app tag` | AMI 标签 | 镜像不是本流水线注册的，重建 |
| `deploy` 报 `no archived bundle` | `bin/bundles/` | 该摘要的归档丢了；重建或重新 `up` |
| Hub 报 `attestation does not match` | 串口 `[loader] app_sha256` | 对齐 `crosshost.json` 的 `app_hash` 与 Hub 的 `-expected-app` |
| 上游 TLS 只发 ClientHello | `upstream TLS trust: ... -> N anchors` | `N=0` 说明根没进信任库 |
| 串口被 handshake 错误刷屏 | `cmd/tee/listenerlog.go` | 已折叠为每分钟一行计数；看第一行原因 |
| 一条日志都没有 | 实例是否有 instance profile | 没有 profile 只有串口；挂 `TOKENHIVE_TEE_INSTANCE_PROFILE` |

## 11. 四条硬约束

1. **R 公钥没有自动校验。** `snp-build.sh` 只检查 `R.pub.pem` 存在，不比对 `shared/secure_boot_release_pub.pem`。每次动 R 都手工跑一次 §2 的两行 sha256。
2. **换 R = 重编 Hub。** Hub 的 release 公钥是 `//go:embed`。`crosshost.sh build` 末尾会重编 Hub（`run.sh build`），所以先同步公钥再构建就一致；反过来就会运行期被拒。
3. **CA 只生成一次。** `.certs/` 一旦被烘进 AMI，就不能再跑 `gencerts` 覆盖。轮换要 AMI + Hub 一起重做。
4. **改任何被测字节都要重新 pin。** 代码、白名单、bundle 内证书，任一变化都改 `snp-app:` 摘要。Hub 的 `-expected-app` 与 `crosshost.json` 的 `tee.app_hash` 必须同步更新。

另外两条运行期约束：

- `TEE_EVIDENCE` 必须为 true（默认值）。生产 Hub 没有按 hash 取证据的 fetcher，hash-only 的收据会被判 `invalid_evidence`。
- Hub 的执行预算（15m）必须严格大于 TEE 的 `TEE_REQUEST_TIMEOUT`（14m）。TEE 先放弃留下 truncated 收据，Hub 仍可按已交付字节结算；Hub 先放弃就是一条字节已到买家、却什么都结算不了的连接。
