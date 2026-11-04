# 公开发布材料与独立验证

本页对应 Hive #200。发布者签名证明谁发布了清单；硬件证明说明回执签名密钥与被证明的执行环境的绑定。两种验证必须分别完成。当前工具已经支持清单签名，但仓库不会自动生成或信任一把正式发布密钥。

## 材料入口

- [应用发布与环境历史](../releases/catalog.json)：构建摘要、源码 commit、策略哈希、启用／停用事件与撤销记录。
- [构建和登记流程](tee-release-catalog.md)：实际 bundle 与构建 sidecar 的来源核对。
- [构建、部署与签名发布协作](release-publishing.md)：两人分工、源码与清单提交、tag 顺序和 Release 附件交接。
- [白名单源码](../policy/whitelist.json)：正式核对使用对应发布的源码 commit 及 bundle 内 `policy/policy.cbor`，不能把 `main` 的策略当作历史版本策略。
- [独立 verifier](https://github.com/tokhive/verifier)、[固定版本下载](https://github.com/tokhive/verifier/releases)、[网页验证器](https://verifier.tokhive.ai/)。
- [验证契约](https://github.com/tokhive/verifier/blob/main/API.md)、[可信边界](#可信边界)。

正式发布附件应包含：原始 `catalog.json`、对应 `.sig`、经过独立渠道确认的签名公钥及指纹说明、相关构建记录和可公开的产物摘要、验证器版本与下载校验和、合成业务请求生成的真实硬件回执及验证报告。未完成的材料应明确标记待发布，不用软件模拟回执替代硬件通过样例。

## 发布签名身份

使用 OpenSSH 8.2+ 的 SSHSIG 格式，固定 namespace 为 `tokhive-tee-release`。推荐单独的 Ed25519 发布密钥，不能复用 TEE epoch 密钥、Hive 客户端证书或 Relay TLS 私钥。正式密钥的生成、加密保管、备份和使用授权由发布负责人安排；工具支持通过 `ssh-agent` 使用已加载密钥，也支持指定私钥文件，不接收命令行口令。

公钥指纹可用以下命令读取：

```bash
ssh-keygen -lf /secure/release-signing.pub -E sha256
```

首次建立信任时，由维护者在独立维护的官网公告／组织安全渠道确认公钥指纹，并让用户与下载到的公钥比对。不能仅从待验证清单或同一附件读取公钥就称为独立信任。尚未公布并核实正式公钥前，不能把本地签名演练当作正式可信发布。

用户自行建立受信任的 `allowed_signers` 文件；下例的公钥部分必须替换为已核实的完整公钥：

```text
tokhive-release namespaces="tokhive-tee-release" ssh-ed25519 <independently-verified-public-key>
```

`tokhive-release` 是签名主体名称，由使用者在验证时明确指定。禁止将从清单读取的身份或公钥自动加入该文件。

## 签署正式清单

先审查并提交 `releases/catalog.json`，确认登记反映实际部署事实，再在同一个 checkout 执行：

```bash
git rev-parse HEAD
python3 deploy/release_catalog.py validate
python3 deploy/signed_release.py sign \
  --catalog releases/catalog.json \
  --key /secure/release-signing.pub \
  --signature /secure/output/catalog.json.sig
```

示例使用已加载到 `ssh-agent` 的公钥文件；也可使用受控私钥文件。工具只签署与当前 HEAD 完全相同的已提交清单字节，拒绝未提交修改，不覆盖已有签名文件。它不修改清单、不启用环境、不推送或上传任何材料。将该提交中的原始清单和签名一同发布；重新排版 JSON 会破坏签名。

命令打印清单来源 commit 和 SHA-256。签名覆盖原始清单字节，Git commit 是发布来源定位信息，不是由 SSHSIG 额外签入的字段；需要核对 Git 来源时，必须另行比较该固定提交中的文件字节。

### 签名密钥轮换和撤销

正常轮换时，提前在独立渠道发布新旧公钥指纹、切换时间和原因；可以让旧密钥签署包含新指纹的迁移公告，用户仍需根据渠道与旧密钥是否可信作判断。使用两个已核实公钥的短期重叠窗口后，移除旧公钥的未来发布权限。保留原清单、签名和公告，不覆盖历史附件。

旧密钥泄露时，不能只依赖旧密钥签署的新密钥声明。通过独立渠道恢复信任，更新用户的 `allowed_signers`，明确哪些旧发布需要重新核实。工具不自动下载或更新信任文件，也不具备可信历史时间戳；普通 SSHSIG 不证明签署发生在密钥泄露之前。

应用版本撤销与发布密钥撤销是两个操作。前者用 `release_catalog.py revoke` 追加记录，再签署、发布新的完整清单；后者更新独立信任渠道及 `allowed_signers`。

## 用户核对清单

从已确认的发布渠道取得原始清单与签名，用独立可信的 `allowed_signers` 执行：

```bash
python3 deploy/signed_release.py verify \
  --catalog catalog.json \
  --signature catalog.json.sig \
  --allowed-signers allowed_signers \
  --identity tokhive-release \
  --environment production \
  --output tee-production.json
```

先验证签名，再按现有 schema 校验并导出。未知环境、没有当前启用版本或当前身份已撤销时拒绝导出，输出文件不得已存在。该输出可交给 Hive 的 `HIVE_TEE_RELEASE_CATALOG_FILE`；环境和清单来源 commit 另行配置。Hive 当前加载器不直接验证 SSHSIG，部署者必须先执行上述核验。

这证明签名发布者曾发布这些字节，不证明这是最新清单或当前实例实际状态。旧的有效签名仍可能被重放；用户应从已确认渠道获取最新清单，并核对版本、日期、撤销公告及预期环境。离线材料不能保证获知后来发布的撤销事件。测试环境应使用实际登记的环境名，不为了让工具通过而冒用 `production`。

## 用户核对自己的回执

1. 在 Hive 的 Call Records 中打开自己的调用，按执行尝试下载原始 CBOR 回执；不同尝试分别验证。
2. 从已核实的发布记录取得应用身份和策略哈希，按调用时间核对实际启用区间及撤销情况。不要直接复制回执自己声明的应用身份作为信任来源。
3. 在网页验证器选择 **Receipt file**，填写可信应用身份，在 **Additional expectations** 中填写策略哈希；或使用固定版本 CLI：

```bash
tokhive-verify verify \
  --expected-app 'snp-app:<trusted-application-hash>' \
  --expected-policy '<trusted-policy-hash>' \
  --json receipt.cbor
```

4. 保存报告，分别查看签名、硬件证明、应用身份和策略检查。软件模拟证明必须失败。缺失材料应显示信息不足或失败，不能替换成通过示例。

CLI 也可以从买家 API 按请求 ID 下载，默认从 `HIVE_API_KEY` 读取买家 Key；测试环境须显式指定 `--api-base-url`。网页静态站点的文件模式不需要 Key，文件保留在浏览器；请求 ID 模式目前需要 verifier 自带的受限本地 bridge，不能将本地服务直接暴露到公网。

验证器当前不会自动读取清单或撤销公告，需先核对清单，再手动提供预期应用身份与策略；不能宣称仅打开网页就自动建立了发布信任。

## 真实硬件公开样例

只使用专门创建、内容可以公开的合成业务请求。原始回执和证据必须来自真实硬件实例，保留对应环境、版本、时间、执行 ID、下载文件 SHA-256、验证器版本、命令和预期结果。先在测试环境跑通，再在正式部署完成后补生产样例。

公开前检查回执的签名字段中是否含供应方路由标识、上游路径等信息，选择可公开的测试供给。不能删改回执再声称是原始签名证据。真实业务正文、Token、买家 Key、供应方邮箱、内部连接配置和私钥不进入附件。应用 bundle 可能包含部署证书或其他运行材料，发布摘要不等于自动授权公开整个 bundle；公开原始产物前逐项检查。

## 可信边界

- Hive 处理请求语义、调度和账务；TEE 注入凭据并建立上游 TLS、签署执行回执；Bee 转发密文，不读取买家正文。官方上游和第三方中转的身份按回执 host/path 区分；到达中转不等于直连官方。
- Bee 当前信任 Hive 下发的收件公钥，尚不防御恶意 Hive 替换公钥；普通 ProviderSeq 文件没有可信防回滚保证。
- 模型名与 usage 是上游声明。验证器不独立鉴定真实模型，也不重算 token。
- 买家 request ID 与 execution ID 的映射来自 Hive；request ID 本身不是 TEE 签名字段。
- 回执通过不等于正文已核对。Hive 当前下载不包含完整 JobSpec 或精确上游请求／响应字节；协议转换、压缩及历史恢复可能改变客户端看到的内容，不能靠重新序列化 JSON 凑出匹配。
- 固定库的 [SNP 验证](../shared/sev_snp_attestation.go) 拒绝 DEBUG 和非 VMPL 0，最低 TCB 为 `0xde1d000000000004`（按组成字段逐项比较）；[组合证明](../shared/snp_combined_verify.go) 和 [Secure Boot 校验](../shared/secure_boot.go) 的代码、内嵌公钥及根证书是具体行为依据。发布时应按所用 commit 链接这些文件并记录公钥指纹。AWS SEV-SNP／NitroTPM 组合证明的具体检查取决于固定验证器与 TEE 库版本。核对相应源码中的 AMD／AWS 根、Secure Boot 发布公钥、调试及 TCB 策略；不能把应用 `snp-app`、基础镜像 `snp-base` 和 SNP launch measurement 混称为同一哈希。
- 证书按当前时间验证；历史证书过期后可能无法通过，未实现可信历史时间戳验证。
- Hive 的失败请求诊断可能保留提示词和代码，按实际隐私政策和保留周期处理；TEE 证明不等于 Hive 不持有业务内容。
