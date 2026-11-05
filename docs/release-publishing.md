# TEE 构建、部署与签名发布协作流程

本文面向两类协作者：构建／部署负责人，以及持有正式发布私钥的签名负责人。目标是在不共享发布私钥、不改写原始构建来源的前提下，为真实部署提供可以独立核验的 GitHub Release 材料。

工具细节见 [TEE 应用身份发布清单](tee-release-catalog.md)；公钥信任、轮换、撤销和买家验证步骤见 [公开发布材料与独立验证](public-verification.md)。本文使用仓库已有的 `deploy/release_catalog.py` 和 `deploy/signed_release.py`，不依赖额外 Bash 封装脚本。

## 一、先区分几种文件

| 文件 | 内容与来源 | 主要用途 |
| --- | --- | --- |
| `<bundle>.build.json` | 构建时自动生成的原始 manifest，包含实际产物摘要、源码提交和构建时间 | 保存某次构建的来源，作为正式登记的输入 |
| `releases/catalog.json` | 全部已登记发布、各环境部署事件和撤销记录 | 维护版本历史，提供可信预期身份的发布依据 |
| `catalog.json.sig` | 使用发布私钥对原始 `catalog.json` 字节生成的独立 SSHSIG 签名 | 配合独立可信公钥核验清单的来源和完整性 |
| `tee-production.json` | 从完整清单按 `production` 导出的环境视图 | 供 Hive 加载并在 `/tee` 页面展示 |
| `catalog.commit` | 导出／签署清单所用的完整 Git commit，由发布流程保存 | 定位原始清单，不是镜像源码 commit 的别名 |

`signed_release.py sign` 和 `verify` 均只读取源清单，不修改 `catalog.json`。签名或导出输出路径已存在时，工具拒绝覆盖。维护完整清单后重新导出环境视图，不手动分别维护两份 JSON。

当前 Hive 不支持直接加载原始 `catalog.json`，也不直接验证 `.sig`。当前 CLI／网页 verifier 不自动读取发布清单或验签；用户先核验清单，再提供可信的应用身份和策略哈希。TEE 运行实例不读取发布签名文件。

## 二、两个人分别负责什么

| 责任 | 构建／部署负责人 | 发布签名负责人 |
| --- | --- | --- |
| 固定源码和构建输入 | 确定源码 commit，记录工具链与输入 | 审阅来源及交接材料 |
| 构建与部署 | 保留原始 bundle、manifest 和构建日志，核对实际运行身份与策略 | 不重新构建来替换已部署产物的来源 |
| 清单登记 | 通过工具登记发布和真实环境事件，提交审查 | 核对清单与构建／部署材料一致 |
| tag 与草稿 Release | 按约定固定清单提交，创建 tag 和草稿 Release，上传构建材料 | 核对 tag 指向的完整 commit |
| 发布密钥 | 不需要持有发布私钥 | 生成、保管、备份和使用专用发布私钥，公布公钥及独立指纹确认渠道 |
| 清单签名 | 交付确切清单 commit | 签名、验签，上传原始清单及签名材料 |
| 正式发布 | 补齐构建、部署和可公开样例 | 附件齐全后核对最终校验和，按团队授权发布 Release |

发布私钥不交给构建／部署人，不放进 TEE 镜像，也不与服务器 SSH 登录密钥、TEE epoch 密钥、Hive mTLS 证书私钥混用。签名负责人首次准备独立发布密钥；以后发布通常复用同一身份。TEE 重启或升级不要求轮换这把发布密钥。

## 三、源码提交 A、清单提交 B 与 tag

正常的新构建登记顺序如下：

```text
提交 A：本次 TEE 构建使用的源码，可能已有旧版本 catalog.json
  │
  ├─ 使用 A 构建 bundle 和原始 .build.json
  │    manifest.source_commit = A
  │
  ├─ 部署并核对实际运行身份、策略与环境状态
  │
提交 B：登记本次构建及已确认的部署事实
  │    catalog 中本次 release.source_commit 仍然是 A
  │
  ├─ 将发布 tag 固定到 B，创建草稿 GitHub Release
  │
  └─ 签名人检出 tag，签署 B 中的 catalog.json，补齐附件并发布
```

在这个流程中，A 不包含此次构建对应的新清单记录；该记录必须等构建完成、取得真实摘要后才能生成。A 可能包含以前的清单，因此不能说 A 一定没有 `catalog.json` 文件。

| 标识 | 指向什么 |
| --- | --- |
| `source_commit` | 实际编译本次 bundle 时使用的源码提交 A |
| 发布 tag | 本次发布材料与清单固定所在的提交 B |
| `catalog.commit`／`HIVE_TEE_RELEASE_CATALOG_COMMIT` | 实际签署和导出清单所用的完整提交 B |

如果清单通过 PR 合并，B 可以是包含该清单的最终合并提交，关键是签名人、tag 和所公布的原始清单字节一致。不得为了让 tag 与构建来源相同而把 `source_commit` 从 A 改成 B。

`catalog.json` 和 `.build.json` 都不放入被测应用 bundle。更新清单或为其签名不会改变已经生成的 bundle 或已部署应用的身份。此流程不要求从 B 重建镜像；若实际重新构建，应按新产物和真实来源重新核对。

## 四、构建／部署人准备材料

### 1. 保留构建时的原始文件

`cloudtest/snp/pack.sh build` 在编译前捕获源码来源，构建完成后计算实际归档和内部文件的摘要，生成：

```text
tokenhive-app-bundle.tar
tokenhive-app-bundle.tar.build.json
```

`crosshost.sh build` 归档时保存：

```text
cloudtest/bin/bundles/<sha256>.tar
cloudtest/bin/bundles/<sha256>.tar.build.json
```

下面仅说明 `.build.json` 的字段结构，尖括号是占位符，不是可登记的真实值：

```json
{
  "version": 1,
  "application_id": "snp-app:<bundle-sha256>",
  "bundle_sha256": "<bundle-sha256>",
  "bundle_size_bytes": 29911040,
  "app_binary_sha256": "<app-binary-sha256>",
  "policy_hash": "<policy-hash>",
  "policy_file_sha256": "<policy-file-sha256>",
  "ca_bundle_sha256": "<ca-bundle-sha256>",
  "source_repository": "https://github.com/tokhive/tee",
  "source_commit": "<full-source-commit-A>",
  "source_dirty": false,
  "bundle_kind": "tee",
  "built_at": "2026-11-04T05:47:59Z"
}
```

`application_id` 是 `snp-app:` 加完整 bundle 的 SHA-256。`policy_hash` 按 TEE 协议计算，用于回执策略核对；`policy_file_sha256` 是策略文件原始字节的普通 SHA-256，不能互换。`source_dirty` 按现有工具规则判断编译来源是否与 commit 一致，不表示工作树中的每个运维文件都没有改动。

当前 manifest 没有记录完整构建命令、Go 版本、构建容器和基础镜像信息。用原始构建日志或 `BUILD.md` 补充这些信息，以及输入摘要、基础启动镜像／AMI 的可公开标识、复现方法与限制。不要向现有 manifest 随意添加字段；其 schema 是固定的。

已部署版本优先从原构建机取回对应的原始文件，不需要为了提供材料重新部署。若原始来源记录缺失，说明缺失和能够独立核对的范围，不能在当前源码上为旧 bundle 重做 manifest 并冒充原始构建记录。

### 2. 核对部署、登记并提交清单

先固定计划使用的 Release tag 和 URL；新版本登记时可引用尚未发布的计划地址。登记命令会读取真实 bundle，核对其与构建 manifest 一致，再追加发布记录：

```bash
python3 deploy/release_catalog.py release \
  --bundle 'cloudtest/bin/bundles/<sha256>.tar' \
  --release-url 'https://github.com/tokhive/tee/releases/tag/<release-tag>'
```

已登记版本应保留原始 `release_url` 和构建来源，不为补附件强行改写历史。可在新的 Release 正文引用原记录和原发布依据。

应用在某环境实际生效后，才登记对应的启用事件。`production` 的启用时间应是 Hive 已实际切换并确认使用该身份的时间；只有 TEE 实例启动或 AMI 创建成功，不足以登记 Hive 已启用。没有实际启用事实时保留候选状态，不能为了成功导出 `tee-production.json` 而虚构事件。

校验并提交 `releases/catalog.json`，完成审查后确定提交 B。登记、启停和 `crosshost.sh record` 的完整命令见 [清单操作说明](tee-release-catalog.md)。

### 3. 固定 tag，准备草稿 Release

下面的 tag 和 commit 均为占位值，执行前替换为本次已审查值：

```bash
git tag -a '<release-tag>' '<full-catalog-commit-B>' \
  -m 'TEE release <release-tag>'
git push origin 'refs/tags/<release-tag>'
gh release create '<release-tag>' --verify-tag --draft \
  --title 'TEE <release-tag>' --notes-file /path/to/release-notes.md
```

这是先固定 tag、再建立草稿 Release，避免 GitHub 自动从未知的最新分支提交创建 tag。普通 annotated tag 不等于发布清单已签名。tag 一旦用于交接，不再移动；需要修改清单时使用新的发布标识和配套签名。

上传构建材料，将 tag、完整 B、应用身份、策略、原始 manifest 和公开材料列表交给签名人。草稿 Release 通常不对普通公众开放，正式发布前不能声称这些材料已经公开可下载。

## 五、签名人核对、签名和验签

### 1. 首次建立发布身份

在可信发布机器上准备专用 Ed25519 发布密钥，使用保护口令并安排备份。公开公钥和指纹，并在独立维护的官方渠道说明该指纹对应 Hive 正式发布身份。首次信任与轮换流程见 [发布签名身份](public-verification.md#发布签名身份)。

### 2. 检出约定 tag，确认清单来源

在独立且干净的 checkout 中执行，比较 `HEAD` 是否正是交接的完整 B：

```bash
git fetch origin tag '<release-tag>'
git switch --detach 'refs/tags/<release-tag>'
git rev-parse HEAD
git diff --exit-code HEAD -- releases/catalog.json
python3 deploy/release_catalog.py validate
```

核对清单中的 `source_commit`、应用身份、策略和构建摘要与交接材料一致。签名代表发布方认可清单声明，不自动证明源码确实生成了该二进制，也不能代替真实部署证据检查。

### 3. 生成新输出目录中的签名材料

以下命令在同一固定 checkout 中连续执行。密钥路径为示例，私钥应已加载到 `ssh-agent`；`release_dir` 每次创建新目录，避免覆盖历史材料：

```bash
ssh-add "$HOME/.ssh/hive-release-signing"
release_dir="$(mktemp -d)"

git rev-parse HEAD > "$release_dir/catalog.commit"
cp releases/catalog.json "$release_dir/catalog.json"

python3 deploy/signed_release.py sign \
  --catalog releases/catalog.json \
  --key "$HOME/.ssh/hive-release-signing.pub" \
  --signature "$release_dir/catalog.json.sig"

cp "$HOME/.ssh/hive-release-signing.pub" "$release_dir/release-signing.pub"
ssh-keygen -lf "$release_dir/release-signing.pub" -E sha256 \
  > "$release_dir/release-signing.fingerprint"

printf 'tokhive-release namespaces="tokhive-tee-release" ' \
  > "$release_dir/allowed_signers"
cat "$release_dir/release-signing.pub" >> "$release_dir/allowed_signers"

python3 deploy/signed_release.py verify \
  --catalog "$release_dir/catalog.json" \
  --signature "$release_dir/catalog.json.sig" \
  --allowed-signers "$release_dir/allowed_signers" \
  --identity tokhive-release \
  --environment production \
  --output "$release_dir/tee-production.json"
```

验签使用的是将要公开的副本，因此复制后源清单发生变化也不能悄悄产生不配套的附件。发布前再次确认 checkout 仍为约定 B，副本与该提交的原始清单字节一致。若任一步失败，停止发布并排查，不把部分输出当作完整发布包。

`allowed_signers` 在这里用于发布人自检。用户即使下载到同一个文件，也必须先从独立渠道核实公钥指纹，不能把发布附件自带的公钥自动视为可信。

`production` 没有当前启用版本或当前版本已撤销时，验签导出命令会失败。不要改填其他环境或修改历史来绕过拒绝；先核实部署状态是否满足正式生产发布条件。

## 六、Release 附件和最终发布

| 材料 | 提供者 | 说明 |
| --- | --- | --- |
| 原始 `<bundle>.build.json` | 构建／部署人 | 对应本次实际产物，不用事后改写的副本代替 |
| `BUILD.md`／固定构建日志链接 | 构建／部署人 | 补充工具链、构建输入、基础镜像和复现范围 |
| 部署说明 | 构建／部署人 | 可写入 Release 正文；记录实际环境、身份、策略和启用依据 |
| 合成请求的真实硬件回执、证据与验证报告 | 构建／部署人 | #200 的生产演示材料；完整证据已内嵌时无需重复独立 evidence 文件 |
| `catalog.json`、`catalog.commit` | 签名人 | 固定提交 B 的原始清单及来源信息 |
| `catalog.json.sig` | 签名人 | 与原始清单逐字节配套 |
| `release-signing.pub`、`release-signing.fingerprint` | 签名人 | 配合独立官方指纹确认渠道 |
| `tee-production.json` | 签名人，可选附件 | 验签后导出的 Hive 配置，能够重新生成 |
| `allowed_signers` | 签名人，可选示例 | 不是自动建立用户信任的依据 |
| `SHA256SUMS` | 最终发布人 | 所有最终附件准备好后生成，排除校验和文件自身 |

Release 正文还应说明版本变化、A 与 B、应用身份、策略哈希、构建与部署依据、公开验证教程、独立公钥确认渠道，以及固定版本 verifier 的下载链接。Verifier 二进制由 verifier 项目的 Release 提供，不要求复制进 TEE Release。

可公开文件全部放入交接目录后再计算最终校验和，加入新附件后须重新计算。签名脚本若只计算自身生成的文件，不能将那份结果冒充覆盖后来添加的构建记录或样例。

完成核对后，由约定的最终发布人将草稿 Release 发布。保存原始清单、签名、manifest 和历史附件；后续变更使用新的发布，不静默覆盖已发布文件。

### 签名实际覆盖范围

- SSHSIG 直接覆盖原始 `catalog.json` 字节。任何空格、换行或字段变化都需要重新签名；通常可以继续使用同一把发布密钥。
- 登记时写入清单的构建字段受到该签名保护，但独立 `.build.json` 文件的排版、额外构建日志、`BUILD.md` 和样例附件并未因此自动得到文件级签名。
- `catalog.commit` 是定位信息，没有被 SSHSIG 额外签入。核对来源需要比较固定提交中的清单字节。
- 普通 `SHA256SUMS` 用于文件完整性检查，不独立证明发布者身份。构建产物应与已验证清单中的摘要核对。
- 有效签名不保证清单最新，也不证明实例此刻状态。用户仍需核对最新发布、撤销公告以及真实硬件证据。

仅公开已检查适合公开的材料。原始 bundle 是否可公开取决于其内容；不能因为有 manifest 就自动上传可能含部署密钥、私有证书材料或内部配置的归档。样例使用合成请求和可公开测试供给，不能修改签名回执来隐藏字段后仍称其为原始证据。

## 七、交付给 Hive 与后续变更

需要更新 Hive 展示时，将验签导出的环境视图送至 Hive 配置目录：

```dotenv
HIVE_TEE_ENVIRONMENT=production
HIVE_TEE_RELEASE_CATALOG_FILE=/actual/path/tee-production.json
HIVE_TEE_RELEASE_CATALOG_COMMIT=<full-catalog-commit-B>
```

Hive 在启动时读取该配置，因此更新视图及来源配置后应重启 Hive。发布签名本身不要求重启或重新部署 TEE。环境视图只用于发布信息展示，不替代 `HIVE_TEE_EXPECTED_APP` 等运行时信任配置。

TEE 发版时检查 verifier 兼容性：仅修改清单、签名、文档和发布工具通常无需更新 verifier 的 TEE 库依赖；应用或策略变更但证明协议兼容时，核对新的可信预期身份和策略；证明格式、回执协议、验证规则变化或验证库安全修复需要评估并发布新版 verifier。

应用撤销、发布密钥撤销和运行 epoch 密钥轮换是不同操作。按各自流程处理并保留历史，不把一次清单签名或生产实例启动视为整个 #200 已完成。
