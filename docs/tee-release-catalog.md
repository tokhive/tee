# TEE 应用身份发布清单

`releases/catalog.json` 是供 Hive 用户页面及独立核对使用的版本化发布记录。它保存应用身份、策略哈希、构建来源、各环境的使用历史及撤销公告；通过 Git 提交和审查发布。`deploy/release_catalog.py` 负责生成构建清单、登记和校验记录，并导出指定环境的公开视图。该工具仅操作本机文件，不创建云资源，也不自动提交或推送；需要在部署机上一条命令完成“登记并提交”时用 `cloudtest/snp/crosshost.sh record`，它只提交 `releases/catalog.json` 这一个文件，且从不推送。

## 构建记录与正式发布

`cloudtest/snp/pack.sh build` 在编译前记录源码提交和工作区状态，在确定性 tar 完成后从实际归档字节计算应用身份，并生成 `<bundle>.build.json`。`crosshost.sh build` 与 `build-single` 归档 bundle 时，同时保存 `<sha256>.tar.build.json`，以后切换到其他源码版本仍可保留原始构建来源。

构建清单放在 bundle 外，不进入被测 tar，避免把自身摘要放进自身内容。以下信息均取自实际产物或构建过程，而非执行回执自己声明的值：

| 字段 | 含义 |
| --- | --- |
| `application_id` | `snp-app:` 加实际 tar 字节的 SHA-256；这是 verifier 的预期应用身份。 |
| `bundle_sha256`、`bundle_size_bytes` | 归档的摘要和字节数。 |
| `app_binary_sha256` | 归档中实际可执行 `app` 的摘要。 |
| `policy_hash` | 归档内实际 `policy/policy.cbor` 的回执策略哈希，对应 verifier 的 `Expected policy hash`。 |
| `policy_file_sha256` | 策略文件原始字节的普通 SHA-256，用于产物核对；不能代替 `policy_hash`。 |
| `ca_bundle_sha256` | 归档内实际公共根证书包的摘要。 |
| `source_repository`、`source_commit`、`source_dirty` | 编译前捕获并在编译后复核的源码来源；登记时不会改成当前检出的提交。 |
| `built_at`、`bundle_kind` | 构建结束时间与 `tee`／`single`／`stub` 类型。 |

策略哈希通过 `cmd/tee-policy-info` 复用 TEE 的规范 CBOR 解码和 `policy.Hash()` 计算，计算形式为 `SHA-256("TokenHive.Policy.v1" || canonical_policy_bytes)`。不使用当前源码中的默认策略替代归档内策略；自定义策略也按实际携带的字节核验。单独检查某份归档时可运行：

```bash
tar -xOf "$TEE_BUNDLE" ./policy/policy.cbor | go run ./cmd/tee-policy-info -
```

构建成功只生成候选清单，**不等于正式发布或已经启用**。缺少 Git 来源、源码不干净、缺失生产策略或公共根证书包，以及 `single`／`stub` 诊断构建均不能登记为正式发布。日常本机调试仍可生成带有不完整来源或 `source_dirty: true` 的构建清单。

需要 Unix 环境、Python 3.9+、Git 和本仓库要求的 Go 工具链。除 Go 模块依赖外，登记工具不需要 Python 第三方包，也不调用 AWS、GCP 或 Hive API。

## 新版本首次登记

1. 在干净、可核对的 Git 检出中运行现有打包流程，保留 tar 及其构建清单。
2. 检查实际运行程序、策略及根证书包，建立能够公开核对的发布说明或构建记录链接。
3. 登记清单，并将 `releases/catalog.json` 的变化交由 Git 审查。

下面的路径和 URL 是占位示例，不代表已登记的历史版本：

```bash
TEE_BUNDLE='cloudtest/bin/bundles/<sha256>.tar'
python3 deploy/release_catalog.py release \
  --bundle "$TEE_BUNDLE" \
  --release-url 'https://github.com/tokhive/tee/releases/tag/<release-tag>'
```

工具会重新读取归档，核对构建清单中的所有产物摘要，并要求来源干净、提交明确、生产输入齐全。正式记录保留构建信息，另外增加 `published_at` 和 `release_url`。相同来源及相同字节的重复登记保留首次记录；相同应用身份不能被换成另一份来源或发布链接。

发布说明链接和构建来源仍须人工审查。清单本身没有独立签名，也不是硬件证明；工具不会联网确认链接、重做完整镜像构建或证明该源码一定产生了该二进制。发布清单、可信构建流程与回执内的硬件证明各自承担不同的核对工作。不要自动把普通本机构建产物当成可信发布，也不要把可能含有测试私钥的诊断 bundle 作为公开附件上传。

首次引入时清单为空。不从文档片段、旧回执或当前环境变量猜测历史发布记录。旧版本缺少原始 bundle、当时的可靠构建记录或发布依据时，保持未登记；不能在当前源码分支给旧 bundle 重做清单，冒充其原始构建来源。

## 每次部署登记什么

每次部署引用已经登记的 `application_id`，同时登记环境和实际启用时间。应用身份对应的 `policy_hash` 已在发布记录里固定，无需再次手填。策略变化会改变被测 bundle，因此必须登记新应用身份与新策略哈希。

```bash
python3 deploy/release_catalog.py activate \
  --environment staging \
  --application-id 'snp-app:<64-character-lowercase-hex>'
```

默认记录当前 UTC 时间。补录时可显式传入 `--at '2026-11-03T08:00:00Z'` 或其他带时区的 RFC 3339 时间。时间应为 Hive 实际切换并确认使用该 TEE 的时间；启动实例、注册 AMI 或构建完成都不证明 Hive 已经切换，因此 `up`／`deploy` 都不会自动执行 `activate`。下一节的 `record` 把这两步合起来，同样需要人工触发。

切换到不同版本时，工具先追加旧版本的停用事件，再追加新版本的启用事件，两者使用同一个切换时间。回滚时重新引用旧版本，产生新的使用区间，不覆盖旧区间。各环境的状态相互独立。

单独停用某个环境：

```bash
python3 deploy/release_catalog.py deactivate \
  --environment staging \
  --application-id 'snp-app:<currently-active-identity>'
```

工具拒绝未知发布身份、与当前身份不符的停用、早于正式发布的部署，以及倒序插入同一环境的切换事件。它记录操作人声明的部署事实，不会自行检查远端 Hive 是否健康，也不会替操作人执行切换。

## 从部署机一键记录

`cloudtest/snp/crosshost.sh record` 把“登记发布”和“启用环境”合成一次操作，测试版与生产版都用它：

```bash
# 本机启动过、状态里记着 app_hash 的环境
./crosshost.sh record --environment staging

# 生产机不由本机启动时，身份从命令行给
./crosshost.sh record --environment production --application-id 'snp-app:<hex>'
```

它按顺序做五件事：从 `cloudtest/crosshost.json` 取 `app_hash`（或读 `--application-id`）；用 `archived_bundle` 取回归档并重算 SHA-256 核对；要求存在 `<sha256>.tar.build.json` 侧车文件；依次调用 `release` 与 `activate`；最后 `git commit --only releases/catalog.json`。`--release-url` 缺省为构建来源的提交链接，要指向发布说明或 PR 就显式传入；同一应用身份的链接必须保持不变，否则工具拒绝重新登记。

`--only` 意味着提交只含这一个文件，运维已经暂存的其它改动不会被卷进发布记录。提交后不推送：部署机在哪个分支上、什么时候推，不该由脚本决定。

不想记录时有三种做法，都不影响已有流程：

- `build`、`up`、`deploy` 从不调用 `record`。没有在某个环境真正服务过的构建不会进历史。
- `--dry-run` 只打印两条调用及其解析结果，不写文件也不提交，用来核对身份和链接。
- `--no-commit` 写清单但不提交，先看 diff 再决定。

环境名只接受 `staging` 与 `production`。名字是 Hive 导出视图的连接键，拼成 `prod` 不会报错，只会另起一段没人读的历史。只有侧车文件出现之后构建的 bundle 才能登记，更早的归档要重新构建一次才能拿到构建来源与策略哈希。

## 撤销与历史保留

停用表示某个环境不再运行该版本；撤销表示该发布身份不应再被启用，需要给出原因和公告依据：

```bash
python3 deploy/release_catalog.py revoke \
  --application-id 'snp-app:<64-character-lowercase-hex>' \
  --reason 'Reason for withdrawing this release' \
  --reference-url 'https://github.com/tokhive/tee/issues/<advisory-number>'
```

撤销不会删除发布记录或掩盖仍在运行的版本。导出结果会保留当前身份，同时将其状态标成 `revoked`。工具拒绝再次启用已撤销身份；操作人仍需停止或切换实际部署。

`releases`、`deployment_events` 和 `revocations` 三个数组仅允许追加。已有记录不能删除、重排或改写；修订通过追加事件和 Git 审查进行。CI 会将本分支清单与基准提交比较，阻止历史消失或被重写。

```bash
python3 deploy/release_catalog.py validate
python3 deploy/release_catalog.py validate --previous /tmp/previous-release-catalog.json
```

现有 verifier 尚未读取此撤销清单，不能据此宣称它会自动拒绝所有撤销版本的回执。历史身份保留也不等于历史证据永久可验证：当前 verifier 仍按当前时间检查硬件证书，已过期证据可能被拒绝。

## 交付给 Hive 用户页面

可直接读取经审查的清单，也可按环境导出公开视图：

```bash
python3 deploy/release_catalog.py export --environment staging --output /tmp/tee-staging.json
```

输出契约为：

- `version: 1`、`environment`：格式版本和环境。
- `current_application_id`：该环境最后一次登记且尚未停用的身份；无当前部署时为 `null`。
- `releases`：全部发布记录，含 `policy_hash`、来源、发布依据和派生的 `status`。状态为 `current`、`retired`、`available`（尚未在此环境启用）或 `revoked`；撤销记录另外带 `revocation`。
- `deployments`：该环境的全部使用区间，每项包含 `application_id`、`activated_at`、`retired_at`；仍启用时结束时间为 `null`。回滚后的相同身份保留多个区间。

Hive 后续应固定或记录读取的清单 Git 提交，把该环境的登记身份与实际启动配置比对，不匹配或未登记时明确显示未知。页面提供应用身份、策略哈希和发布依据，用户仍需独立决定是否信任相应发布。导出内容不包含实例地址、访问凭据或原始请求／响应，也不新增上游域名及路径的用户展示字段。

## 本地验证

```bash
go test ./...
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/tests -v
python3 deploy/release_catalog.py validate
```

测试使用临时 Git 仓库、合成 tar 和真实策略哈希实现；实际执行 `pack.sh` 的归档及 sidecar 生成流程时，只替换编译器为本地桩，不调用云 API。覆盖构建来源、策略规范编码、产物不符拒绝、诊断／脏源码拒绝、发布记录不被覆盖、回滚多区间、环境隔离、撤销及历史追加约束。这些结果不代替真实镜像构建、硬件证明或云部署验收。

2026-11-03 本地验证：15 个发布清单测试、`cmd/tee-policy-info`／`policy`／`internal/canonical` 三个 Go 包测试，以及现有 16 个跨主机脚本测试、6 个镜像打包测试通过；shell 语法检查、空清单校验和公开视图导出通过。所有镜像和部署相关测试均使用本地桩，未调用云 API；未构建、发布或切换真实 TEE 镜像。
