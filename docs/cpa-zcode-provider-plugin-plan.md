# CPA ZCode Provider 插件方案

## 结论

构建一个名为 `zcode` 的 Go CGO 动态库 Provider 插件，加载到 CPA/CLIProxyAPI 宿主中。它不启动独立网关，也不管理独立的 SQLite 账号池；账号、凭证和调度继续由宿主负责。插件通过宿主稳定协议注册以下能力：

- 原生 OAuth 认证；
- 静态基础模型及账号范围的动态模型发现；
- Anthropic Messages 执行器（流式和非流式）；
- 认证后的运维管理页及账号操作。

上游身份在宿主中始终表现为**一个可调度账号**。该账号的 Coding Plan JWT 是主凭证；由同一次 OAuth 兑换得到的 Z.AI API Key 是回退凭证。两者的可用性、失败原因和恢复动作独立保存，但在一次请求内按“JWT 优先、API Key 回退”的顺序使用。

该插件保持 MIT 许可，独立实现，不复制、翻译或改写 `docs/zcode2api` 的 AGPL-3.0 实现。相关决策见 [ADR 0001](adr/0001-independent-mit-implementation.md)。

## 已确认的约束

| 决策 | 选择 |
| --- | --- |
| 交付形态 | CPA/CLIProxyAPI 宿主 Provider 动态插件，不是独立服务或 ZCode Desktop 插件。 |
| 宿主兼容 | 假定 CLIProxyAPI 插件协议稳定，不主动按宿主版本建立兼容矩阵；将 ABI 调用收敛在适配层，协议实际变化时再更新。 |
| 身份模型 | 一个 Z.AI 上游身份对应一个宿主可调度账号。 |
| 凭证模型 | JWT 为主凭证；OAuth 兑换而来的 API Key 为同账号回退凭证。 |
| 验证码 | v1 不模拟浏览器、不执行远程验证码脚本、不实现 CAPTCHA 绕过；JWT 的 captcha/verify 拒绝触发 API Key 回退。 |
| API Key 所有权 | 只使用插件创建并记录的 Key；不通过名字扫描、复用或接管既有上游 Key。 |
| OAuth 入口 | 从宿主原生认证能力发起；管理页只展示进度、重试和运维操作。 |
| 模型目录 | 公开静态基础模型，并以“身份 + 上游环境”为键动态发现、缓存模型。 |
| 管理面 | 提供账号、OAuth、凭证状态、模型缓存、额度查询及刷新，不实现无明确 ZCode 语义的功能。 |
| 许可证 | MIT；按上游可观察协议独立实现，公开发布前完成许可证审查。 |

领域术语和状态定义位于仓库根目录 [CONTEXT.md](../CONTEXT.md)。

## 参考项目的取舍

### 从 `docs/cpa-plugin-zcode` 吸收的工程基线

`docs/cpa-plugin-zcode` 是与目标同属 CPA/CLIProxyAPI 动态库形态的最直接工程参考。它应提供 ABI 和交付基线，而不能作为 OAuth Provider 的业务实现来源。

可直接吸收：

1. **CGO 交付与内存归属**：使用 `-buildmode=c-shared`；初始化时填充宿主 ABI 版本和函数指针；插件响应由 `C.CBytes` 分配、仅由导出的 free 函数释放。
2. **代码生成的注册信息**：在一个 Go 注册函数中同时声明 metadata、配置字段和 capability，避免静态 manifest 与实际行为分叉。
3. **配置快照**：YAML 解码、默认值、合并和归一化集中处理；请求端只读取不可变配置快照。
4. **防御性小工具**：统一 ABI envelope、限制上游响应体大小、模型 ID 去空去重、避免修改调用方 header map。
5. **静态模型兜底**：动态发现关闭、失败或未认证时，静态基础模型依旧可见。
6. **发布产物机制**：跨平台 CGO 共享库矩阵、自包含 tar.gz 压缩包（动态库 + 生成的 C 头文件 + 许可证 + 中文安装说明）、checksum 和安装文档。

必须修正或替换：

- 当前骨架注册 `Executor`，但方法分发没有处理 `executor.execute` 或 `executor.execute_stream`；新插件不得声明任何未完整实现和契约测试过的 capability。
- 当前骨架的全局 `api_key` 配置与“从客户端 Authorization/x-api-key 提取后透传”的设计违反本方案的 OAuth 凭证归属要求，必须完全移除。
- 现有动态模型缓存是全局单条目，动态成功会覆盖静态模型；新实现必须按身份/上游环境隔离，并返回静态模型与动态模型的并集。
- 现有 CGO host callback 桥只存储了 callback 指针，尚未形成 Go 层 Adapter；新实现必须用 `host_adapter` 收口 buffer 释放、认证读写、流 callback 和错误 envelope。
- `shutdown` 为空；新实现必须终止 OAuth 会话、活跃流、计时器和未来 host callback。
- 现有 mock/fingerprint 模块包含 `zcode2api` 命名、SHA-1 和忽略随机数错误的实现；不纳入新插件。仅在独立验证确有上游需求时，以 `crypto/rand` 和域隔离 SHA-256 独立实现必需字段。
- 不可将原始上游响应体带入运维错误；新实现先做统一 redaction，再返回有边界的错误码和摘要。

因此，工程实现按本方案中的 `host_adapter`、无损凭证补丁、OAuth 会话、Profile、SSE 流泵和管理面模块重组；保留构建/发布思路，但不继承固定 API Key、任意 header 复制或单全局模型缓存的行为。

### 从 `workbuddy-cliproxy-plus` 复用的架构模式

`~/work/workbuddy-cliproxy-plus` 是良好的 CPA Provider 参考，但其 WorkBuddy 业务逻辑不可直接移用。新插件沿用以下结构性模式：

1. **CGO 共享库及运行时注册**：通过 `-buildmode=c-shared` 导出 CPA ABI 入口；注册信息是 Go 代码的单一事实来源。
2. **窄宿主适配层**：将 host callback、认证存取、流式 emit/close 和管理页路由隔离在边界层，业务代码通过小接口访问它们。
3. **无损凭证补丁**：将宿主认证 JSON 当作可扩展文档，只更新插件拥有的 `zcode` 字段，保留未知宿主字段及数值精度。
4. **凭证绑定的不可变上游配置**：每个请求先解析一次 Credential/Profile，再用该快照构造 URL、认证头、模型发现和执行请求，避免跨身份串用配置。
5. **上游流式、下游适配**：统一以 SSE 上游传输；宿主请求非流式时在插件内聚合，流式时由 goroutine 通过宿主 callback 逐块输出。
6. **每身份串行的运维操作**：刷新、额度查询、OAuth 完成写入和状态转换以单账号锁串行；批量操作先快照账号，再逐项执行并汇总。
7. **安全管理页**：静态 HTML，动态内容只用 DOM `textContent` 写入；异步更新用 generation 防止旧请求覆盖新状态；错误信息先脱敏再展示。

不复用 WorkBuddy 特有的 URL、浏览器身份、签到、模型字段、内容改写和代理范围策略。

### 从 `zcode2api` 提取但独立验证的协议事实

`docs/zcode2api` 仅是 AGPL 行为参考。初版需在集成环境独立核验以下请求与响应结构，不把它们视作长期稳定契约：

1. OAuth 初始化：`POST https://zcode.z.ai/api/v1/oauth/cli/init`，带随机轮询秘密的 Bearer 认证和 `{"provider":"zai"}`。
2. OAuth 轮询：`GET https://zcode.z.ai/api/v1/oauth/cli/poll/{flowID}`，成功时预期得到 Coding Plan JWT，以及可选的 Z.AI access token。
3. API Key 兑换：使用 OAuth access token 登录 Z.AI 业务接口、选择显式配置或用户确认的组织/项目、创建并记录插件专属 API Key、读取其可调用密钥材料。
4. JWT 上游：ZCode Plan 的 Anthropic Messages 接口，以 Bearer JWT 鉴权。
5. API Key 上游：Z.AI 的 Anthropic Messages 接口，以 `x-api-key` 鉴权。
6. 额度查询：Coding Plan billing 与 usage 接口；其字段应采用容错解析，未知字段不能推导为额度耗尽或凭证无效。

## 组件设计

采用单个 Go module、多个职责明确的源文件或内部包。是否使用 `internal/` 目录可按现有插件的单包风格决定；边界和接口必须保持如下划分。

```text
main.go / abi.go
  └─ CPA C ABI、方法分发、生命周期和关闭

host_adapter.go / auth_store.go
  └─ 宿主 callback 封装；认证记录 list/get/get-runtime/save；流式回调

credential.go / credential_patch.go
  └─ ZCode credential 解码、无损 JSON 合并、身份 ID、秘密脱敏

oauth.go / oauth_sessions.go / api_key_exchange.go
  └─ OAuth 初始化与轮询、过期会话、组织/项目选择、受管 Key 创建

profile.go / upstream.go / executor.go / stream.go
  └─ JWT/API-Key 上游配置、请求构造、错误分类、SSE 转发和聚合

model_catalog.go
  └─ 静态模型、身份范围动态发现、正缓存和短失败缓存

quota.go / credential_state.go
  └─ 额度获取、独立凭证状态机、原子状态迁移

management.go / management_ops.go / management_page.go
  └─ 管理页资源、认证后操作、批处理、静态页面

redaction.go / transport.go
  └─ 允许转发头、上游 HTTP 客户端、错误/诊断脱敏
```

### 宿主适配接口

业务代码不得直接散布 ABI callback 调用。适配层至少提供：

```go
type AuthStore interface {
    List(ctx context.Context, provider string) ([]AuthIndex, error)
    Get(ctx context.Context, authIndex string) (json.RawMessage, error)
    GetRuntime(ctx context.Context, authIndex string) (json.RawMessage, error)
    Save(ctx context.Context, authIndex string, value json.RawMessage) error
}

type StreamSink interface {
    Emit(ctx context.Context, streamID string, payload []byte) error
    Close(ctx context.Context, streamID, message string) error
}

type Host interface {
    AuthStore() AuthStore
    Stream() StreamSink
}
```

具体的 DTO 和方法名以 CPA 当前 SDK 为准；接口只表达插件业务所需能力，避免让 OAuth、上游和管理代码依赖 C ABI 细节。

### 凭证文档

宿主拥有认证记录的外层结构。插件在它自己的命名空间内保存 ZCode 数据，例如：

```json
{
  "type": "zcode",
  "name": "Z.AI user",
  "zcode": {
    "schema_version": 1,
    "identity_id": "zcode-<stable-subject-or-digest>",
    "jwt": {
      "token": "<secret>",
      "status": "active",
      "retry_after": null,
      "last_error_code": null,
      "last_checked_at": "2026-09-30T00:00:00Z"
    },
    "api_key": {
      "key_id": "<upstream-resource-id>",
      "credential": "<secret>",
      "status": "active",
      "last_error_code": null,
      "last_checked_at": "2026-09-30T00:00:00Z"
    },
    "key_ownership": {
      "managed": true,
      "name": "cpa-zcode-<short-id>"
    },
    "selection": {
      "organization_id": "<non-secret-id>",
      "project_id": "<non-secret-id>"
    }
  }
}
```

这只是字段边界，不是要求将秘密明文记录在插件自己的文件中。凭证必须由宿主安全认证存储保存；日志、错误、管理页、模型缓存键和遥测均不应保留或输出 JWT、OAuth token、完整 API Key 或 Secret Key。若宿主认证存储缺乏静态加密能力，应在实现前明确其保护模型，不自行创建明文旁路存储。

`identity_id` 首选来自 OAuth 返回的稳定、不敏感主体 ID；若上游没有该字段，再对不可逆的稳定输入作域分隔 SHA-256，绝不直接把秘密作为索引或日志内容。

### 授权会话

一次 OAuth 会话只存在于插件进程内并由 `sync.Map` 或受锁的 map 管理，包含：

- `flow_id`；
- 32 字节 `crypto/rand` 生成并 hex 编码的轮询秘密；
- 授权 URL；
- 创建方/宿主认证上下文；
- 创建和到期时间；
- 完成状态与一次性结果。

会话规范：

- 每次登录使用独立 HTTP client、cookie jar（即使当前 OAuth 流程不依赖 cookie，也避免今后跨会话泄漏）；
- 默认五分钟过期；完成、拒绝、过期和插件 shutdown 时清理；
- 会话结果仅能被其创建方读取或完成；
- 轮询秘密绝不出现在管理页、宿主响应、日志或错误中；
- 同一会话的完成逻辑用 `sync.Once` 或互斥锁保证只保存一次凭证。

OAuth 完成顺序：

1. 宿主触发 Provider 原生认证，插件创建授权会话并返回授权 URL/会话标识。
2. 用户在浏览器中完成 Z.AI 授权；宿主或插件的认证轮询读取状态。
3. 当上游返回 JWT 时，创建或无损更新该宿主账号的主凭证。
4. 若同时获得兑换 API Key 所需 access token，执行 API Key 兑换流程；失败不能回滚已完成的 JWT 登录，但必须在状态中可见。
5. 第一次为该身份创建 API Key 时，要求明确的组织/项目选择策略：优先使用登录流程返回或用户/宿主配置指定的 ID；缺失或存在多个候选时，返回待选择信息，不按“默认机构/默认项目”等本地化显示名猜测。
6. 创建名字为 `cpa-zcode-<crypto-random-short-id>` 的 API Key，并将上游资源 ID、名称和密钥关系写回同一宿主账号。

## 请求执行与回退

### 上游 Profile

为每个请求创建只读 `ResolvedProfile`：

```go
type ResolvedProfile struct {
    IdentityID      string
    CredentialKind  CredentialKind // JWT 或 APIKey
    MessagesURL     *url.URL
    AuthHeader      http.Header
    RequestHeaders  http.Header
    ModelID         string
}
```

Profile 集中定义固定的上游 URL、所需 `anthropic-version`、ZCode 产品标识 headers、超时和模型名标准化规则。它不转发客户端的 `Authorization`、`x-api-key`、`Cookie`、`Proxy-Authorization`、`Host`、`Connection` 或任意 `X-ZCode-*` 头。

插件只允许转发明确需要的非敏感协议头，例如 `Accept`、经验证可用的 Anthropic feature header，以及由插件生成的追踪标识。客户端 API Key 永远不能透传到 Z.AI 上游。

### 选择与错误处理

一次执行请求按下列顺序处理：

1. 从认证记录构建凭证快照；若没有可尝试凭证，返回 `401` 或明确的不可用错误。
2. JWT 若处于 `invalid`、`exhausted` 或尚未结束的 `verification_blocked` / `cooldown` 状态，则跳过至 API Key；否则先发送 JWT Profile。
3. JWT 成功时，记录成功并正常转发流；不主动尝试 API Key。
4. JWT 被分类为可回退失败时，以同一个、未经变异的请求体尝试 API Key Profile。
5. API Key 成功时完成流；失败时只更新 API Key 状态并返回经过脱敏的最终错误。

状态机：

| JWT 结果 | 本请求 | 持久化结论 | 恢复 |
| --- | --- | --- | --- |
| captcha / verify 相关 403 | 回退 API Key | `verification_blocked`，五分钟 retry-after | 到期后自动再试 JWT |
| 401 / 非验证码 403 | 回退 API Key | `invalid` | 手动刷新或重新 OAuth |
| 402 / 经确认额度耗尽 | 回退 API Key | `exhausted` | 额度刷新确认可用后恢复 |
| 429、网络错误、5xx | 回退 API Key | `cooldown` | 短期退避到期后自动再试 |
| 非上述 4xx | 不伪装为额度或认证问题 | 记录有限、脱敏诊断 | 由上游语义决定 |

API Key 有相同的独立状态字段，但其失败不改变 JWT 的状态。状态修改通过单身份锁和一次无损 `AuthStore.Save` 实现，避免额度刷新、请求失败和管理操作相互覆盖。

### 流式处理

- 始终向上游请求 SSE，设置可配置的连接、写入和整体执行超时；读超时必须能支持长连接，同时以调用方 context 取消为准。
- 流式请求立刻返回宿主，将 SSE chunk 在 goroutine 中通过 `StreamSink.Emit` 转出，并在 EOF、错误或客户端取消后精确调用一次 `Close`。
- 非流式请求复用相同上游流泵，设定最大聚合字节数，转换/聚合为 CPA 要求的非流式响应。
- 只有在上游尚未向客户端输出任何可见内容时，才允许在 JWT 失败后回退 API Key；已开始的流不应重新播放或拼接来自不同凭证的输出。

## 模型目录和额度

### 模型目录

初始注册使用经集成测试验证的静态列表，例如由配置中的 `models` 定义。动态发现采用：

```text
cache key = provider + upstream-environment + stable-identity-id
success TTL = 1h（可配置）
failure cooldown = 5m（可配置）
```

缓存键不能包含 JWT/API Key。动态接口响应须限制大小、严格解析、去空和去重；成功结果是对静态目录的补充，而非把静态目录清空。发现失败时保留静态模型、记录脱敏运维状态并在失败冷却结束后再试。

### 额度

额度查询仅是管理面和状态恢复的输入，不是请求成功的前提。对每种凭证分别以其适用上游认证头调用经独立验证的 billing/usage 端点。解析器须：

- 限制响应大小和超时；
- 先检查 HTTP 认证结果，再读取字段；
- 接受可选/未知字段；
- 仅在所有已知、有效余额明确为零或负数时判定 `exhausted`；
- 遇到字段变更、类型不符或空响应时返回 `unknown/upstream_schema_incompatible`，不更新凭证为失效或耗尽；
- 仅用明确成功的认证/额度响应恢复相应凭证，不把一个凭证的成功视作另一个凭证有效。

v1 管理页提供单账号刷新、批量刷新和最近检查结果。批量刷新应快照账号、继续处理其他账号、按结果汇总成功/失败/未知；可用受控并发避免对上游造成突发流量。

## 管理面

插件注册一个需宿主认证的资源页和操作路由。页面功能：

- 展示每个身份的显示名称、主/回退凭证状态、最后检查时间与脱敏错误码；
- 显示授权会话等待、完成、失败或过期；
- 触发重新 OAuth、单账号凭证刷新、单账号额度刷新、模型缓存刷新；
- 可选批量刷新及结果摘要；
- 显示动态模型缓存的来源、过期时间或失败冷却状态；
- 不显示原始 secret、完整授权链接中的敏感部分、上游响应体或用户 prompts。

操作契约使用固定动作词汇，并要求账号粒度操作提交 `auth_index`。非法 JSON、未知动作、没有权限的账号、缺失 `auth_index`、冲突中的同账号操作和上游失败均返回规范化状态码与脱敏消息。页面在成功完成新动作前禁用重复提交。

## 配置表面

首版配置应少而明确，不暴露秘密绕过开关：

```yaml
plugins:
  configs:
    zcode:
      enabled: true
      priority: 1

      # 静态安全兜底模型；动态模型结果只能补充它们。
      models:
        - GLM-5.2
        - GLM-5-Turbo

      model_discovery:
        enabled: true
        success_ttl_seconds: 3600
        failure_cooldown_seconds: 300

      oauth:
        session_ttl_seconds: 300
        managed_key_name_prefix: cpa-zcode
        # 仅在上游不能从授权结果确定项目时使用；不按中文显示名猜测。
        organization_id: ""
        project_id: ""

      upstream:
        connect_timeout_seconds: 30
        request_timeout_seconds: 300
        max_response_bytes: 67108864

      quota:
        refresh_concurrency: 4
```

不提供 `api_key` 固定全局配置，也不从客户端请求头透传 API Key。凭证只来自被宿主管理的 OAuth 身份记录。实际静态模型名称、上游 URL、必要产品头和动态模型端点必须在集成环境验证后写入默认值。

## 测试与验证策略

### 单元测试

1. ABI 方法注册、生命周期和错误 envelope。
2. 宿主 callback adapter：错误 envelope、buffer 回收、认证记录读写。
3. 凭证 JSON 无损 round-trip：未知字段、嵌套字段、`json.Number` 大整数、插件字段迁移。
4. OAuth：随机轮询秘密长度、会话过期、一次性完成、跨会话隔离、失败不覆盖原凭证。
5. API Key 兑换：显式组织/项目选择、仅创建受管 Key、记录资源 ID、对多候选返回选择需求。
6. 状态分类矩阵：验证码、401/403、402、429、5xx、网络故障、未知错误；断言 JWT/API Key 独立更新。
7. 执行器：认证头选择、允许头转发、模型映射、无输出前才可回退、流已输出后不可重试。
8. SSE：正常 chunk、无效 frame、宿主 emit 失败、context 取消、只 close 一次、非流式大小限制。
9. 模型缓存：静态模型始终存在、身份隔离、TTL、失败冷却、凭证不出现在 key 中。
10. 额度解析：已知字段、缺字段、字符串数字、非法类型、认证失败、unknown 不改变状态。
11. 管理操作：每账号互斥、批量快照、部分失败继续、错误脱敏、HTML 不使用不安全插值。

所有 HTTP 测试应使用 `httptest.Server` 和可注入 transport；测试不会访问真实 Z.AI、验证码或 OAuth 服务。

### 集成验证

在获授权的测试身份和隔离项目中，人工确认：

1. OAuth 授权 URL 能完成登录，轮询能得到预期凭证形态；
2. 受管 API Key 可创建、记录、后续登录可按记录复用；
3. JWT 与 API Key 分别能够发送 Anthropic 请求；
4. JWT 遭遇真实验证阻塞时，不做验证码自动化且可回退；
5. 流式与非流式 CPA 客户端均有正确输出；
6. 模型和 billing 响应的真实字段适配器正确工作；
7. 管理页从真实宿主认证、保存和 stream callback 运行；
8. 插件共享库在目标系统/架构加载，并完成 `go test ./...`、`go vet ./...`、构建和最小宿主冒烟测试。

测试日志、录制响应、截图和 issue 附件必须先删除 token、key、Cookie、授权 URL 中的敏感参数及用户 prompt。

## 分阶段实施

### 阶段 0：契约核验与工程基线

- 确认 CPA 当前 SDK 的认证、OAuth、管理页、模型和 executor 方法及 DTO。
- 以现有 Go/CGO 构建脚本建立最小插件骨架、CI、lint/test 命令与发布产物。
- 建立 host adapter fake 和无损凭证补丁测试。
- 在授权集成环境记录经脱敏的上游协议样本。

**完成条件：** 共享库可加载；静态注册、模型、认证存储 fake 和流回调 smoke test 通过。

### 阶段 1：身份与 OAuth

- 实现 Authorization Session、宿主原生认证入口、轮询和安全 cleanup。
- 实现单宿主账号的 JWT 保存和稳定身份解析。
- 实现 API Key 兑换、显式组织/项目选择与插件受管 Key 记录。
- 实现凭证无损更新、脱敏和管理页 OAuth 状态。

**完成条件：** 完整 OAuth 可创建一个拥有 JWT 与受管 API Key 的宿主账号；失败路径不泄露秘密、不破坏既有账号。

### 阶段 2：执行器与独立状态机

- 实现 Profile、请求头 allowlist、模型规范化、Anthropic Messages 转发。
- 实现 SSE pump / 非流式聚合和未输出前的 JWT→API Key 回退。
- 实现独立 JWT/API Key 状态、单账号串行更新和冷却恢复。
- 明确禁止验证码自动化代码、依赖和配置。

**完成条件：** 模拟上游的所有状态分类和回退测试通过；真实授权环境能够处理一个流式和一个非流式请求。

### 阶段 3：模型、额度与管理面

- 完成静态 + 身份范围动态模型目录缓存。
- 实现防御性额度查询与状态恢复。
- 实现管理页、单账号操作、批量刷新、模型缓存和额度状态展示。
- 完成 redaction、操作审计和 UI 并发保护。

**完成条件：** 管理面可安全完成所有 v1 运维动作；上游 schema 变更只报告 unknown，不误伤账号状态。

### 阶段 4：发布准备

- 矩阵构建目标平台的 C 共享库；生成 checksums 和安装文档。
- 使用真实 CPA 宿主做加载、OAuth、执行器、模型和管理页回归。
- 许可证审查：核对 MIT 源码独立性、依赖许可证、README 的第三方声明。
- 进行凭证泄漏审计、日志审计和最小威胁建模。

**完成条件：** CI 全绿、目标平台冒烟完成、许可证审查通过、发布资产可安装和回滚。

## 主要风险与应对

| 风险 | 应对 |
| --- | --- |
| ZCode API 不是稳定公开契约 | 将 URL、headers、解析器和错误分类集中；集成环境核验；未知 schema 不作危险推断。 |
| CAPTCHA 阻塞 JWT | 不自动化 CAPTCHA；独立标记验证受阻并尝试 API Key；没有回退时给明确可操作错误。 |
| OAuth token/Key 泄漏 | 宿主安全存储、日志和 UI redaction、header allowlist、测试 fixture 审查、避免 query 中放管理秘密。 |
| 同一身份的并发写覆盖 | 单身份锁、无损 merge、单次保存、批量前快照。 |
| API Key 错误归属或碰撞 | 只创建带随机后缀的受管 Key，并持久化上游资源 ID；不按名字扫描。 |
| 非流式/流式语义不一致 | 上游统一流式、下游以适配器聚合；输出开始后不跨凭证重试。 |
| 模型/额度接口失败影响使用 | 静态模型不消失；模型失败冷却；额度解析异常只显示 unknown。 |
| 参考项目许可污染 | 仅用 AGPL 项目验证行为，不复制其代码或结构；发布前做许可证审查。 |

## 不在 v1 范围内

- CAPTCHA 规避、浏览器自动化、远程 SDK 执行或第三方验证码破解服务；
- 自建 HTTP 网关、SQLite 账号池或绕过 CPA 调度；
- 透传 CPA 客户端 API Key 作为 Z.AI 上游凭证；
- 通过中文/本地化组织或项目名称猜测 API Key 创建位置；
- 自动接管、删除或轮转并非本插件创建的上游 API Key；
- WorkBuddy 专属签到、内容改写或跨区域行为；
- 未经验证即宣称固定的上游模型目录、额度字段或长期 API 兼容性。
