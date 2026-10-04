# Start Plan 是否存在每日发放或用户领取：官方源码调查

- **范围**：仅审阅本仓库 `docs/ZCode/` 下的官方源码；未使用第三方资料、抓包或运行时凭据。
- **源码版本**：`docs/ZCode` 的当前 `HEAD` 为 `29628c9`。
- **结论标记**：**明确证据**表示源码直接实现或声明；**边界/推断**表示官方客户端源码不足以证明服务端行为。

## 结论

**明确证据：截至该源码版本，ZCode 客户端没有实现 Start Plan 的“每日/新日发放”、也没有实现用户点击“领取/claim”后调用 Start Plan 发放接口的操作。**

Start Plan 的已实现闭环是：用户 OAuth 登录取得凭据 → 客户端 `GET` 读取远端套餐及余额 → 按服务端返回的 `active`、生效时间和额度桶展示/启用模型。唯一直接的 Start Plan billing 调用是只读 `GET /api/v1/zcode-plan/billing/balance`；其实现没有 `POST` body，也没有 claim/activate/issue 方法。见 `docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L63-L125`、`docs/ZCode/packages/services/src/usage-stats/providers/bigmodelUsageQuotaProvider.ts:L351-L450`。

源码里确实有“领取后”“领取/付费卡”“购买或领取完成后”等**注释**，但相应位置只做可用性查询或缓存失效声明，没有领取请求实现：

- `docs/ZCode/packages/services/src/model-provider/codingPlanProviderAvailability.ts:L188-L212`
- `docs/ZCode/packages/shared/src/model-provider-types.ts:L49-L58`
- `docs/ZCode/packages/shared/src/usage-stats.ts:L46-L61`

**边界/推断：**服务端可能在登录、活动资格或其它官网流程后为账号创建套餐；客户端只会在随后读到 `plans`/`balances` 时观察到结果。该源码不能证明服务端何时、为何发放，更不能证明“每天自动发新套餐”。

## 实际接口与请求形态

|用途|路径、方法、触发条件|请求（已脱敏）|响应与结论|
|---|---|---|---|
|Start Plan 目录/预览|`GET /api/v1/client/configs?app_version=<当前版本>&platform=<os-arch>`；打开满足条件的未连接/无套餐 Start Plan 卡时读取，配置服务本身有 1 小时快照，UI preview 有 24 小时缓存。|无 body；由统一客户端附加 ZCode 来源头和请求 ID。|读取 `data.configs.startPlanPreview`，只用于展示套餐名与额度说明，不创建套餐。`docs/ZCode/packages/services/src/coding-plan-subscription/bigmodelCodingPlanSubscriptionProvider.ts:L598-L628`、`L1194-L1248`；`docs/ZCode/packages/ui/src/settings/model-provider-section/useStartPlanPreview.ts:L12-L105`。|
|Start Plan 可用性/余额|`GET /api/v1/zcode-plan/billing/balance?app_version=<当前版本>`；账号连接可用性检查、权益快照、待生效后用户手动“刷新权益”等都会走这里。旧 `billing/current` 被明确标为废弃。|无 body；显式 `Authorization: Bearer <已登录账号的 ZCode JWT>`。请求超时 15 秒，短时间相同请求合并。|读取已有 `plans` 与 `balances`；不领取、不续期、不重置。`docs/ZCode/packages/shared/src/zcodeEndpoint.ts:L260-L270`、`docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L9-L125`、`docs/ZCode/packages/services/src/usage-stats/providers/bigmodelUsageQuotaProvider.ts:L371-L450`。|
|OAuth（访问 Start Plan 的前置交互，不是领取）|Z.ai/BigModel 授权页完成回调后，均向 `POST /api/v1/oauth/token` 交换令牌；Z.ai 另向 `/api/auth/z/login` 交换业务 token。|OAuth token body：`{ provider, code: <redacted>, redirect_uri, state }`；Z.ai business login body：`{ token: <redacted> }`；均为 JSON。|得到 `data.token`（ZCode JWT）及相应业务 access token；JWT 被用于后续余额读取，非发放响应。`docs/ZCode/packages/services/src/oauth/providers/zaiProviderAdapter.ts:L308-L388`、`docs/ZCode/packages/services/src/oauth/providers/bigmodelProviderAdapter.ts:L118-L203`、`docs/ZCode/packages/services/src/providers/zaiBusinessTokenResolver.ts:L69-L104`。|
|Start Plan 模型调用地址|配置为 `https://zcode.z.ai/api/v1/zcode-plan/anthropic`。|本报告未把模型推理请求当作套餐发放接口；配置未声明 claim 方法/body。|这是已获权益后的模型服务基址，不是领取接口。`docs/ZCode/config/provider/zcode-builtin.json:L735-L753`、`L798-L816`。|

### 传输头（无秘密值）

`billing/balance` helper 的显式请求配置只有 `Authorization: Bearer <redacted>`，为 `GET` 且没有 body；其余 ZCode endpoint 头由统一 `NodeApiClient` 合并。最终应以如下**字段名**理解，不能复制真实值：`Authorization`、`User-Agent`、`HTTP-Referer`、`X-Title`、`X-ZCode-App-Version`（条件存在）、`X-Platform`（条件存在）、`X-Release-Channel`（条件存在）、`X-Client-Language`、`X-Client-Timezone`、`X-Os-Category`、`X-Os-Version`、`X-Device-Mid`（条件存在）、`x-request-id: <UUID>`。`X-Device-Mid` 仅在已有设备身份时加入；远端缺失它时余额请求可能被服务端拒绝，故远端启动代码会确保设备标识存在。不要记录或复制 Authorization/JWT/设备标识。`docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L103-L109`；`docs/ZCode/packages/services/src/providers/api/nodeApiClient.ts:L44-L72`、`L117-L131`；`docs/ZCode/packages/shared/src/zcode-source-headers.ts:L29-L57`；`docs/ZCode/packages/services/src/providers/api/requestIdHeaders.ts:L3-L10`；`docs/ZCode/packages/server/src/stdioDeviceMid.ts:L10-L18`。

### 相关实现角色

- `ZaiStartPlanBilling`（模块）封装余额 URL、单飞短缓存和过期归一；`BigModelUsageQuotaProvider` 将已有套餐/桶投影为 entitlement、订阅详情和 UI quota。
- `codingPlanProviderAvailability`（模块）专门判断 Start Plan 可用性；`AccountProviderRequestAuthService` 为 Start Plan 提供当前账号的 ZCode JWT。
- `BigModelCodingPlanSubscriptionProvider` 提供仅展示用的 `startPlanPreview`；`BigModelProviderAdapter`、`ZaiProviderAdapter` 和 `ZaiBusinessTokenResolver` 只负责 OAuth/业务令牌交换。
- UI 由 `StartPlanCard`、`CodingPlanStatusPanel`、`StartPlanStatusMeta`、`useStartPlanPreview`、`useStartPlanRecommendation` 组成；这些角色均未暴露 Start Plan claim 方法。

证据：`docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L57-L125`；`docs/ZCode/packages/services/src/usage-stats/providers/bigmodelUsageQuotaProvider.ts:L351-L483`；`docs/ZCode/packages/services/src/model-provider/codingPlanProviderAvailability.ts:L396-L510`；`docs/ZCode/packages/services/src/model-provider/accountProviderRequestAuthService.ts:L67-L84`；`docs/ZCode/packages/services/src/coding-plan-subscription/bigmodelCodingPlanSubscriptionProvider.ts:L201-L214`；`docs/ZCode/packages/services/src/oauth/providers/bigmodelProviderAdapter.ts:L118-L203`；`docs/ZCode/packages/services/src/oauth/providers/zaiProviderAdapter.ts:L307-L388`；`docs/ZCode/packages/ui/src/settings/model-provider-section/StartPlanCard.tsx:L12-L67`。

## 服务端返回字段与客户端判定

### 1. `billing/balance` 的已知字段

**明确证据：**客户端声明的 envelope 包含：

- 顶层：`code`、`success`、`msg`；
- `data.server_time`；
- `data.plans[]`：`user_plan_id`、`plan_id`、`name`、`status`、`starts_at`、`ends_at`、`entitlements[]`；权益含 `entitlement_id`、`show_name`、`period`、`effective_at`；
- `data.balances[]`：`bucket_id`、`user_plan_id`、`plan_id`、`entitlement_id`、`show_name`、`meter`、`unit_type`、`capabilities`、`total_units`、`used_units`、`reserved_units`、`remaining_units`、`available_units`、`period_start`、`period_end`、`expires_at`。

见 `docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L13-L54`。

客户端用 `remaining_units` 展示余额，明确不以会扣除预占请求的 `available_units` 兜底；将 `expires_at` 映射为每个桶的 `nextResetTime`，保留 `period_start`/`period_end`/`bucket_id`/`period` 以表达周期身份。`docs/ZCode/packages/services/src/usage-stats/providers/bigmodelUsageQuotaProvider.ts:L1281-L1350`。

### 2. Start Plan 的资格与状态

**明确证据：**

1. 必须先能解析为当前账号的 `planKind: "start-plan"`，再从该账号 OAuth token set 取得 ZCode JWT；缺少当前账号/凭据不会伪造权益。`docs/ZCode/packages/services/src/model-provider/accountProviderConnectionResolver.ts:L307-L342`；`docs/ZCode/packages/services/src/model-provider/accountProviderRequestAuthService.ts:L67-L84`。
2. Start Plan 与个人/团队付费套餐独立查询；即使当前连接选择的是付费套餐，Start Plan 仍单独请求余额。`docs/ZCode/packages/services/src/model-provider/codingPlanProviderAvailability.ts:L173-L212`。
3. 可用性要求业务 envelope 成功，且 `plans` 中存在 `status === "active"`、并且 `plan_id` 或 `name` 含 `start-plan` / `start plan` 的记录。没有则为 `coding_plan_not_entitled`。`docs/ZCode/packages/services/src/model-provider/codingPlanProviderAvailability.ts:L462-L503`、`L519-L547`。
4. 当 active plan 的所有已知 `effective_at` 都在服务端当前时间之后、且还没有可用模型额度桶时，状态为 `pending` 并暴露最早 `effectiveAt`；否则可用性由已有余额桶决定。`docs/ZCode/packages/services/src/model-provider/codingPlanProviderAvailability.ts:L471-L503`。
5. 客户端会把已到 `ends_at` 的 `active` 记录本地归一成 `expired`，优先使用 HTTP `Date`，其次用 `server_time`，最后才用本机时钟；同时过滤仅归属已过期套餐的余额桶。`docs/ZCode/packages/services/src/model-provider/zaiStartPlanBilling.ts:L156-L187`。

“新用户体验”只是卡片标签，源码没有以注册日期、账号年龄、信任分、`trust build` 或本地资格规则计算新用户资格；权威资格来自上述远端 `plans`。`docs/ZCode/packages/ui/src/settings/model-provider-section/StartPlanCard.tsx:L32-L67`。

### 3. preview 不是 entitlement

`startPlanPreview` 的结构仅为 `planId`、`name`、`entitlements[]`，其中权益描述为 `grantUnits`、`meter`、`period`、`showName`、`unitType`。它是远端目录/展示配置；`grantUnits` 不是客户端执行的“授予”动作。`docs/ZCode/packages/shared/src/coding-plan-subscription.ts:L102-L114`；`docs/ZCode/packages/services/src/coding-plan-subscription/bigmodelCodingPlanSubscriptionProvider.ts:L1194-L1248`。

## UI 操作与人工交互

1. **展示，不领取。**Start Plan promo 卡只接收 preview；当前调用点传入 `<StartPlanCard preview={...} />`，没有传入其可选的 `actions`，卡片本身没有 claim handler。它仅在 Start Plan 处于 disconnected/notPurchased 且 preview 已启用时显示。`docs/ZCode/packages/ui/src/settings/model-provider-section/StartPlanCard.tsx:L12-L67`；`docs/ZCode/packages/ui/src/settings/model-provider-section/StatusCards.tsx:L326-L332`、`L642-L645`。
2. **登录是明确的用户操作。**状态卡在未连接/可恢复的不可用状态显示登录/重新登录按钮；点击调用 `onLogin`。设置页若未是当前 OAuth provider，则走统一 `requestLoginEntry(providerId)`，进入浏览器 OAuth。`docs/ZCode/packages/ui/src/settings/model-provider-section/StatusCards.tsx:L303-L308`、`L515-L537`；`docs/ZCode/packages/ui/src/settings/ModelProviderSection.tsx:L787-L813`。
3. **“刷新权益”不是领取。**仅当 `effective_at` 已到、但服务端尚未创建/返回额度桶时显示；按钮只是刷新现有 entitlement/balance。到点的定时器也只更新 UI 状态，不自行发放或自动 POST。`docs/ZCode/packages/ui/src/settings/model-provider-section/CodingPlanStatusMeta.tsx:L86-L179`、`L183-L208`。
4. **模型推荐不是领取。**提交时可弹确认框，允许用户把当前模型选择切至已有 Start Plan provider；判定要求同模型已有有效且有剩余额度的 bucket。它不创建 entitlement。`docs/ZCode/packages/ui/src/hooks/useStartPlanRecommendation.ts:L36-L85`；`docs/ZCode/packages/ui/src/lib/startPlanRecommendation.ts:L17-L45`。
5. **付费套餐 WebView 与 Start Plan 领取应严格区分。**升级页可打开官方 `/coding-plan` WebView，完成后刷新 provider/entitlement；这是一条购买/支付承载链路，不能当作 Start Plan claim 的证据。`docs/ZCode/packages/ui/src/settings/CodingPlanUpgradeDialog.tsx:L34-L64`、`L131-L150`；`docs/ZCode/packages/ui/src/settings/model-provider-section/codingPlanEmbeddedWebview.ts:L93-L124`、`L163-L221`。

**关于人机验证：**余额读取和“刷新权益”路径均为无 body 的已登录 `GET`，源码没有在 Start Plan 路径传 CAPTCHA、`ticket` 或 `randstr`，因此没有“Start Plan 领取必须人机验证”的客户端证据。OAuth 登录本身是明确的用户浏览器授权交互。付费 Coding Plan 的 preview 类型确实含 `ticket`/`randstr`，但对应 `/pay/preview` 或 `/pay/zai-preview`，不能外推到 Start Plan。`docs/ZCode/packages/shared/src/coding-plan-subscription.ts:L183-L191`；`docs/ZCode/packages/services/src/coding-plan-subscription/bigmodelCodingPlanSubscriptionProvider.ts:L280-L293`、`L1073-L1075`。

## 每日与重置语义

**明确证据：**`period === "daily"` 表示一个服务端 entitlement/bucket 的周期，UI 可显示“每日额度”；当前有效桶还必须满足 `periodStart <= now < periodEnd`，且 `nextResetTime`（来自 `expires_at`）尚未来临。`docs/ZCode/packages/shared/src/usage-quota.ts:L14-L34`；`docs/ZCode/packages/ui/src/v4/startPlanQuotaBuckets.ts:L16-L27`；`docs/ZCode/packages/ui/src/settings/model-provider-section/StartPlanCard.tsx:L171-L220`。

因此，源码支持的是**已有 Start Plan 的日额度恢复观察**：每个桶的真实恢复边界以服务端 `expires_at` 为准，而不是本地“午夜”计算。聊天区的“体验套餐额度已用完，请等待额度恢复”也只是提示，不会创建新套餐或主动重置。`docs/ZCode/packages/ui/src/chat-input-toolbar/StartPlanContextBalance.tsx:L79-L106`；`docs/ZCode/packages/ui/src/i18n/locales/zh-CN.ts:L5510-L5515`。

**没有的内容：**未发现 Start Plan 专用 cron、日切任务、`POST` issuance endpoint、或“新一天自动领一次”的客户端状态机。即使翻译文案中出现“5 个自然日”“3M tokens/日”，这些键在当前源码中仅见于 locale 定义，不能作为插件的额度或期限契约。`docs/ZCode/packages/ui/src/i18n/locales/zh-CN.ts:L2639-L2649`。

### 容易混淆但不属于 Start Plan 发放的接口

源码另有 `/api/v1/coding-plan/reset/opportunity`、`/use`、`/history/read`：它们使用幂等键，管理 `FIVE_HOUR`/`WEEK` 的 Coding Plan **额度重置机会**，响应中的 `granted`/`next_try_at` 也只描述该机会。Start Plan 的 UI 分支渲染的是余额桶，不渲染这套 reset 卡；因此它不能证明 Start Plan 有领取或每日发放。`docs/ZCode/packages/shared/src/coding-plan-reset.ts:L1-L40`；`docs/ZCode/packages/services/src/usage-stats/providers/bigmodelUsageQuotaProvider.ts:L553-L646`；`docs/ZCode/packages/ui/src/settings/model-provider-section/StatusCards.tsx:L570-L635`。

## 给本插件的操作建议

1. **不要实现每日 cron、自动领取、模拟点击或猜测的 POST claim。**官方源码没有这类 Start Plan 合同；把 `daily` 解释为“每日可领取新套餐”是错误的。
2. 若插件需要展示状态，只把 Start Plan 当作**已登录账号的只读 entitlement**：通过合法、用户明确授权的官方登录态读取/刷新余额，展示 `available`、`pending(effective_at)`、`expired(ends_at)`、`no_plan`、`unknown/error`，并按服务端 `period_*`/`expires_at` 显示恢复时间。
3. 无套餐或待生效时，应引导用户完成官方登录/官网流程并允许手动刷新；不要承诺能由插件发放。不要硬编码“新用户”“5 天”或“3M/日”，也不要写入日志、配置或 Issue 中的 JWT、Authorization、设备标识或完整请求头。
4. 若未来需要“领取”能力，应先取得官方新增的、明确文档化的服务端 API 与用户交互/验证要求；在此之前，把它列为不可实现/需人工官方流程，而非自动化功能。
