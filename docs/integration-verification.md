# 授权隔离环境集成验证清单

本清单对应主任务(#1)与发布硬化任务(#9)中"在授权隔离身份上独立验证"的验收标准。自动化测试覆盖不了的只有一件事:**真实上游、真实授权身份、真实宿主的端到端行为**。这一步必须由持有授权测试身份的人在隔离环境中人工执行,任何人不得使用他人账号、生产账号或未授权身份。

## 0. 前置条件

- [ ] 持有一个**专门用于测试**的 Z.AI 账号与 Coding Plan 身份(隔离身份,非生产)。
- [ ] 一个运行在受控网络里的 CPA/CLIProxyAPI v8 宿主,日志输出可被检查。
- [ ] 已通过 `make check`(vet + 单测 + C 桥 + 冒烟)的插件共享库,或已发布的发布压缩包。
- [ ] 宿主日志级别足够观察 Provider 加载、认证与执行事件,但不输出请求体。

## 1. 验证项

按顺序执行;任何一项失败即停止并记录,不要带着失败继续。

### 证据等级

本清单的每条结论都必须标注它所属的证据等级,三类不得混写:

- **源码/单元测试已确认**:结论来自官方开放源码(`docs/ZCode`)或本仓测试,如 `3012` 在官方遥测归因表中映射为 `invalid_request`。
- **本地 mock 可验证**:结论由 httptest 模拟上游与插件闭环得出,如 405+3012 映射为调用方 400、不迁移凭证状态、不跨计费域回退。
- **需授权真实环境抓包**:结论必须来自隔离身份上官方客户端与插件同一场景的差分抓包,如 Start Plan JWT 的最终 wire 认证形态(是否同时携带 `Authorization: Bearer` 与 `x-api-key`)、设备/会话归因字段、官方 `/ultra-zai` 网关的实际计费域。抓包门槛未通过前,官方网关 adapter 不启用,相关 wire 细节不写成默认协议承诺。

禁止把第三类写成第一类:上游没有在源码或抓包中解释过的成因(包括把 `3012` 等同于"缺官方挑战材料"或验证码),一律不得写入代码注释、错误文案或文档。`3012` 的成因已于 2026-10-02 经授权抓包加差分实验取证(见 1.10 结论),属第一类+第二类证据,其门控是请求体 `system` 的官方前缀指纹,与任何头级差异无关。

### 1.1 OAuth 登录(宿主原生入口)

- [ ] 从 CPA 宿主原生 Provider 认证入口发起 `zcode` 登录,浏览器打开授权 URL,完成登录。
- [ ] 轮询在登录完成后返回成功;宿主认证存储出现一个按稳定身份命名的账号文件。
- [ ] 重复登录同一上游身份,不产生第二个账号(同账号更新,不新增)。
- [ ] 授权会话超时(放置 5 分钟不操作)后,会话进入过期状态并可重新发起;过期会话不可再完成登录。

### 1.2 受管 API Key 创建与记录

- [ ] 登录完成后,上游控制台出现名称形如 `cpa-zcode-<随机后缀>` 的新 Key,**仅此一个**,且每次重登录不重复创建(按记录复用)。
- [ ] 记录中保存了该 Key 的上游资源标识;管理页能看到 Key 的存在与状态,但看不到 Key 值。
- [ ] 在上游手动删除该 Key 后,管理页刷新凭证能观察到失效;插件不会去扫描或接管其它任何 Key。

### 1.3 业务 token 兑换链(前置)

OAuth 登录返回的 `data.zai.access_token` **不是**任何 `api.z.ai` 业务接口接受的凭证,必须先兑换。直接拿它打业务接口会返回 `{"code":401,"msg":"token expired or incorrect"}`——刚登录完几分钟内出现,极易被误判为凭证过期而反复重登。

- [ ] 登录完成后,auth 文件的 `zcode.oauth` 同时存在 `access_token`(兑换原料,带 `exp`)、`business_token`(兑换所得)、`business_token_expires_at`。
- [ ] 用该 auth 文件里的 `business_token`(不带 `Bearer` 前缀)请求 `GET /api/biz/subscription/list`,返回 `code:200` / `success:true`。
- [ ] 重启宿主后不重新登录,业务接口仍可用(业务 token 从 auth 文件读回,不重新兑换)。
- [ ] 兑换失败时,插件不丢失 Coding Plan 凭证:管理页仍可发起请求(走 JWT 或受管 API Key),并提示需要重新登录。

### 1.4 额度与权益前置(billing/balance)

**在验证推理之前必须先确认这一步**,否则"推理 200"可能只是在替一个其实没有套餐权益的账号兜底。

- [ ] `plugins.configs.zcode.product.app_version` 已设置为**客户端真实版本**。取证方式:在能正常使用的 ZCode 客户端抓一次 start plan 的 balance 请求,读其 `app_version` 查询参数。**不得**沿用参考实现里的 `3.0.0`/`3.0.1`。注意:实测该端点**不按这个值判定能力**,它只是客户端自身版本的上线声明(并驱动 `User-Agent` / `X-ZCode-App-Version`),但取值仍应真实。
- [ ] 插件发出的请求确认为 `GET /api/v1/zcode-plan/billing/balance?app_version=<版本>`,且 `Authorization` 是**裸 JWT**(不加 `Bearer`)。
- [ ] 该请求带有 `X-Device-Mid` 头,且值是一个格式合法的 UUID。该端点**以设备身份为门槛**:缺失时返回 `400 {"code":3001,"msg":"parameter error"}`——与参数错误无法区分。官方客户端在登录时生成一个 UUIDv4 存入设备身份文件,本插件在登录建凭证时写入 `zcode.device_mid`,重登保留原值。
- [ ] 该请求返回 `code:0` 且 `data.plans` **非空**。
  - 若返回 `{"code":3001,"msg":"parameter error"}`:**几乎总是缺 `X-Device-Mid`**,不是 `app_version` 的问题。**不要**猜测版本号重试——实测 `app_version` 取 `3.14.4`、`3.14.3`、`0.0.0` 甚至 `999.999.999`,只要带了合法设备身份都同样返回 200;而 `device_mid` 取一个随机 UUID(任意合法 UUID 均可)同样返回 200,取非 UUID 字符串才复现 3001。先确认请求头,而不是版本。
  - 若返回 `401`:凭证类型不对。该端点只接受 Coding Plan 裸 JWT;`business_token` 与 `x-api-key` 都得到 401,不会进入参数校验。
- [ ] **不得**以已废弃的 `billing/current` 的 `plans` 作为判据——该端点官方已废弃,它的 `plans:[]` 不构成"账号无订阅"的证据。

### 1.5 JWT / API Key 请求

- [ ] 用流式客户端(Claude Code 等发 Anthropic 格式请求的客户端)发起请求,JWT 主凭证生效,增量输出正常。
- [ ] 用非流式客户端发起同一请求,输出完整、无重复、无截断。
- [ ] 客户端自带的 `Authorization` / `x-api-key` / `Cookie` 不会出现在上游请求中(宿主日志或抓包确认上游只收到插件构造的凭证)。
- [ ] 上游请求体携带 `metadata.user_id`,且形态与官方客户端一致(证据等级:**源码/单元测试已确认** + 抓包比对见 1.10):字符串化 JSON `{"device_id":...,"account_uuid":"","session_id":...}`,其中 `device_id` 与同一请求的 `X-Device-Mid` 头同值(同一来源解析),`account_uuid` 为空串(官方即此形态),`session_id` 为按 auth 记录派生的稳定 UUID——同一调用方会话的多轮请求 `session_id` 不变,不同账号不同;无设备身份时整个字段省略而非发空值。调用方自带的 `metadata.user_id` 被替换为插件声明的身份,无关的 caller `metadata` 键保留。
- [ ] 归因头可关联(证据等级:**源码/单元测试已确认** + 抓包比对见 1.10):`x-request-id` / `x-zcode-trace-id` / `x-query-id` 同一请求内同值(官方允许同值或派生),跨请求换新;`x-session-id` 跨请求稳定(与 body `session_id` 同值),无会话上下文时省略;`x-zcode-session-type` 维持 `main`。

### 1.6 验证受阻回退(无 CAPTCHA 自动化)

- [ ] 在受控方式下触发一次上游验证阻塞(例如上游弹出验证要求的时段),观察:
  - 插件**不**尝试任何验证码自动化(源码与依赖中不存在 CAPTCHA/浏览器自动化组件,见许可证审查文档);
  - 请求自动回退到受管 API Key 并成功返回;
  - 管理页 JWT 状态显示 `verification_blocked`,约五分钟后自动重试 JWT。
- [ ] 若验证阻塞在隔离环境中无法复现,记录"未能复现",并改用模拟上游测试的结论作为依据(见 `credential_state_test.go` 与 `error_codes_test.go` 的分类矩阵)。
- [ ] 上游返回 `{"code":3012}` 时(通常以 HTTP 405 承载)观察(证据等级:**本地 mock 可验证** + 需抓包补全成因):
  - 调用方收到的状态码**不是** 405(405 会让调用方误判为"方法不允许"),而是 400;
  - JWT 状态**不**变为 `invalid`/`exhausted`,API Key 状态也**不**变——`3012` 在官方遥测归因中是请求级 `invalid_request`,不是凭证失效;
  - 成因(证据等级:**已取证**,2026-10-02 抓包+差分):网关完整性预检,门控是 `system` 数组以官方 system prompt 前两块打头;注入开关关闭或指纹收紧时仍会出现;
  - 请求**不**回退到受管 API Key:两条路径的计费/权益域不同,请求级拒绝不得因"可重试"就静默跨域消耗 API Key 余额(带 captcha/verify 证据的 403 回退不受影响);
  - 错误消息包含上游自己的 `msg` 与业务码,而不是一句 `upstream rejected the request (http 405)`;
  - 开启 `debug` 后,日志按请求记录 route、计费域、凭证种类、上游状态、业务码、有界 `msg`、`logid` 与回退决策;日志中不出现 token、API Key、Cookie、prompt、原始请求/响应 body、设备 ID 或会话 ID(`X-Session-Id` 的值自请求身份稳定后与 `X-Device-Mid` 一样只打印脱敏标记,仅 request/trace/query 归因 ID 打印值)。

### 1.7 模型与额度

- [ ] 未登录状态下模型列表仍有静态基础模型(Provider 可选、可预测)。
- [ ] 登录后动态发现生效,模型为静态 ∪ 动态;管理页模型缓存按身份+环境展示。
- [ ] 管理页"Quota"刷新能区分四种状态,而不是笼统的 unknown:
  - `plan with quota` —— 有套餐且有余额;
  - `no Coding Plan on this account` —— 上游明确报告无套餐(**这不是** unknown);
  - `plan expired` —— 套餐已终止;
  - `unknown (upstream answer not readable)` —— 上游 schema 漂移或答案不可读,此时**不**标记 exhausted/invalid,凭证状态保持不变。
- [ ] 上游携带业务失败时,被读成 unknown 而非"无套餐"——否则一次参数错误会伪装成账号没有订阅。实测 `3001` 走 HTTP **400** 承载,该状态与 200 携带业务码都要覆盖:判断依据是响应体里的业务码,不是 HTTP 状态。

### 1.8 管理面回调

管理页有两种入口,验证时都要走:宿主控制面板左侧导航的 **ZCode** 入口(打开
`/v0/resource/plugins/zcode/page`,**无鉴权**),以及鉴权路由 `/v0/management/zcode/page`。
无鉴权只覆盖 HTML 外壳——外壳里必须没有任何账号数据。

- [ ] 宿主控制面板左侧导航出现 **ZCode** 入口,点击可打开管理页;直接访问 `/v0/resource/plugins/zcode/page` 返回 200 HTML 外壳,不带任何鉴权头也能取到。
- [ ] 对该外壳做敏感词扫描(`grep -nE 'eyJ|sk-|cpa-zcode-[0-9a-f]'`),只命中 JS 字段名,无任何真实凭据值;外壳与 `/v0/management/zcode/page` 逐字节一致。
- [ ] 未填管理密钥时:页面不发起任何状态请求、不展示任何账号行,并给出"Enter and save the management key"提示。
- [ ] 填入密钥后状态可读(账号表、OAuth 会话、额度、模型缓存);五个操作(`refresh_credential` / `refresh_quota` / `refresh_models` / `oauth_retry` / `batch_refresh`)各执行一次并观察结果与串行提示。
- [ ] 密钥错误或被撤销时(宿主答 401):密钥从 localStorage 清除、表格清空、输入框重新聚焦、给出可读提示,且不再按 20 秒定时器重试该密钥。
- [ ] 密钥只落在 localStorage:DevTools 里 sessionStorage 与 cookie 均无该值。
- [ ] OAuth 重试返回的授权链接可完成登录,完成后账号状态与凭证正确落盘。
- [ ] 页面无重复提交、无旧响应覆盖新状态的现象。
- [ ] `POST /v0/resource/plugins/zcode/page` 不被路由到(资源路由仅 GET);`/v0/resource/plugins/zcode/state` 返回 404 而不是账号数据。

### 1.9 目标平台宿主加载

- [ ] 在每个目标平台上,用发布压缩包(经 `SHA256SUMS` 校验)按 `docs/install.md` 安装,宿主成功加载并注册。
  自动化冒烟的覆盖面:CI 在 Ubuntu 原生执行加载/注册冒烟;release 工作流在 linux/amd64 与 darwin/arm64 原生冒烟。windows/amd64 与 darwin/amd64 产物未做自动化加载冒烟,依赖本项的人工宿主加载验证。
- [ ] 按 `docs/install.md` 第 4 节完成一次升级与一次回滚演练。

### 1.10 请求身份与归因差分抓包(#15 后续,证据等级:**抓包已完成,结论已回填**)

2026-10-02 已完成抓包(会话 `20261002-194452_2344fd`,官方 Windows 客户端 3.14.4,同账号,
经本机 mitmproxy 中继)与 26 组单变量差分实验(插件 JWT 直连上游,矩阵随 issue #16 归档)。
结论:

- **3012 门控 = 请求体 `system` 数组以官方 ZCode system prompt 前两块打头**(CLI 前缀句
  "You are ZCode, an interactive coding agent" + 完整 agent 身份段;独立块、按序、不可合并
  /替换;调用方内容只能后置;`cache_control` 无关;无 system/单块/乱序/合并/调用方前插均为
  3012)。**所有头级差异经单变量排除**:`x-api-key` 双头、UA 的 ai-sdk 后缀、`X-Device-Mid`
  缺失、Referer 斜杠、归因头语义——官方头集逐字节重放(含官方自己的 JWT)从脚本客户端发出
  仍是 3012;插件现行头 + 官方 system 块 = 200。
- 官方 `metadata.user_id` 确为字符串化 JSON,`device_id`/`account_uuid`/`session_id` 与
  #15 注入形态一致;官方 `x-session-id` 与 body `session_id` 同值、会话内稳定;官方同时携带
  `x-api-key` 与 `Authorization: Bearer`(同值)——以上为抓包证实的形态事实,但均**不是**
  3012 的门控。
- 维护者决策(issue #16,2026-10-02):插件自动注入官方 system 前缀
  (`inject_official_system_prefix`,默认开;实现 `system_prefix.go`)。注入文本取自实测
  通过的官方请求(块 2 为抓包 preview 前缀,实验证明足以过门控)。
- 残余观察项(不影响 3012,抓包时顺手记录):官方每轮对话发 `session-type: main` 与
  `other` 交替的多请求;官方 Messages 请求不带 `X-Device-Mid` 头(billing 端点才带);
  `x-query-id` 为 UUIDv7 形态。这些差异对插件行为无已知影响,若未来指纹收紧可回来复核。

以下原始清单保留为方法论记录(当时"不得在抓包前写成协议承诺"的纪律对 #14/#15 全程有效):

用现有 openai_reg mitmproxy 链路,在隔离身份上分别抓官方 CLI 与本插件同一场景的
`POST /api/v1/zcode-plan/anthropic/v1/messages` 出站请求,逐头逐 body 比对以下项目。

用现有 openai_reg mitmproxy 链路,在隔离身份上分别抓官方 CLI 与本插件同一场景的
`POST /api/v1/zcode-plan/anthropic/v1/messages` 出站请求,逐头逐 body 比对以下项目。比对
结论按证据等级回填到对应文档;**不得**在抓包前把任何一条写成默认协议承诺。

- [ ] body `metadata` 形态:官方 `metadata.user_id` 是否确为字符串化 JSON,字段序与取值
  (`device_id` / `account_uuid` / `session_id`)与插件注入的是否一致;官方无会话上下文的请求
  (如有)`session_id` 是省略还是空串。
- [ ] 四个归因头的关系:官方同一会话多轮请求间 `x-session-id` 是否稳定、`x-zcode-trace-id`
  是随请求还是随会话、`x-request-id` / `x-query-id` 与 trace 的同值/派生关系,插件"同请求内
  同值、session 稳定"的形态是否需要修正。
- [ ] 双头鉴权形态:官方是否同时携带 `x-api-key` 与 `Authorization: Bearer`(官方源码
  `model-execution.ts` 的 `withAnthropicAuthorizationHeader` 注释声称网关同时读取两者)。
  **抓包证实前,插件维持仅 `Authorization: Bearer`;证实后另行决定是否将 `x-api-key` 双头
  纳入默认协议**(沿用 #14 的 route resolver 与验证门槛)。
- [ ] 若插件补齐请求构造后仍被 `3012` 拒绝:对比请求被拒前后所有可观测差异,只记录差异本身,
  不推断成因——`3012` 的风控语义维持 #14 的结论纪律。

## 2. 记录与脱敏要求

验证产生的**一切**内容——日志摘录、录制的上游响应、截图、issue 附件——在保存/粘贴前必须清除:

| 必须清除 | 说明 |
| --- | --- |
| JWT 与 access token | 任何 `eyJ...` 形态的三段式令牌 |
| API Key | `cpa-zcode-*` 的 Key 值、任何 `sk-` 形态密钥 |
| Cookie 与轮询秘密 | 会话 Cookie、OAuth 轮询 Bearer 秘密 |
| 授权 URL 中的敏感参数 | `code=`、`state=`、`access_token=` 的实际值(保留可读的授权端点域名即可) |
| 用户 prompt 与上游响应原文 | 截图只保留状态字段;日志摘要只保留错误码 |

操作规程:

0. **已知残留风险(接受而非修复)**:管理密钥按设计只存 localStorage,同一宿主源下的任何脚本(含其他插件的资源页)都能读到它。这是「不得落 cookie / sessionStorage」这条硬要求的直接代价,换取的是密钥不随每个宿主请求自动外发。验证环境请使用不含无关插件的独立宿主;该风险随宿主自身的 XSS 防护能力变化,不由本插件兜底。
1. 对要提交进仓库的内容先跑 `scripts/check-scrubbed.sh`(它扫描 git 跟踪文件与 dist 产物)。
2. 对仓库外的单文件(日志、截图 OCR 文本、录制响应),直接人工复核:
   `grep -nE 'eyJ|sk-|Bearer [A-Za-z0-9._-]{25,}|(code|state)=[A-Za-z0-9]{24,}' <文件>`,命中即须清除。
3. 隔离身份的会话在验证结束后全部作废:在宿主中删除测试账号,在上游撤销受管 Key 与授权。

## 3. 结果记录

- [ ] 每个验证项记录:日期、平台、宿主版本、结论(通过/失败/未能复现)、脱敏后的证据。
- [ ] 结果以评论形式附在 #9;失败项开启独立 issue 并按仓库 triage 流程打标。
- [ ] 全部通过后,由执行人在 #9 勾选对应验收项并注明执行人、环境与日期。
