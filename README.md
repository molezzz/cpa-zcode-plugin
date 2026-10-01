# cpa-zcode-plugin

`zcode` 是一个 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)(CPA)的 Go CGO 共享库 Provider 插件:它把一个 Z.AI Coding Plan 上游身份接入宿主的认证、调度、模型与执行器管道——JWT 为主凭证,同一 OAuth 流程创建的受管 API Key 为回退,不再需要独立网关或独立账号存储。

## 能力概览

- **宿主原生 OAuth**:从 CPA 的 Provider 认证入口发起登录;一次性授权会话、随机轮询秘密、五分钟 TTL、完成即清理。登录时同步把 OAuth access token 兑换为 Z.AI 业务 token(带 5 分钟过期 skew 缓存)并落盘,订阅/额度类接口因此开箱可用。
- **单账号双凭证**:一个上游身份对应一个宿主账号;Coding Plan JWT 为主,受管 API Key(`cpa-zcode-<随机后缀>`,只复用本插件记录的那个)为回退。
- **独立凭证状态机**:验证受阻(五分钟自动重试)、失效(需刷新/重登)、额度耗尽(额度刷新恢复)、限流/5xx(短暂冷却)各自独立;JWT→API Key 仅在无可见输出前以同一 payload 回退。
- **按 Z.AI 业务码分类**:响应优先按业务码(`code`/`msg`)而非 HTTP 状态码判定;`3012`(风控)不误标凭证失效、且不再把承载它的 405 透传给调用方;`1113`/`1304`/`1308`/`1310`/`1313-1321` 归额度耗尽,`3007` 归鉴权失败,`3002`/`3008-3010` 归限流。
- **模型**:验证过的静态基础模型 ∪ 按身份+环境动态发现(带成功 TTL 与失败冷却);动态永不取代静态。额度刷新读到的 `data.balances[].capabilities` 里的 `model:<id>` 作为 Coding Plan 自身的模型声明一并并入。
- **管理面**:认证后的脱敏状态页与固定操作词汇(OAuth 重试、凭证/额度/模型缓存刷新、批量刷新),每账号串行、批量先快照。
- **额度**:只查 `GET /billing/balance?app_version=<真实版本>`(官方已废弃 `billing/current`);`data.plans` 是权益权威,`data.balances` 是额度证据;管理面区分「有额度 / 无订阅 / 计划过期 / 上游 schema 不兼容(unknown)」。

## 配置

```yaml
plugins:
  configs:
    zcode:
      enabled: true
      priority: 1
      product:
        # 声明的 ZCode 客户端版本。上游按这个值判定能力与套餐权益,
        # 必须是一个真实发行版本:声明一个不存在的版本,等于按你实际运行
        # 的版本之外的后端策略来验证。
        # 取证方法:在能正常使用的 ZCode 客户端抓一次 start plan 的
        # balance 请求,读它的 app_version 查询参数——这是唯一权威来源。
        app_version: "3.14.3"
```

`app_version` 同时驱动 `User-Agent: ZCode/<ver>` 与 `X-ZCode-App-Version`,两处必须一致。默认值取自 `docs/ZCode` 中 `package.json` 记录的版本。

不做什么:CAPTCHA/验证自动化、独立网关、客户端凭证透传、按名扫描或接管非本插件创建的上游 Key。完整边界见 `docs/cpa-zcode-provider-plugin-plan.md` 与 ADR 0001。

## 安装

见 [docs/install.md](docs/install.md)(含平台矩阵、校验、升级、回滚与卸载)。

## 构建与测试

```bash
make check          # vet + 全部测试 + C 桥回环 + 加载/注册冒烟
make release        # 多平台共享库 + 压缩包 + SHA256SUMS(见 scripts/release.sh)
scripts/check-scrubbed.sh   # 凭证泄漏审计
```

要求 Go 1.26+(含 CGO 工具链);交叉构建需按 `scripts/release.sh` 头部说明提供各目标平台的 C 交叉编译器。

## 许可证与第三方声明

本项目以 [MIT](LICENSE) 许可发布,是独立实现(见 [ADR 0001](docs/adr/0001-independent-mit-implementation.md) 与 [许可证审查](docs/license-review.md))。

链接进发布产物的第三方组件:

| 组件 | 许可证 | 用途 |
| --- | --- | --- |
| [CLIProxyAPI v8](https://github.com/router-for-me/CLIProxyAPI) `sdk/pluginabi`、`sdk/pluginapi` | MIT | 宿主插件协议类型契约 |
| [gopkg.in/yaml.v3](https://gopkg.in/yaml.v3) | MIT(Go-YAML) | 配置解析 |

AGPL-3.0 的参考实现(`zcode2api` 等)仅存在于本地 git-ignored 目录,用于行为核验,没有任何代码被复制、翻译、移植或改写进本项目。
