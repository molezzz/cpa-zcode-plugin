# cpa-zcode-plugin

`zcode` 是一个 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)(CPA)的 Go CGO 共享库 Provider 插件:它把一个 Z.AI Coding Plan 上游身份接入宿主的认证、调度、模型与执行器管道——JWT 为主凭证,同一 OAuth 流程创建的受管 API Key 为回退,不再需要独立网关或独立账号存储。

## 能力概览

- **宿主原生 OAuth**:从 CPA 的 Provider 认证入口发起登录;一次性授权会话、随机轮询秘密、五分钟 TTL、完成即清理。
- **单账号双凭证**:一个上游身份对应一个宿主账号;Coding Plan JWT 为主,受管 API Key(`cpa-zcode-<随机后缀>`,只复用本插件记录的那个)为回退。
- **独立凭证状态机**:验证受阻(五分钟自动重试)、失效(需刷新/重登)、额度耗尽(额度刷新恢复)、限流/5xx(短暂冷却)各自独立;JWT→API Key 仅在无可见输出前以同一 payload 回退。
- **模型**:验证过的静态基础模型 ∪ 按身份+环境动态发现(带成功 TTL 与失败冷却);动态永不取代静态。
- **管理面**:认证后的脱敏状态页与固定操作词汇(OAuth 重试、凭证/额度/模型缓存刷新、批量刷新),每账号串行、批量先快照。
- **额度**:防御性解析——只有明确的余额证据才会标记/恢复耗尽;schema 漂移只显示 unknown。

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
