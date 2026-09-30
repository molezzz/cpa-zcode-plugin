# 许可证与依赖审查(MIT 独立实现)

- 审查日期:2026-10-01
- 审查对象:提交 `3e6a93b`(发布硬化与验证工具链落地)时的全部源码、链接依赖与发布工具链
- 结论:**通过** —— 本插件是 MIT 许可下的独立实现;链接进发布产物的全部第三方依赖均为 MIT;AGPL 参考仓库不在版本管理与发布资产之内。
- 复核:本提交的构建产物链接面经 `go list -deps` 复核,与下表一致;CI 的凭证泄漏审计与冒烟测试随本提交纳入。

## 1. 本仓库源码

- 许可:MIT(`LICENSE`)。
- 独立性:实现基于对上游可观察协议行为(OAuth 流程、凭证兑换、Anthropic Messages、计费端点)的独立核验,不复制、不翻译、不移植、不改写任何 AGPL 源码(ADR 0001)。`docs/zcode2api` 仅作为行为假设的核验来源。
- 结构独立性:数据模型、状态机、会话隔离、脱敏与安全边界均为自主设计,与参考仓库无源码对应关系。

## 2. 链接进发布产物的依赖

CGO 共享库只链接实际 import 的包。审查命令(可复跑):

```bash
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{"\t"}}{{.Module}}{{end}}' .
```

输出(非标准库部分,即全部外部链接面):

| 包 | 模块 | 版本 | 许可证 | 用途 |
| --- | --- | --- | --- | --- |
| `sdk/pluginabi`、`sdk/pluginapi` | `github.com/router-for-me/CLIProxyAPI/v8` | v8.0.4 | MIT | 宿主插件协议的类型契约 |
| `gopkg.in/yaml.v3` | `gopkg.in/yaml.v3` | v3.0.1 | MIT(Go-YAML) | 插件配置解析 |

其余 `go.mod` 中的间接依赖均为 CLIProxyAPI 宿主自身的依赖图,**不被本插件链接**(上表即全部),发布产物不携带它们。

许可证核验方法:CLIProxyAPI 的许可文本直接取自模块缓存中 `v8@v8.0.4/LICENSE`(MIT,版权 2025 Luis Pater / Router-For.ME);`gopkg.in/yaml.v3` 为上游 Go-YAML v3 的 MIT 许可。两者均与 MIT 插件兼容,且要求在分发时保留版权与许可声明——发布压缩包已包含本插件 `LICENSE`;`zcode.h` 由 Go 工具链生成,不含第三方代码。

## 3. AGPL 参考仓库的隔离

| 本地路径 | 上游 | 许可 | 隔离方式 |
| --- | --- | --- | --- |
| `docs/zcode2api/` | liu5269/zcode2api | AGPL-3.0 | `.gitignore` 排除,不进入 git 历史 |
| `docs/cpa-plugin-zcode/` | rensumo/cpa-plugin-zcode | 见其仓库 | `.gitignore` 排除,不进入 git 历史 |

- 两个参考仓库都只在本地用于行为核验与宿主工程形态参考,**不存在任何源码级引入**:`grep -rn` 核对本仓库没有来自参考仓库的函数、类型、常量或注释文本的对应物。
- 它们不会进入发布压缩包:打包来源只有仓库跟踪文件与 `go build` 产物(`scripts/release.sh`)。
- `git check-ignore docs/zcode2api docs/cpa-plugin-zcode` 应始终命中;CI 的凭证审计与 `git ls-files` 也不会包含它们。

## 4. CAPTCHA / 自动化组件审查

主任务明确禁止 CAPTCHA 自动化。核对结果:

- 源码中不存在任何验证码识别、浏览器自动化、指纹伪装或第三方打码服务的调用、依赖或配置项(`go list -deps` 全表即证:无 headless 浏览器、无自动化 SDK)。
- JWT 验证受阻被归类为 `verification_blocked` 状态,走受管 API Key 回退 + 五分钟重试,不做任何自动化绕过。

## 5. 复审触发条件

出现以下任一情况须重做本审查:

1. 升级 CLIProxyAPI SDK 版本或新增任何依赖;
2. 变更构建/打包方式(新的产物来源);
3. 引入任何新的参考仓库或上游行为样本。

复审时更新本文件的日期、提交与结论。
