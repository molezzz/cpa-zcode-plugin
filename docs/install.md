# ZCode Provider 插件安装与回滚说明

本插件以 CGO 共享库(`zcode.so` / `zcode.dylib` / `zcode.dll`)的形式被 CLIProxyAPI(CPA)宿主加载,不引入独立网关进程或独立账号存储。本文说明如何在目标平台上安装、升级、回滚与卸载。

## 1. 平台与系统要求

| 平台 | 产物 | 依赖 |
| --- | --- | --- |
| linux/amd64、linux/arm64 | `zcode.so` | glibc ≥ 2.17;宿主需以动态链接方式运行 |
| darwin/arm64、darwin/amd64 | `zcode.dylib` | macOS 12 及以上 |
| windows/amd64 | `zcode.dll` | Windows 10 / Server 2016 及以上 |

宿主版本要求:支持 v8 插件 ABI(`cliproxy_plugin_init`,abi_version 1)的 CLIProxyAPI/CPA 宿主。插件不固定宿主小版本,只依赖稳定插件协议。

## 2. 安装步骤

1. **下载发布压缩包与校验和**

   从项目发布页获取与目标平台匹配的压缩包及 `SHA256SUMS`,例如 Linux x86_64 主机:

   ```bash
   # 以实际版本号替换
   VERSION=0.1.0
   PLATFORM=linux-amd64
   wget "https://github.com/molezzz/cpa-zcode-plugin/releases/download/v${VERSION}/zcode-v${VERSION}-${PLATFORM}.tar.gz"
   wget "https://github.com/molezzz/cpa-zcode-plugin/releases/download/v${VERSION}/SHA256SUMS"
   ```

2. **校验完整性**

   ```bash
   sha256sum -c SHA256SUMS 2>/dev/null | grep "${PLATFORM}"
   ```

   校验和是发布可信边界的一部分:不匹配的压缩包必须丢弃,不得安装。

3. **解压**

   ```bash
   tar -xzf "zcode-v${VERSION}-${PLATFORM}.tar.gz"
   ```

   解压得到一个目录,内含共享库、`zcode.h`、`LICENSE` 与本说明。压缩包不携带任何凭证或配置。

4. **安装到宿主插件目录**

   将压缩包内的 `zcode.so`(或对应平台扩展名的共享库)复制进 CPA 宿主的插件搜索目录(通常为配置中声明的插件目录,如 `plugins/`)。

   ```bash
   cp "zcode-v${VERSION}-${PLATFORM}/zcode.so" /path/to/cpa/plugins/
   ```

   同一插件目录内不要同时存在多个版本的插件库;升级前先按第 4 节移除旧版本。

5. **重启宿主并确认加载**

   重启 CPA 宿主后,在宿主日志中确认 `zcode` Provider 已注册。加载失败时宿主会记录 dlopen/初始化错误,常见原因:平台不匹配(如在 glibc 较老的系统上使用较新工具链构建的库)、遗漏依赖、插件目录配置错误。

6. **连接账号**

   通过 CPA 宿主原生的 Provider 认证入口发起 ZCode OAuth 登录;登录完成的账号会出现在宿主认证存储中,并在管理页(`GET /v0/management/zcode/page`)可见。

## 3. 升级

1. 按第 2 节下载并校验新版本压缩包(先不要解压覆盖)。
2. **备份当前版本**:记录现有共享库文件名与版本,或直接复制一份到备份目录。
3. 停止宿主,替换插件目录中的共享库文件(删除旧文件、复制新文件),再启动宿主。
4. 确认日志中新版本加载成功、既有账号仍在(账号凭证保存在宿主认证存储中,与插件库文件无关,升级不会清除)。
5. 出现问题时按第 4 节回滚。

## 4. 回滚

回滚 = 把插件共享库恢复为上一个可用版本,账号数据不需要也无法由本插件迁移:

1. 停止 CPA 宿主。
2. 用备份的上一个版本共享库**替换**(不是并存)当前版本文件。
3. 启动宿主,确认 Provider 加载成功、账号与管理页状态正常。

若没有备份旧版本,可直接下载上一个发布版本的压缩包,替换为其中的共享库。

**彻底卸载**:停止宿主后直接删除插件目录中的 `zcode.so` / `zcode.dylib` / `zcode.dll`,再启动宿主。宿主认证存储中由本插件创建的 `zcode` 账号记录会保留;如需一并清理,可在宿主中删除对应账号,或在上游控制台撤销/删除名为 `cpa-zcode-<随机后缀>` 的受管 API Key。插件不会主动操作任何非本插件创建的上游 Key。

## 5. 安全边界说明

- 插件从不展示、导出或转发完整凭证;管理页只提供脱敏摘要。
- 插件不会自动执行任何验证码(CAPTCHA)或绕过上游安全验证;遇到验证阻塞时自动回退到受管 API Key 并在五分钟后重试 JWT。
- 发布压缩包与校验和不含任何凭证;若你从非官方渠道获得压缩包,必须重新校验 `SHA256SUMS`。
