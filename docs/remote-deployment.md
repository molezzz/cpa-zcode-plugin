# CPA 远程构建与部署手册（192.168.1.2 NAS）

ZCode 插件针对 Linux amd64、使用 CGO 构建。遵循 `~/work/workbuddy-cliproxy-plus` 的实际构建路径：**源码在 Mac 编辑，编译在 NAS 上的 Go Docker 镜像内执行**。NAS 宿主机和 CPA 容器本身都没有 Go；不要尝试在 Mac 原生编译，或把 macOS 的 `.dylib` 放进 Linux 插件目录。

本文中，NAS 地址、用户、CPA bind mount、Go 1.26 镜像以及 NAS 上已有的 ZCode 构建目录均已实际检查。对于 WorkBuddy 的通用做法（NAS Docker 编译）与 ZCode 现有副本实际采用的命令（Makefile 的 `make build`），下面会区分已核验内容与为 ZCode 适配的建议命令。

## 目标实例和构建环境

| 项目 | 值 |
|---|---|
| NAS SSH 用户 / 主机 | `admin@192.168.1.2` |
| NAS 架构 | Linux x86_64 / amd64 |
| CPA 容器 / 镜像 | `cli-proxy-api` / `eceasy/cli-proxy-api:latest` |
| CPA 插件目录（NAS） | `/vol1/1000/docker/cliproxyapi/plugins/linux/amd64/` |
| CPA 插件目录（容器） | `/CLIProxyAPI/plugins/linux/amd64/` |
| ZCode NAS 工作副本 | `/vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/` |
| Go 构建镜像 | `golang:1.26`（NAS 上已有，`linux/amd64`） |
| 插件文件 | `zcode.so` |

CPA 将 NAS 的 `/vol1/1000/docker/cliproxyapi/plugins` bind-mount 到容器 `/CLIProxyAPI/plugins`。`admin@192.168.1.2` 可通过 Docker 管理该容器和写入插件目录；不需要 root SSH 或密码。

NAS 上的 ZCode 工作副本已经存在，但它可能落后于 Mac 当前工作树。部署时应从 Mac 将**明确选定的源码版本**同步到该目录，再在 NAS Docker 中编译。不要把 NAS 上旧副本当作当前工作树。

## 1. 本地检查与同步源码

先在 Mac 仓库根目录完成检查：

```sh
make check
```

确认 SSH 登录及目标目录：

```sh
ssh admin@192.168.1.2 'uname -m && docker image inspect golang:1.26 --format "{{.Os}}/{{.Architecture}}" && ls -ld /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin'
```

预期为 `x86_64` 和 `linux/amd64`。将当前仓库内容同步到 NAS 工作副本；排除本地构建产物、版本控制元数据和 NAS 上不应被覆盖的文件。一个显式列出源码和必要元数据的 `rsync` 方式：

```sh
rsync -av --delete \
  --exclude='.git/' \
  --exclude='dist/' \
  --exclude='cpa-zcode-plugin' \
  --exclude='abi_smoke' \
  --exclude='*.dylib' \
  --exclude='*.so' \
  --exclude='*.h' \
  ./ admin@192.168.1.2:/vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/
```

> `--delete` 会删除目标目录中不在当前 Mac 工作树里的文件。运行前必须检查源、目标路径与排除规则；如果不确定，先去掉 `--delete`，或先加 `--dry-run` 预览。不要让同步操作触及 `plugins/linux/amd64/` 下已部署的插件或备份。

同步完成后，检查 NAS 上的关键文件已更新：

```sh
ssh admin@192.168.1.2 \
  'ls -l /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/{go.mod,Makefile,client_fingerprint.go} 2>/dev/null'
```

## 2. 在 NAS 的 Go 容器中构建

Go 1.26 镜像在 NAS 上，Docker 容器通过 bind mount 使用 NAS 工作副本。`CGO_ENABLED=1` 是构建 CPA C-shared 插件所必需的。

仓库 Makefile 声明的构建入口（**NAS 容器内执行**）：

```sh
cd /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin
make build GOOS=linux GOARCH=amd64 PLUGIN_OUTPUT=zcode.so
```

或者从 Mac 经 SSH 在 NAS 上一次性运行（不使用 `sh -l`，避免 login shell 重置容器 PATH）：

```sh
ssh admin@192.168.1.2 'docker run --rm \
  -v /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin:/src \
  -w /src -e GOPROXY=https://goproxy.cn,direct golang:1.26 \
  make build GOOS=linux GOARCH=amd64 PLUGIN_OUTPUT=zcode.so'
```

> **实测补充（2026-10-02，#17 部署）：** NAS 容器访问 `proxy.golang.org` 会超时，`go build` 在下载 `CLIProxyAPI/v8` 与 `yaml.v3` 时挂住。必须加 `-e GOPROXY=https://goproxy.cn,direct`（或先在容器里 `go mod download` 走同一 proxy）。这是 NAS 网络出口的固有限制，与源码无关。

已在 NAS 只读验证：`golang:1.26` 镜像是 `linux/amd64`，含 Go 1.26.8、GCC 和 Make；Go 位于 `/usr/local/go/bin/go`，容器镜像默认 PATH 包含它。NAS 宿主和 CPA 服务容器本身没有 Go。NAS 上已有 `pluginbuild/cpa-zcode-plugin/zcode.so`，表明该目录曾产出共享库，但时间戳本身不能证明它与当前 Mac 工作树一致。
迄今未从 WorkBuddy 项目中发现可复用的 NAS build 脚本，因此上述命令是针对该 NAS 已验证镜像和 ZCode Makefile 写出的直接 NAS build 命令，而不是 WorkBuddy 现成脚本的复制。

**构建产物必须与线上产物逐字节可区分。** 替换前记录构建产物的字节数与 BuildID（`file zcode.so` 会打印 `BuildID[sha1]=...`），替换后用它确认线上跑的就是新构建；仅凭时间戳或"文件存在"不算部署成功（#17 部署即以 8184560B / BuildID `07133192…` 核对）。

构建后检查产物格式和导出文件：

```sh
ssh admin@192.168.1.2 \
  'file /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/zcode.so && ls -l /vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/zcode.{so,h}'
```

应为 Linux ELF x86-64 shared object。构建失败时停止，不要继续替换线上插件。

## 3. 备份并原子替换线上插件

以下操作会修改远端 CPA 插件并造成服务重启。先保留带时间戳的旧版，再从构建目录复制到临时文件，最后原子替换：

```sh
ssh admin@192.168.1.2 '
  set -eu
  plugin=/vol1/1000/docker/cliproxyapi/plugins/linux/amd64/zcode.so
  built=/vol1/1000/docker/cliproxyapi/pluginbuild/cpa-zcode-plugin/zcode.so
  stamp=$(date +%Y%m%d%H%M%S)
  test -s "$built"
  cp -p "$plugin" "$plugin.bak-$stamp"
  cp "$built" "$plugin.new"
  chmod 755 "$plugin.new"
  mv "$plugin.new" "$plugin"
  ls -l "$plugin" "$plugin.bak-$stamp"
'
```

不要在没有成功生成和检查 NAS 目标二进制之前备份/覆盖线上文件。保留备份直到加载与健康检查确认成功。

## 4. 重启 CPA 并验证加载

插件由 CPA 启动时加载；替换后重启容器：

```sh
ssh admin@192.168.1.2 'docker restart cli-proxy-api'
```

检查容器状态与近期日志：

```sh
ssh admin@192.168.1.2 'docker ps --filter name=cli-proxy-api --format "{{.Names}} {{.Status}}" && docker logs --since 5m cli-proxy-api 2>&1 | tail -100'
```

再通过 CPA 管理 API 确认 `zcode` 已注册，并检查元数据版本。管理地址和密钥只能从本机受保护的 `~/.openclaw/secrets/cpac.env` 读取，不要写入文档或日志：

```sh
set -a
. "$HOME/.openclaw/secrets/cpac.env"
set +a
curl -fsS -H "Authorization: Bearer ${CLIPROXY_MGMT_KEY}" \
  "${CLIPROXY_BASE_URL}/v0/management/plugins" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); [print(p["id"], p.get("metadata",{}).get("version"), p.get("effective_enabled")) for p in d.get("plugins",[]) if p.get("id")=="zcode"]'
```

最后用 `/v1/models` 和一个最小模型请求进行功能验证。管理 API 中版本仍为旧版、容器没有成功启动或插件未注册时，先回滚，不要把文件存在误当成部署成功。

## 回滚

选择刚才创建的 `zcode.so.bak-<timestamp>`，恢复并重启：

```sh
ssh admin@192.168.1.2 \
  'cp -p /vol1/1000/docker/cliproxyapi/plugins/linux/amd64/zcode.so.bak-<timestamp> /vol1/1000/docker/cliproxyapi/plugins/linux/amd64/zcode.so && docker restart cli-proxy-api'
```

然后重复容器状态、日志和管理 API 检查。

## 证据和边界

- WorkBuddy 仓库 README 的安装段（`~/work/workbuddy-cliproxy-plus/README.md`）说明插件需要 Go 1.26+、gcc，目标架构匹配，并以 `CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared` 生成 `.so`。
- WorkBuddy handoff（`~/work/workbuddy-cliproxy-plus/docs/WORKBUDDY_CPA_HANDOFF.md`）曾记录服务器/CPA 容器无 Go；这与 NAS 上后来存在的 `golang:1.26` 镜像及 NAS 工作树/二进制一致：构建 Go 工具链由 Docker 镜像提供，而非 Mac 或 CPA 容器本身。
- 当前 NAS 已验证的事实：SSH 用户 `admin`；Linux amd64；Docker 镜像 `golang:1.26` 为 `linux/amd64`；NAS Go 命令和 CPA 容器内 Go 命令缺失；CPA 插件目录 bind mount；NAS 上有 ZCode `pluginbuild/cpa-zcode-plugin` 工作副本和 `zcode.so`。
- NAS 上没有从 WorkBuddy 仓库发现可复用的 deploy 脚本，WorkBuddy README 的直 build 命令也不是 NAS Docker 编译脚本。因此上面 `docker run` 命令是按已核验 NAS 镜像、路径、Makefile 构造的 ZCode 操作步骤，不声称是 WorkBuddy 仓库现成脚本的逐字复刻。
- 本文只记录部署方法；执行部署、覆盖远端 `.so` 或重启 CPA 都必须在明确要求时另行进行。
