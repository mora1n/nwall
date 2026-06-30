# nwall

`nwall` 是一个基于 nftables 的单二进制防护工具，用于本机白名单流量保护、临时租约放行、出站限制、HTTP/TLS/SOCKS 封锁和下行伪装。

## 特性

- 单个 `nwall` 二进制；执行 `nwall` 默认打开配置界面
- 配置和运行状态都在 `/var/lib/nwall/nwall.db`
- 地区白名单按省份/城市选择
- 入站白名单、出站白名单、端口覆盖策略
- TCP 租约：默认放行访问来源 IPv4 所在 C 段，可按请求改成单 IP
- 下行伪装：按共享令牌向客户端发送指定体量的随机下行流量

## 安装

安装最新版：

```bash
curl -fsSL https://raw.githubusercontent.com/mora1n/nwall/main/scripts/install.sh | bash
```

安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/mora1n/nwall/main/scripts/install.sh | bash -s -- --version v0.1.0
```

手动下载 Release：

```bash
VERSION=v0.1.0
curl -LO "https://github.com/mora1n/nwall/releases/download/${VERSION}/nwall-linux-amd64-${VERSION}.tar.gz"
curl -LO "https://github.com/mora1n/nwall/releases/download/${VERSION}/nwall-linux-amd64-${VERSION}.tar.gz.sha256"
sha256sum -c "nwall-linux-amd64-${VERSION}.tar.gz.sha256"
tar -xzf "nwall-linux-amd64-${VERSION}.tar.gz"
cd "nwall-linux-amd64-${VERSION}"
./install.sh
```

安装不会覆盖已有 `/var/lib/nwall/nwall.db`。

## 快速开始

```bash
nwall
```

## 工作原理

`nwall` 运行在被保护的机器上，只管理本机访问规则。通过 TUI 或 CLI 修改配置，再执行 `nwall protect apply --confirm` 让规则生效；如果没有及时确认，nwall 会自动回滚，避免远程机器被错误规则锁死。

入站白名单决定哪些来源能访问本机服务；TCP 租约用于临时放行访问者，IPv4 默认放行来源 IP 所在 C 段，也可以用 `mask=32` 只放行单个 IP。公网入口可以运行 `lease trigger`，把 `/<token>` 访问转换成发往安装机的 TCP 租约消息；`<token>` 没有默认值，必须由用户显式配置。下行伪装按共享令牌校验客户端，然后发送指定体量的下行流量。

## 常用命令

查看帮助：

```bash
nwall -h
```

入站白名单：

```bash
nwall protect config set --clear-open-ports --open-port 2222 --open-port 19082 --guard-all true
nwall ingress cn select 广东省 四川省
nwall ingress city add 440100 440300 510100
nwall ingress custom add 198.51.100.0/24
nwall ingress port 443 city add 440100 440300
nwall protect apply --confirm
```

上面的城市 code 分别示例广州、深圳、成都。端口覆盖策略只影响指定端口，例如只允许广州和深圳访问 `443`。

出站白名单：

```bash
nwall egress enable
nwall egress custom add 198.51.100.0/24
nwall protect apply --confirm
```

HTTP/TLS/SOCKS 封锁：

```bash
nwall dpi http on
nwall dpi tls on
nwall dpi socks on
systemctl enable --now nwall-dpi.service
nwall protect apply --confirm
```

## 租约

生成并写入租约 key：

```bash
LEASE_KEY="$(nwall lease keygen)"
nwall lease config set --lease-key "$LEASE_KEY" --listen 192.0.2.10:19082 --trusted-relay 198.51.100.0/24
```

新增租约路由：

```bash
nwall lease route add default --idle-ttl 3d --allow 203.0.113.0/24
systemctl enable --now nwall-lease.service
```

`--allow 203.0.113.0/24` 表示只有这个 C 段内的来源能申请 `default` 租约。服务端实际放行的是请求内 `source-ip` 所在 C 段，除非请求带 `mask=24..32`。

配置公网触发器：

```bash
nwall lease trigger-config set --listen 127.0.0.1:19081 --trusted-proxy 127.0.0.1/32 --trusted-proxy ::1/128
nwall lease trigger-route add <token> --label default --target 192.0.2.10:19082 --idle-ttl 3d --ipv4-prefix-len 24
systemctl enable --now nwall-lease-trigger.service
```

`<token>` 是 URL 中的访问令牌，例如 `https://example.com/<token>`，请换成自己生成的随机字符串。反代到 `127.0.0.1:19081` 后，trigger 只信任来自 `--trusted-proxy` 的 `X-Real-IP` / `X-Forwarded-For`，再把真实来源 IP 写入 TCP 租约消息。访问 `?mask=32` 会只放行单 IP；访问 `?mask=24` 会放行 C 段。

发送 TCP 租约：

```bash
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --lease-key "$LEASE_KEY"
```

显式放行 C 段：

```bash
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 24 --lease-key "$LEASE_KEY"
```

只放行单 IP：

```bash
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 32 --lease-key "$LEASE_KEY"
```

TCP 租约消息自带时间戳、nonce 和签名。

## 下行伪装

服务端：

```bash
DOWNMASK_TOKEN="$(openssl rand -hex 16)"
nwall downmask config set --tcp-addr 0.0.0.0:15301 --token "$DOWNMASK_TOKEN"
nwall downmask seed --size 268435456
systemctl enable --now nwall-downmask.service
```

客户端拉取 1 GiB 下行流量：

```bash
nwall downmask pull --protocol tcp --remote-host 203.0.113.10 --remote-port 15301 --token "$DOWNMASK_TOKEN" --wanted-bytes 1073741824
```

`DOWNMASK_TOKEN` 是服务端和客户端一致的下行伪装共享令牌。它只用于下行伪装鉴权，不是公网触发器 URL 中的 `<token>`，也不是加密密钥。

## 更新

```bash
nwall update
```

指定版本：

```bash
nwall update --version v0.1.0
```

更新流程：解析 latest 或指定版本，下载 Release 与 sha256，校验，备份当前二进制和 systemd unit 到临时目录，原子替换，重启已启用服务，执行健康检查。任一步失败都会自动回滚；成功后临时备份会随临时目录清理。

## 卸载

交互式卸载：

```bash
nwall uninstall
```

保留配置 DB：

```bash
nwall uninstall --keep-config
```

删除配置 DB：

```bash
nwall uninstall --purge-config
```

卸载会停止 systemd 服务、删除活动规则、删除二进制和 unit。未指定 `--keep-config` 或 `--purge-config` 时，会询问是否删除 `/var/lib/nwall/nwall.db`。保留 DB 后重新安装，`nwall` 会从同一路径重新加载配置和运行状态。

## 运行依赖

| 依赖 / 能力 | 用途 |
| --- | --- |
| `nftables` | 应用、删除、检查防护规则 |
| `iproute2` (`ip`) | 出站白名单需要读取本机路由信息 |
| `root` 或 `CAP_NET_ADMIN` | 应用 nftables 规则、运行协议封锁 |
| `systemd` | 使用随包提供的服务 |
| `openssl` | 示例中生成 token；非 nwall 运行必需 |

## 构建依赖

| 依赖 | 用途 |
| --- | --- |
| Go | 构建 `nwall` |
| `tar` | 生成 Release 压缩包 |
| `sha256sum` | 生成和校验 Release 摘要 |

## 主要 Go 依赖包

| 包 | 用途 |
| --- | --- |
| `modernc.org/sqlite` | 单文件 SQLite DB |
| `github.com/charmbracelet/bubbletea` / `lipgloss` | TUI |
| `github.com/florianl/go-nfqueue/v2` | 协议封锁数据包队列 |
| `github.com/oschwald/maxminddb-golang/v2` | 构建地理数据资产 |

## 产物

构建产物：

| 路径 | 用途 |
| --- | --- |
| `dist/nwall` | 本地构建出的二进制 |
| `dist/nwall-linux-amd64-${VERSION}.tar.gz` | GitHub Release 压缩包 |
| `dist/nwall-linux-amd64-${VERSION}.tar.gz.sha256` | Release 校验文件 |

安装后产物：

| 路径 / unit | 用途 |
| --- | --- |
| `/usr/local/bin/nwall` | 主程序 |
| `/var/lib/nwall/nwall.db` | 配置、回滚快照、nonce、下行伪装种子和状态 |
| `nwall.service` | 开机恢复防护规则 |
| `nwall-dpi.service` | 协议封锁进程 |
| `nwall-lease.service` | TCP 租约 agent |
| `nwall-lease-trigger.service` | 公网 token 触发器 |
| `nwall-downmask.service` | 下行伪装服务 |

## 发布打包

通过 GitHub 手动创建 Release，上传 tar 包和 sha256 文件：

```bash
VERSION=v0.1.0 scripts/package.sh
```

命名标准：

```text
nwall-linux-amd64-${VERSION}.tar.gz
nwall-linux-amd64-${VERSION}.tar.gz.sha256
```

tar 包内包含：

```text
nwall
install.sh
uninstall.sh
systemd/*.service
README.md
```

## 源码验证

```bash
go test ./...
go vet ./...
go build ./...
VERSION=v0.1.0 scripts/package.sh
(cd dist && sha256sum -c nwall-linux-amd64-v0.1.0.tar.gz.sha256)
tar -tzf dist/nwall-linux-amd64-v0.1.0.tar.gz
```

## 注意事项

- `nwall` 的放行规则不能覆盖其他防火墙管理器已经做出的拒绝规则。
- 启用 HTTP/TLS/SOCKS 封锁后，需要保持 `nwall-dpi.service` 运行。
- 修改配置后，除服务自身监听参数外，防护规则需要执行 `nwall protect apply --confirm` 才会生效。
