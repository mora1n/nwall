# nwall

`nwall` 是一个单二进制的本机防护工具：TUI 配置，SQLite 保存状态，systemd 运行守护进程。

## 特性

- 执行 `nwall` 默认打开 TUI；不用编辑配置文件
- 配置、运行态、回滚快照和 nonce 保存在 `/var/lib/nwall/nwall.db`
- 入站白名单支持本机端口和 DNAT 入站转发，按省份、城市、自定义 CIDR、单端口覆盖放行
- TCP 租约默认放行来源 IPv4 的 `/24`，可用 `mask=32` 改为单 IP
- 下行伪装支持服务端发流、客户端按 RX/TX 缺口自动拉取
- systemd 只需要一个 `nwall.service`

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
curl -LO "https://github.com/mora1n/nwall/releases/download/${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS
tar -xzf "nwall-linux-amd64-${VERSION}.tar.gz"
cd "nwall-linux-amd64-${VERSION}"
./install.sh
```

`install.sh` 会安装并启动 `nwall.service`。安装不会覆盖已有 `/var/lib/nwall/nwall.db`。保留旧 DB 重新安装时，nwall 会从同一路径加载配置。

## 工作原理

nwall 管理本机 input 以及 DNAT 入站转发规则。你通过 TUI 或 CLI 写入 SQLite DB，再执行 `nwall protect apply --confirm` 应用防护规则；未确认的 apply 会自动回滚，避免远程机器被错误规则锁死。

长期任务都由 `nwall daemon` 托管：协议封锁、TCP 租约服务端、公网 token 触发器、下行伪装服务端和自动拉取。`nwall status` 通过 `/run/nwall/nwall.sock` 查看守护进程状态；`nwall reload` 让守护进程重新读取 DB 配置。

TCP 租约只走 TCP 消息：请求里携带来源 IP、时间戳、nonce 和签名。IPv4 默认放行来源 IP 所在 `/24`，访问触发器时可用 `?mask=32` 放行单 IP，也可用 `?mask=24` 明确放行 C 段。

下行伪装的 seed 文件默认保存为 `/var/lib/nwall/downmask/seed.bin`；DB 只保存 `seed_path`，不会保存 seed 内容。

## 规则优先级

入站本机流量和 DNAT/forward 流量使用同一套防护语义：

- loopback、已建立连接先放行；invalid 连接先丢弃
- TCP 租约服务端端口会优先放行允许发送租约的来源，保证 trigger 或直接发送能投递签名租约
- 公开端口直接放行，不走入站白名单，也不进入协议封锁
- 受保护流量先检查临时租约，再检查端口覆盖策略，最后检查全局入站白名单
- 端口覆盖策略只影响指定公网入口端口；DNAT 入口按公网原始端口匹配
- 入站自定义 CIDR 是全局白名单的一部分；出站自定义 CIDR 只在出站白名单启用时作用于 output
- 协议封锁只检查已经被白名单或临时租约允许的受保护流量；跳过端口会直接放行

默认配置保留 `22` 为公开端口和协议封锁跳过端口，作为 SSH 安全垫。TUI 里新增端口时输入框保持为空，避免把默认安全垫误当作新配置项。

## 快速开始

```bash
nwall
```

常用守护进程命令：

```bash
nwall status
nwall reload
systemctl status nwall.service
```

## 入站白名单

推荐用 TUI 选择省份/城市：

```bash
nwall
```

CLI 示例：

```bash
nwall protect config set --clear-open-ports --open-port 2222 --open-port 19082 --guard-all true
nwall ingress enable
nwall ingress cn select 广东省 四川省
nwall ingress city add 440100 440300 510100
nwall ingress custom add 198.51.100.0/24
nwall ingress port 443 city add 440100 440300
nwall protect apply --confirm
nwall reload
```

说明：

- `440100 440300 510100` 示例为广州、深圳、成都
- 选中省份后，同省城市会被省份 IP 段覆盖
- `ingress port 443 ...` 只影响指定端口
- DNAT 转发按公网原始端口匹配，例如公网 `41423 -> 后端:40422` 应配置 `41423`，不是后端端口 `40422`
- `open_ports` 同样按公网原始端口公开放行 DNAT 转发入口；未公开的 DNAT 新连接会进入白名单判定，未命中则 drop
- 入站白名单关闭时只关闭来源限制；已开启的 HTTP/TLS/SOCKS 协议封锁仍会检查受保护流量

## 出站白名单

```bash
nwall egress enable
nwall egress custom add 198.51.100.0/24
nwall protect apply --confirm
nwall reload
```

## 协议封锁

```bash
nwall dpi http on
nwall dpi tls on
nwall dpi socks on
nwall dpi skip-port add 2222
nwall protect apply --confirm
nwall reload
```

## TCP 租约

TCP 租约用于把来源 IP 临时写入 nftables 动态集合，适合临时放行入站或 DNAT/forward 入口。IPv4 默认放行来源 `/24`，访问触发器时可用 `?mask=32` 只放行单 IP。TUI 交互部署见 [TCP 租约 TUI 部署指南](docs/tcp-lease-tui.md)。

### CLI 等价配置

生成共享 key 和 URL token：

```bash
LEASE_KEY="$(nwall lease keygen)"
TOKEN="$(openssl rand -hex 16)"
```

无中转机直接发送租约：

安装机：

```bash
nwall lease server set --lease-key "$LEASE_KEY" --listen 0.0.0.0:19082 --trusted-relay 203.0.113.9
nwall lease route add default --idle-ttl 3d
nwall protect apply --confirm
nwall reload
```

发送端：

```bash
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 24 --lease-key "$LEASE_KEY"
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 32 --lease-key "$LEASE_KEY"
```

无中转机提供 token 触发器：

```bash
nwall lease server set --lease-key "$LEASE_KEY" --listen 127.0.0.1:19082
nwall lease route add default --idle-ttl 3d
nwall lease trigger set --listen 127.0.0.1:19081 --trusted-proxy 127.0.0.1 --trusted-proxy ::1
nwall lease trigger-route add "$TOKEN" --label default --target 127.0.0.1:19082 --idle-ttl 3d --ipv4-prefix-len 24
nwall protect apply --confirm
nwall reload
```

有中转机提供 token 触发器：

```bash
# 安装机
nwall lease server set --lease-key "$LEASE_KEY" --listen 0.0.0.0:19082 --trusted-relay 198.51.100.20
nwall lease route add default --idle-ttl 3d
nwall protect apply --confirm
nwall reload

# 中转机
nwall lease server set --lease-key "$LEASE_KEY"
nwall lease trigger set --listen 127.0.0.1:19081 --trusted-proxy 127.0.0.1 --trusted-proxy ::1
nwall lease trigger-route add "$TOKEN" --label default --target 192.0.2.10:19082 --idle-ttl 3d --ipv4-prefix-len 24
nwall reload
```

`trusted-relay` 是允许连接安装机 TCP 租约服务端的发送端或中转机出口；`trusted-proxy` 只信任这些反代来源提供的 `X-Real-IP` / `X-Forwarded-For`。如果 trigger 直接暴露给公网，不要把公网客户端网段填进 `trusted-proxy`，否则客户端可以伪造来源 IP。修改 daemon 组件配置后执行 `nwall reload`；修改防护规则、公开端口、允许发送租约的来源或首次启用防护后执行 `nwall protect apply --confirm`。

## 下行伪装

生成下行伪装共享密钥和 seed：

```bash
DOWNMASK_KEY="$(openssl rand -hex 16)"
nwall downmask seed --size 268435456
```

服务端：

```bash
nwall downmask server set --tcp 0.0.0.0:15301 --udp 0.0.0.0:15301 --token "$DOWNMASK_KEY"
nwall reload
```

客户端自动拉取：

```bash
nwall downmask client set --min-ratio 1.5 --max-ratio 2.0 --min-deficit-bytes 20MB --max-bytes-per-run 500MB --max-jitter 60 --protocol-mode parallel --tcp-enabled true --udp-enabled true --remote-port 15301 --token "$DOWNMASK_KEY" --speed-limit 4M --timeout 300 --speed-jitter-percent 12 --bytes-jitter-percent 18
nwall downmask target add 192.0.2.20 --weight 1
nwall reload
```

`--iface` 可省略或留空，自动拉取运行时会按默认路由自动探测统计网卡；多出口机器建议显式指定，例如 `--iface eth0`。

多目标：

```bash
nwall downmask target add 192.0.2.20 --weight 2
nwall downmask target add 198.51.100.20 --weight 1 --tcp-enabled true --udp-enabled false
nwall downmask target list
```

手动拉取和状态：

```bash
nwall downmask pull --protocol tcp --remote-host 192.0.2.20 --remote-port 15301 --token "$DOWNMASK_KEY" --wanted-bytes 1GB
nwall downmask run
nwall downmask status
```

`DOWNMASK_KEY` 只用于下行伪装服务端和客户端鉴权。它不是公网触发器 URL 的 `<token>`。

## 更新

```bash
nwall update
nwall update --version v0.1.0
```

更新流程：

1. 解析 `latest` 或指定版本
2. 下载 `nwall-linux-amd64-${VERSION}.tar.gz` 和 `SHA256SUMS`
3. 校验 SHA256
4. 备份当前二进制和 systemd unit 到临时目录
5. 原子替换二进制和 unit
6. 重启 `nwall.service`
7. 健康检查失败则自动回滚；成功后临时备份自动清理

## 卸载

```bash
nwall uninstall
nwall uninstall --keep-config
nwall uninstall --purge-config
```

卸载会停止服务、删除 nwall 规则、删除二进制和 systemd unit。

## 运行依赖

| 依赖 / 能力 | 用途 |
| --- | --- |
| `nftables` | 应用、删除、检查本机规则 |
| `iproute2` (`ip`) | 出站白名单读取路由信息 |
| `root` 或 `CAP_NET_ADMIN` | 应用规则和运行协议封锁 |
| `systemd` | 运行 `nwall.service` |
| `openssl` | 示例中生成随机 key；不是 nwall 运行必需 |

## 构建依赖

| 依赖 | 用途 |
| --- | --- |
| Go | 构建 `nwall` |
| `tar` | 生成 Release 压缩包 |
| `sha256sum` | 生成和校验 Release 摘要 |

## 主要 Go 依赖包

| 包 | 用途 |
| --- | --- |
| `modernc.org/sqlite` | SQLite DB |
| `github.com/charmbracelet/bubbletea` / `lipgloss` | TUI |
| `github.com/florianl/go-nfqueue/v2` | 协议封锁队列 |
| `github.com/oschwald/maxminddb-golang/v2` | 构建地理数据资产 |

## 产物

构建产物：

| 路径 | 用途 |
| --- | --- |
| `dist/nwall-linux-amd64-${VERSION}/nwall` | Release 二进制 |
| `dist/nwall-linux-amd64-${VERSION}.tar.gz` | GitHub Release 压缩包 |
| `dist/SHA256SUMS` | GitHub Release 校验文件 |

安装后产物：

| 路径 / unit | 用途 |
| --- | --- |
| `/usr/local/bin/nwall` | 主程序 |
| `/var/lib/nwall/nwall.db` | 配置、运行态、回滚快照、nonce |
| `/var/lib/nwall/downmask/seed.bin` | 下行伪装 seed 文件 |
| `/run/nwall/nwall.sock` | 守护进程本地控制 socket |
| `nwall.service` | 单守护进程 systemd unit |

## 发布打包

通过 GitHub 手动创建 Release，上传 tar 包和 `SHA256SUMS`：

```bash
VERSION=v0.1.0 scripts/package.sh
```

命名标准：

```text
nwall-linux-amd64-${VERSION}.tar.gz
SHA256SUMS
```

tar 包内包含：

```text
nwall
install.sh
uninstall.sh
systemd/nwall.service
README.md
```

## 源码验证

```bash
go test ./...
go vet ./...
go build ./...
bash -n scripts/install.sh scripts/uninstall.sh scripts/package.sh
systemd-analyze verify systemd/*.service
VERSION=v0.1.0 scripts/package.sh
(cd dist && sha256sum -c SHA256SUMS)
tar -tzf dist/nwall-linux-amd64-v0.1.0.tar.gz
```
