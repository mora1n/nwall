# TCP 租约 TUI 部署指南

TCP 租约用于把访问者来源 IP 临时写入 nftables，适合临时放行入站或 DNAT/forward 入口。共享 key 用于 TCP 租约签名，URL token 只是公网路径令牌，两者不要混用。

## 流程

```mermaid
flowchart LR
  C[访问者] -->|HTTPS /token| P[反代]
  P -->|真实客户端 IP| T[nwall token 触发器]
  T -->|签名 TCP 租约| A[安装机 TCP 租约服务端]
  A -->|写入 lease4_24..lease4_32 / lease6| N[nftables]
  N --> G[临时放行入站或 DNAT/forward]
```

无中转机时，token 触发器和 TCP 租约服务端都在安装机；有中转机时，token 触发器在中转机，TCP 租约服务端在安装机。

## 通用配置

运行 `nwall`，进入 `TCP 租约`。

1. `共享 key`：第一台机器可清空后回车生成；复制同一个 key 到安装机、中转机或发送端。
2. `默认租约时长`：通常填 `3d`。
3. `临时放行路由`：按 `a`，按向导填写 `default`、`3d`、IPv4 `24`、IPv6 `128`；来源限制留空即可。需要限制谁能使用该路由时，在最后一步填 IP/CIDR。

## 无中转机直接发送

1. 安装机：`监听` 填 `0.0.0.0:19082`。
2. 安装机：进入 `公网 token 触发器 / 连接来源` -> `允许发送租约到本机`，添加发送端 IP/CIDR。
3. 安装机：回到 `状态 / 应用`，确认管理 SSH 在 `防护` -> `公开端口` 后，选 `应用并确认当前设置`。本机服务填监听端口；DNAT/forward 入口填公网原始入口端口，不填后端端口。
4. 发送端：执行：

```bash
nwall lease send --target <安装机IP>:19082 --route default --source-ip <发送端IP> --mask 24 --lease-key "$LEASE_KEY"
```

`--mask 24` 放行来源所在 `/24`，`--mask 32` 只放行单 IP。

## 无中转机提供公网 token

1. 安装机：`监听` 填 `127.0.0.1:19082`。
2. 安装机：进入 `公网 token 触发器 / 连接来源`，`监听` 填 `127.0.0.1:19081`。
3. 安装机：`反代真实 IP 来源` 添加 `127.0.0.1,::1`。
4. 安装机：`token 路由` 按向导填写 `<token>`、`default`、`127.0.0.1:19082`、`3d`、`24`、`128`。
5. nginx/Caddy 把 `https://example.com/<token>` 反代到 `127.0.0.1:19081`，并传递真实客户端 IP。
6. 回到 `状态 / 应用`，选 `应用并确认当前设置`。

## 有中转机提供公网 token

安装机：

1. `监听` 填 `0.0.0.0:19082`。
2. `公网 token 触发器 / 连接来源` -> `允许发送租约到本机` 添加中转机连接安装机时的出口 IP/CIDR。
3. 回到 `状态 / 应用`，选 `应用并确认当前设置`。

中转机：

1. `共享 key` 粘贴同一个 key。
2. `公网 token 触发器 / 连接来源` -> `监听` 填 `127.0.0.1:19081`。
3. `反代真实 IP 来源` 添加 `127.0.0.1,::1`。
4. `token 路由` 按向导填写 `<token>`、`default`、`<安装机IP:19082>`、`3d`、`24`、`128`。
5. nginx/Caddy 把公网路径反代到 `127.0.0.1:19081`。
6. 保存后执行 `nwall reload`。

## 验证

```bash
curl -sk https://example.com/<token>
curl -sk 'https://example.com/<token>?mask=32'
nwall status
nft list set inet nwall lease4_24
nft list set inet nwall lease4_32
```

token 访问应返回 `ok=true` 和 `lease_cidr`。IPv4 `/24` 会写入对应的网络地址 key，例如 `lease4_24` 中的 `203.0.113.0 timeout 3d`，不会展开成 256 个 host 元素；命中流量会刷新租约 timeout。
