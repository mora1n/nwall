# TCP 租约 TUI 部署指南

TCP 租约用于把来源 IP 临时写入 nftables 动态集合，适合临时放行入站或 DNAT/forward 入口。共享 key 用于 TCP 租约签名，URL token 只是公网路径令牌，两者不要混用。

运行 `nwall`，进入 `TCP 租约`。共享 key 可以在第一台机器留空回车生成，界面会显示生成值；复制同一个 key 到其他安装机或中转机。

## 常用输入格式

- `临时放行路由` 按 `a` 新增：`default 3d 24 128`
- 需要限制来源时：`default 3d 24 128 203.0.113.0/24`
- `token 路由` 按 `a` 新增：`<token> default <安装机TCP地址> 3d 24 128`
- `可信 relay` 填允许连接安装机 TCP 租约服务端的发送端或中转机 IP/CIDR
- `可信反代` 通常填本机反代来源：`127.0.0.1,::1`

## 无中转机直接发送租约

1. 安装机：`TCP 租约` -> `监听` 填 `0.0.0.0:19082`。
2. 安装机：`共享 key` 生成或粘贴同一个 key。
3. 安装机：`可信 relay` 按 `a` 添加发送端 IP/CIDR。
4. 安装机：`临时放行路由` 按 `a` 添加 `default 3d 24 128`。
5. 安装机：回到 `状态 / 应用`，确认 SSH 管理端口仍在 `防护` -> `公开端口` 后，选 `应用并确认当前设置`。
6. 发送端：用 `nwall lease send` 发送租约；`--mask 24` 放行来源 C 段，`--mask 32` 只放行单 IP。

示例：

```bash
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 24 --lease-key "$LEASE_KEY"
nwall lease send --target 192.0.2.10:19082 --route default --source-ip 203.0.113.9 --mask 32 --lease-key "$LEASE_KEY"
```

## 无中转机提供公网 token 触发器

1. 安装机：`TCP 租约` -> `监听` 填 `127.0.0.1:19082`，配置共享 key 和 `default 3d 24 128` 临时放行路由。
2. 安装机：进入 `token 触发器`，`监听` 填 `127.0.0.1:19081`。
3. 安装机：`可信反代` 添加 `127.0.0.1,::1`。
4. 安装机：`token 路由` 添加 `<token> default 127.0.0.1:19082 3d 24 128`。
5. 外层 nginx/Caddy 把 `https://example.com/<token>` 反代到 `127.0.0.1:19081`。
6. 回到 `状态 / 应用`，应用并确认当前设置。

## 有中转机提供公网 token 触发器

1. 安装机：`TCP 租约` -> `监听` 填 `0.0.0.0:19082`，配置共享 key。
2. 安装机：`可信 relay` 添加中转机 IP/CIDR，`临时放行路由` 添加 `default 3d 24 128`。
3. 中转机：`TCP 租约` -> `共享 key` 粘贴同一个 key。
4. 中转机：进入 `token 触发器`，`监听` 填 `127.0.0.1:19081`，`可信反代` 添加 `127.0.0.1,::1`。
5. 中转机：`token 路由` 添加 `<token> default <安装机IP:19082> 3d 24 128`。
6. 中转机外层 nginx/Caddy 把公网路径反代到 `127.0.0.1:19081`。
7. 安装机回到 `状态 / 应用`，应用并确认当前设置；中转机保存配置后退出 TUI，执行 `nwall reload`。

远程机器如果要先带回滚测试，先选 `状态 / 应用` -> `应用当前设置`，再执行 `nwall reload` 启动或重启 TCP 租约组件；验证通过后回到 TUI 选 `应用并确认当前设置`。

## 验证

```bash
curl -sk https://example.com/<token>
curl -sk 'https://example.com/<token>?mask=32'
nwall status
nft list set inet nwall lease4
```

token 访问应返回 `ok=true` 和 `lease_cidr`。IPv4 `/24` 会展开成多个 host 元素写入 `lease4`，因此 nft 输出里通常看到具体 IP，而不是一条 `/24` 前缀。
