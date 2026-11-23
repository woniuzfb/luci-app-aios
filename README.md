# luci-app-aios

面向 OpenWrt 的 **Xray-core & V2Ray (v2fly)** 双核统一代理控制台。

## 核心特性

- **双核一等支持**：同一配置模型通过分离式能力矩阵自动编译为 **Xray-core**（支持 `streamSettings.method` / 扁平出站 / `users` 入站 / REALITY / XHTTP / FinalMask / Hysteria / MASQUE / VLESS Encryption / WireGuard / TUN / Metrics）、**V2Ray `jsonv4`**（支持 Hysteria2 / `vnext`/`servers` / `services.tun` / `services.burstObservatory`）或 **V2Ray `jsonv5`**（支持 `router` / `services.*` / `dns.fakeDns` / Shadowsocks 2022 / Hysteria2 / uTLS / HTTPUpgrade），并在前端与 ucode 双端执行 Fail-Fast 组合校验。
- **兼容新旧 OpenWrt**：
  - OpenWrt 22.03+：`firewall4 (nftables)` 独立表 `table inet aios` + `ucode` 编译引擎 + Dynamic Direct + FakeDNS Ping + 动态默认网关/IPv6 PD 绕过。
  - OpenWrt 19.07 / 21.02 / LEDE：`firewall3 (iptables + ipset)` 独立 `AIOS_*` 链与 `aios_*` 集合 + 前端预编译 JSON 兜底（无 `ucode` 也可运行）。
- **全维度防冲突隔离**：统一使用 `/etc/config/aios`、独立 `procd` PID 与高冲突规避路由表/fwmark（默认 `table 166`、`0x3a01`–`0x3a04`），内置启动前共存插件冲突预检。
- **全手动自由拼装 + 预设快捷键**：完整手动配置任意 `inbounds` / `outbounds` / `dns` / `fakedns` / `routing` / `balancers` / `observatory` / `policy` / `reverse`，内置推荐预设，并支持**将当前完整设置一键保存为自定义预设**（含应用前 Diff 预览与 JSON 导入/导出）。
- **Vite + TypeScript + Vue 3 独立后台**：产物部署至 `/www/aios/`（由 `uhttpd` 直接托管，零常驻内存），通过 `/ubus` + `rpcd/luci.aios` 通信，并在 LuCI 菜单提供轻量入口壳。

## 本地开发与验证

```bash
cd web
pnpm install
pnpm test    # 运行双核编译、预设保存与链接导入单元测试
pnpm build   # 类型检查并构建静态产物到 packages/luci-app-aios/root/www/aios/
pnpm dev     # 启动本地预览（可设置 AIOS_ROUTER_URL=http://<router-ip> 代理 /ubus）
```

## 包结构

- `packages/luci-app-aios`：单包交付（`PKGARCH:=all`），内置 `init.d/aios`、`rpcd/luci.aios`、双防火墙后端、`ucode` 编译器、完整 ACL 权限、LuCI 入口壳与 Vite 独立后台产物。
