# 公网小助手 · fnOS

把飞牛 NAS 上的服务发布到公网。四步向导完成：连服务器 → 域名证书 → 选端口 → 部署。

家宽没有公网 IP 也能用：NAS 端 `frpc` 主动连出，公网服务器上 `frps` 接住，再由 `nginx` 按端口反向代理，可选自动签发 Let's Encrypt 证书。

<p align="center">
  <a href="https://github.com/tv1314/pubhelper/releases/latest">
    <img alt="下载最新版本" src="https://img.shields.io/badge/%E4%B8%8B%E8%BD%BD%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC-fnOS%20%E5%AE%89%E8%A3%85%E5%8C%85-4c8dff?style=for-the-badge&logo=github&logoColor=white">
  </a>
</p>

<p align="center">
  <a href="https://github.com/tv1314/pubhelper/releases"><img alt="release" src="https://img.shields.io/github/v/release/tv1314/pubhelper?style=flat-square&label=release&color=4c8dff"></a>
  <img alt="downloads" src="https://img.shields.io/github/downloads/tv1314/pubhelper/total?style=flat-square&color=3ecf8e">
  <img alt="platform" src="https://img.shields.io/badge/platform-fnOS%201.2%2B-4c8dff?style=flat-square">
  <img alt="license" src="https://img.shields.io/github/license/tv1314/pubhelper?style=flat-square&color=ffb020">
</p>

## 它是怎么工作的

```
浏览器
  │  https://你的域名:8096
  ▼
公网服务器 nginx   ← 按端口生成 server 块（TLS 在本机终止）
  │  http(s)://127.0.0.1:18000
  ▼
frps（公网）  ←→  隧道  ←→  frpc（NAS）
                                │  http://127.0.0.1:8096
                                ▼
                          你的实际服务
```

- 隧道端口只绑定 `127.0.0.1`，公网无法直连，必须经 nginx
- frpc 由 systemd 托管（`Restart=always`），被 kill 后自动拉起
- 部署前会自动探测每个源站是 HTTP 还是 HTTPS，决定回源协议

## 功能

| 能力 | 说明 |
|---|---|
| 四步向导 | 连接服务器 → 域名与证书 → 端口配置 → 部署与状态 |
| 端口扫描 | 自动列出本机监听端口，标注用途与风险等级，可手动添加任意端口 |
| 反向隧道 | frp token 随机生成，控制端口自动分配并固化 |
| 端口反代 | 按勾选端口生成 nginx 站点，支持 WebSocket、大文件上传 |
| HTTPS | 域名填了即可自动签发证书，签完自动改用 HTTPS |
| 状态监控 | 隧道状态、运行时长、各端口可达性与延迟 |
| 启停控制 | 启动 / 重启 / 停止隧道，一键移除全部部署 |
| 增量变更 | 改端口后用「应用变更」走精简流程，不重装、不重签 |

## 安装

1. 到 [Releases](https://github.com/tv1314/pubhelper/releases/latest) 下载 `pubhelper.fpk`
2. 应用中心 → 手动安装 → 选择该文件
3. 桌面出现「公网小助手」图标

要求：fnOS 1.2.0+，x86_64。

## 从源码构建

在 NAS 上执行（需要 `fnpack`）：

```bash
cd pubhelper
rm -rf app/server/__pycache__
rm -f pubhelper.fpk
fnpack build
```

产物：`pubhelper.fpk`

`app/server/bundle/` 已内置 `frp_0.52.3_linux_amd64.tar.gz`（11 MB，来自
[frp 官方 release](https://github.com/fatedier/frp/releases)，未做任何修改），
clone 后可直接构建，不需要联网。

内置包的作用是让部署过程完全离线：NAS 与公网服务器都从本地取二进制，
避开 GitHub 在国内经常连不上的问题。

## 目录结构

```
pubhelper/
├── manifest              应用元数据
├── cmd/                  生命周期脚本（install/config/upgrade/uninstall + main 守护）
├── config/               privilege（以 root 运行，需读系统信息）
├── app/
│   ├── server/           后端（Python 标准库，无第三方依赖）
│   │   ├── server.py     网关 HTTP 服务 + 业务接口
│   │   ├── deploy.py     部署编排（frps/frpc/nginx/证书）
│   │   ├── sshx.py       SSH 执行封装
│   │   └── bundle/       内置依赖（frp、acme.sh）
│   ├── www/              前端（原生 JS，无构建步骤）
│   └── ui/               桌面入口与图标
└── ICON.PNG  ICON_256.PNG
```

## 技术要点

- 后端监听 **Unix socket**，由飞牛统一网关转发并注入登录身份（`X-Trim-Userid`），不占 TCP 端口
- 未登录访问 `/api/*` 返回 401
- 所有远端操作都有超时与失败回滚，`nginx -t` 不过会自动撤销本次写入
- 部署是幂等的，失败可直接重试

## 许可

MIT
