#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公网小助手 - fnOS app backend (stdlib only).

P0 能力：
  - 配置读写（密码用 openssl AES-256 加密落盘，不存明文）
  - 扫本机真实监听端口（ss -lntup），并匹配服务名/风险等级
  - 测试公网服务器 SSH 连通性，回显发行版/架构/已占用端口/防火墙
"""

import argparse
import base64
import concurrent.futures
import json
import os
import re
import socket
import socketserver
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import deploy
import sshx

APP_VERSION = "0.2.0"
APP_NAME = "公网小助手"

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WWW_DIR = os.path.join(APP_DIR, "www")

PREFIX = ""
REQUIRE_AUTH = True
GATEWAY_USER_HEADERS = ("X-Trim-Userid", "Trim-Userid", "X-Trim-Username")

STORE = None
LOCK = threading.Lock()
DEPLOYER = None

# 进程启动时刻：用于识别「代码已被替换但还没重启」
BOOT_TIME = time.time()


def code_stale():
    """健康检查：代码文件是否比进程还新（热更新未生效）。"""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        for f in ("server.py", "deploy.py", "sshx.py"):
            p = os.path.join(here, f)
            if os.path.isfile(p) and os.path.getmtime(p) > BOOT_TIME + 1:
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------- 端口预设库
# level: ok=建议发布 / care=谨慎 / block=禁止 / unknown=未识别
PORT_PRESETS = [
    {"port": 80, "proto": "tcp", "name": "Web 80（服务器自用）", "level": "block", "on": False},
    {"port": 443, "proto": "tcp", "name": "Web 443（服务器自用）", "level": "block", "on": False},
    {"port": 7000, "proto": "tcp", "name": "frp 控制端口（服务器自用）", "level": "block", "on": False},
    {"port": 8096, "proto": "tcp", "name": "飞牛影视 / Jellyfin", "level": "ok", "on": False},
    {"port": 8920, "proto": "tcp", "name": "飞牛影视 / Jellyfin HTTPS", "level": "care", "on": False},
    {"port": 5244, "proto": "tcp", "name": "OpenList / AList", "level": "ok", "on": False},
    {"port": 8023, "proto": "tcp", "name": "tao-sync 同步", "level": "ok", "on": False},
    {"port": 5005, "proto": "tcp", "name": "WebDAV (HTTP)", "level": "ok", "on": False},
    {"port": 5006, "proto": "tcp", "name": "WebDAV (HTTPS)", "level": "care", "on": False},
    {"port": 8200, "proto": "tcp", "name": "DLNA 媒体服务", "level": "ok", "on": False},
    {"port": 32400, "proto": "tcp", "name": "Plex", "level": "ok", "on": False},
    {"port": 8123, "proto": "tcp", "name": "Home Assistant", "level": "ok", "on": False},
    {"port": 5700, "proto": "tcp", "name": "青龙面板", "level": "ok", "on": False},
    {"port": 9000, "proto": "tcp", "name": "Portainer", "level": "ok", "on": False},
    {"port": 8080, "proto": "tcp", "name": "qBittorrent WebUI", "level": "ok", "on": False},
    {"port": 9091, "proto": "tcp", "name": "Transmission WebUI", "level": "ok", "on": False},
    {"port": 6881, "proto": "tcp", "name": "BT 端口 (TCP)", "level": "ok", "on": False},
    {"port": 6881, "proto": "udp", "name": "BT 端口 (UDP)", "level": "ok", "on": False},
    {"port": 51413, "proto": "tcp", "name": "Transmission BT", "level": "ok", "on": False},
    {"port": 51413, "proto": "udp", "name": "Transmission BT (UDP)", "level": "ok", "on": False},
    {"port": 5666, "proto": "tcp", "name": "飞牛管理后台 (HTTP)", "level": "care", "on": False},
    {"port": 5667, "proto": "tcp", "name": "飞牛管理后台 (HTTPS)", "level": "care", "on": False},
    {"port": 22, "proto": "tcp", "name": "SSH", "level": "care", "on": False},
    {"port": 8005, "proto": "tcp", "name": "飞牛影视后端（内部）", "level": "block", "on": False},
    {"port": 9876, "proto": "tcp", "name": "ddns-go（内部工具）", "level": "block", "on": False},
    {"port": 2019, "proto": "tcp", "name": "Clash 面板 zashboard", "level": "block", "on": False},
    {"port": 9090, "proto": "tcp", "name": "Clash 面板", "level": "block", "on": False},
    {"port": 9990, "proto": "tcp", "name": "fndesk（内部）", "level": "block", "on": False},
    {"port": 445, "proto": "tcp", "name": "SMB 文件共享", "level": "block", "on": False},
    {"port": 139, "proto": "tcp", "name": "SMB / NetBIOS", "level": "block", "on": False},
    {"port": 111, "proto": "tcp", "name": "rpcbind", "level": "block", "on": False},
    {"port": 2049, "proto": "tcp", "name": "NFS", "level": "block", "on": False},
    {"port": 2375, "proto": "tcp", "name": "Docker API（明文）", "level": "block", "on": False},
    {"port": 2376, "proto": "tcp", "name": "Docker API", "level": "block", "on": False},
    {"port": 5432, "proto": "tcp", "name": "PostgreSQL（内部）", "level": "block", "on": False},
    {"port": 5672, "proto": "tcp", "name": "RabbitMQ（内部）", "level": "block", "on": False},
    {"port": 4369, "proto": "tcp", "name": "Erlang epmd（内部）", "level": "block", "on": False},
    {"port": 25672, "proto": "tcp", "name": "RabbitMQ 集群（内部）", "level": "block", "on": False},
    {"port": 1900, "proto": "udp", "name": "DLNA 发现", "level": "block", "on": False},
    {"port": 5353, "proto": "udp", "name": "mDNS", "level": "block", "on": False},
]

PRESET_MAP = {}
for _p in PORT_PRESETS:
    PRESET_MAP[(_p["port"], _p["proto"])] = _p

LEVEL_ORDER = {"ok": 0, "care": 1, "unknown": 2, "block": 3}


# ---------------------------------------------------------------- 默认配置
DEFAULT_CFG = {
    "cfg_version": 1,
    "vps": {
        "host": "",
        "port": 22,
        "user": "root",
        "auth": "password",
        "password": "",
        "keyfile": "",
        "family": "auto",
    },
    "domain": "",
    "email": "",
    "use_https": False,
    "mode": "port",
    "services": [],
    "frp_port": 7000,
    "direct_expose": True,
    "basic_auth": False,
    "basic_user": "nas",
    "basic_pass": "",
    "tunnel_token": "",
    "installed": False,
    "last_test": None,
    "last_deploy": None,
}


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    """打到 stdout，被 cmd/main 收进 info.log，方便事后定位。"""
    try:
        print("[%s] %s" % (now(), msg), flush=True)
    except Exception:
        pass


def deep_copy(obj):
    return json.loads(json.dumps(obj))


def norm_cfg(raw):
    c = deep_copy(DEFAULT_CFG)
    if not isinstance(raw, dict):
        return c
    for k, v in raw.items():
        if isinstance(v, dict) and isinstance(c.get(k), dict):
            c[k].update(v)
        else:
            c[k] = v
    vps = c.get("vps") or {}
    try:
        vps["port"] = int(vps.get("port") or 22)
    except Exception:
        vps["port"] = 22
    if vps.get("family") not in ("auto", "ipv4", "ipv6"):
        vps["family"] = "auto"
    if vps.get("auth") not in ("password", "key"):
        vps["auth"] = "password"
    if not isinstance(c.get("services"), list):
        c["services"] = []
    return c


# ---------------------------------------------------------------- 配置存储
class Store(object):
    def __init__(self, data_dir, conf_dir):
        self.data = data_dir
        self.conf = conf_dir
        for d in (self.data, self.conf):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception:
                pass
        self.path = os.path.join(self.conf, "config.json")
        self.cfg = self.load()
        self._pw_cache = None

    # ---- 加解密（openssl 可用则真加密，否则退化为编码，并在接口里告警） ----
    def _keyfile(self):
        p = os.path.join(self.conf, ".seal.key")
        if not os.path.exists(p):
            raw = base64.b16encode(os.urandom(32)).decode().lower()
            with open(p, "w", encoding="utf-8") as f:
                f.write(raw + "\n")
            try:
                os.chmod(p, 0o600)
            except Exception:
                pass
        return p

    def seal(self, text):
        if not text:
            return ""
        try:
            r = subprocess.run(
                ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-a", "-A",
                 "-pass", "file:" + self._keyfile()],
                input=text.encode("utf-8"), capture_output=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                return "s1:" + r.stdout.decode("utf-8").strip()
        except Exception:
            pass
        return "p1:" + base64.b64encode(text.encode("utf-8")).decode("ascii")

    def unseal(self, blob):
        if not blob:
            return ""
        try:
            if blob.startswith("s1:"):
                r = subprocess.run(
                    ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-a", "-A",
                     "-pass", "file:" + self._keyfile()],
                    input=blob[3:].encode("utf-8"), capture_output=True, timeout=15)
                if r.returncode == 0:
                    return r.stdout.decode("utf-8")
                return ""
            if blob.startswith("p1:"):
                return base64.b64decode(blob[3:]).decode("utf-8")
        except Exception:
            return ""
        return ""

    # ---- 读写 ----
    def load(self):
        raw = {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f) or {}
        except Exception:
            raw = {}
        sealed = (raw.get("vps") or {}).get("password_sealed") or ""
        cfg = norm_cfg(raw)
        cfg["vps"]["password"] = ""
        cfg["vps"]["password_sealed"] = sealed
        return cfg

    def save(self):
        c = deep_copy(self.cfg)
        c["vps"]["password"] = ""
        body = json.dumps(c, ensure_ascii=False, indent=2)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(body + "\n")
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, self.path)

    # ---- 密码 ----
    def get_password(self):
        if self._pw_cache is not None:
            return self._pw_cache
        self._pw_cache = self.unseal(self.cfg["vps"].get("password_sealed") or "")
        return self._pw_cache

    def set_password(self, pw):
        self._pw_cache = pw or ""
        if pw:
            self.cfg["vps"]["password_sealed"] = self.seal(pw)
        else:
            self.cfg["vps"]["password_sealed"] = ""

    def sealed_ok(self):
        return (self.cfg["vps"].get("password_sealed") or "").startswith("s1:")

    def public_cfg(self):
        c = deep_copy(self.cfg)
        vps = c.setdefault("vps", {})
        sealed = vps.pop("password_sealed", "") or ""
        vps["password"] = ""
        vps["password_set"] = bool(sealed)
        c["crypto"] = "aes" if sealed.startswith("s1:") else ("plain" if sealed else "none")
        c["version"] = APP_VERSION
        c["name"] = APP_NAME
        return c


# ---------------------------------------------------------------- 本机环境
def run_local(argv, timeout=8):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        return None
    return None


def local_addrs():
    info = {"hostname": "", "ipv4": [], "ipv6": [], "model": ""}
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        pass
    out = run_local(["ip", "-o", "addr", "show", "scope", "global"])
    if out:
        for line in out.splitlines():
            m = re.search(r"\binet6?\s+([0-9a-fA-F:.]+)/", line)
            if not m:
                continue
            addr = m.group(1).split("%")[0]
            if ":" in addr:
                if addr not in info["ipv6"]:
                    info["ipv6"].append(addr)
            elif addr not in info["ipv4"]:
                info["ipv4"].append(addr)
    try:
        with open("/sys/class/dmi/id/product_name", "r", encoding="utf-8") as f:
            info["model"] = f.read().strip()
    except Exception:
        pass
    return info


def _parse_ss(out, proto):
    res = {}
    if not out:
        return res
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        local = parts[3]
        rest = parts[4] if len(parts) > 4 else ""
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        port = int(m.group(1))
        bind = local[:m.start()]
        proc = ""
        pm = re.search(r'\(\("([^"]+)"', rest)
        if pm:
            proc = pm.group(1)
        key = (port, proto)
        pub = bind in ("0.0.0.0", "*", "[::]", "")
        item = res.get(key)
        if item is None:
            res[key] = {"port": port, "proto": proto, "bind": [bind],
                        "proc": [proc] if proc else [], "public": pub}
        else:
            if bind not in item["bind"]:
                item["bind"].append(bind)
            if proc and proc not in item["proc"]:
                item["proc"].append(proc)
            item["public"] = item["public"] or pub
    return res


def scan_ports():
    found = {}
    for proto, argv in (("tcp", ["ss", "-lntp", "-H"]),
                        ("udp", ["ss", "-lnup", "-H"])):
        out = run_local(argv)
        if out is None:
            if proto == "tcp":
                out = run_local(["netstat", "-lntp"]) or ""
            else:
                out = ""
        found.update(_parse_ss(out, proto))
    return found


_PORTS_CACHE = {"at": 0.0, "data": None}
_PORTS_CACHE_TTL = 20.0


def cached_ports(force=False):
    """端口扫描带 20 秒缓存：打开页面时不必重复扫，也避免协议探测反复握手。"""
    now_ts = time.time()
    if (not force and _PORTS_CACHE["data"] is not None
            and now_ts - _PORTS_CACHE["at"] < _PORTS_CACHE_TTL):
        return _PORTS_CACHE["data"]
    data = build_ports()
    _PORTS_CACHE["at"] = time.time()
    _PORTS_CACHE["data"] = data
    return data


def build_ports():
    """只返回「认得出 + 允许发布」的端口。

    未识别和禁止发布的一律不出现在列表里，避免干扰；
    需要发布这些端口时用界面上的「手动添加」，并自行填写服务名。
    """
    found = scan_ports()
    items = []
    for (port, proto), v in found.items():
        pre = PRESET_MAP.get((port, proto))
        if not pre:
            continue                      # 未识别：不显示
        if pre.get("level") == "block":
            continue                      # 禁止：不显示
        # 等级按端口号划分：100 以下属系统保留端口 → 谨慎；100 及以上 → 推荐
        lvl = "care" if port < 100 else "ok"
        items.append({
            "port": port,
            "proto": proto,
            "bind": ",".join(sorted(x for x in set(v["bind"]) if x)),
            "public": bool(v["public"]),
            "proc": ", ".join(sorted(set(v["proc"]))[:3]),
            "name": pre.get("name") or "",
            "level": lvl,
            "on": bool(pre.get("on")),
            "known": True,
        })
    # 探测每个 HTTP 类端口说的是 http 还是 https，供部署时决定回源协议
    tcp = [i for i in items if i["proto"] == "tcp"]
    if tcp:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(tcp))) as ex:
                fut = {ex.submit(deploy.detect_scheme, i["port"], 1.2): i for i in tcp}
                for f in concurrent.futures.as_completed(fut, timeout=10):
                    it = fut[f]
                    try:
                        it["scheme"] = f.result()
                    except Exception:
                        it["scheme"] = "unknown"
        except Exception:
            pass
    for i in items:
        i.setdefault("scheme", "" if i["proto"] == "udp" else "unknown")

    items.sort(key=lambda x: (LEVEL_ORDER.get(x["level"], 2), x["port"]))
    return items


# ---------------------------------------------------------------- VPS 探测
PROBE_SCRIPT = r'''
set +e
echo "@@@OS"
cat /etc/os-release 2>/dev/null
echo "@@@ARCH"
uname -m
echo "@@@UID"
id -u
echo "@@@WHO"
whoami
echo "@@@HOST"
hostname
echo "@@@BIN"
for b in sudo systemctl nginx docker ss curl tar base64 openssl ufw firewall-cmd getenforce; do
  p=$(command -v $b 2>/dev/null)
  echo "$b=$p"
done
echo "@@@NGINXVER"
command -v nginx >/dev/null 2>&1 && nginx -v 2>&1
echo "@@@PORTS"
ss -lntH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -n -u
echo "@@@UDPS"
ss -lnuH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -n -u
echo "@@@FW"
(ufw status 2>/dev/null) | head -4
(firewall-cmd --state 2>/dev/null)
echo "@@@SELINUX"
(getenforce 2>/dev/null) || echo Disabled
echo "@@@DISK"
df -h / 2>/dev/null | tail -1
echo "@@@MEM"
free -m 2>/dev/null | sed -n '2p'
echo "@@@DONE"
'''


def _sections(out):
    sec = {}
    cur = None
    for line in out.splitlines():
        if line.startswith("@@@"):
            cur = line[3:].strip()
            sec.setdefault(cur, [])
        elif cur:
            sec[cur].append(line)
    return dict((k, "\n".join(v).strip()) for k, v in sec.items())


def _kv_lines(text):
    d = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    return d


def _os_family(osid, version):
    osid = (osid or "").lower()
    if osid in ("ubuntu", "debian", "linuxmint", "raspbian"):
        return "apt"
    if osid in ("centos", "rhel", "rocky", "almalinux", "fedora",
                "openeuler", "anolis", "kylin", "tencentos"):
        if osid == "centos" and str(version).startswith("7"):
            return "yum7"
        return "dnf"
    return "unknown"


def probe_vps(cfg, password):
    vps = cfg.get("vps") or {}
    ssh = sshx.SSH(host=vps.get("host"), port=vps.get("port") or 22,
                   user=vps.get("user") or "root", password=password,
                   keyfile=vps.get("keyfile") or "",
                   family=vps.get("family") or "auto",
                   workdir=os.path.join(STORE.data, "ssh"),
                   timeout=45)
    try:
        ssh.ping()
        sudo = False
        out = ssh.run_ok(PROBE_SCRIPT, sudo=False, timeout=45)
        sec = _sections(out)
        uid = 0
        try:
            uid = int((sec.get("UID") or "0").strip().splitlines()[0])
        except Exception:
            uid = -1
        osrel = _kv_lines(sec.get("OS"))
        osid = osrel.get("ID", "").strip().strip('"')
        ver = osrel.get("VERSION_ID", "").strip().strip('"')
        pretty = osrel.get("PRETTY_NAME", "").strip().strip('"')
        bins = _kv_lines(sec.get("BIN"))
        ports = []
        for tok in (sec.get("PORTS") or "").split():
            if tok.isdigit():
                ports.append(int(tok))
        udp = []
        for tok in (sec.get("UDPS") or "").split():
            if tok.isdigit():
                udp.append(int(tok))
        res = {
            "host": vps.get("host"),
            "port": vps.get("port") or 22,
            "user": vps.get("user") or "root",
            "hostname": (sec.get("HOST") or "").strip(),
            "arch": (sec.get("ARCH") or "").strip(),
            "uid": uid,
            "is_root": uid == 0,
            "os_id": osid,
            "os_name": pretty or osid,
            "os_version": ver,
            "pkg": _os_family(osid, ver),
            "has": dict((k, bool(v)) for k, v in bins.items()),
            "nginx_version": (sec.get("NGINXVER") or "").strip(),
            "used_tcp": ports,
            "used_udp": udp,
            "firewall": (sec.get("FW") or "").strip(),
            "selinux": (sec.get("SELINUX") or "").strip(),
            "disk": (sec.get("DISK") or "").strip(),
            "mem": (sec.get("MEM") or "").strip().replace("\n", " / "),
            "warns": [],
            "at": now(),
        }
        w = res["warns"]
        if not res["is_root"]:
            if bins.get("sudo"):
                res["sudo"] = True
            else:
                res["sudo"] = False
                w.append("当前账号不是 root，且服务器上没有 sudo，无法安装 frps/nginx，请换 root 账号")
        else:
            res["sudo"] = True
        if res["pkg"] == "unknown":
            w.append("未识别的发行版（%s），只能尝试通过 Docker 方式部署" % (osid or "unknown"))
        if res["pkg"] == "yum7":
            w.append("CentOS 7 已 EOL，nginx 需要 EPEL 源，脚本会自动处理")
        if bins.get("nginx"):
            w.append("服务器已装 nginx，部署时会复用现有 nginx，不会覆盖你已有的站点配置")
        if 80 in ports or 443 in ports:
            w.append("80/443 已被占用，部署时会复用占用它们的 Web 服务，请确认不会冲突")
        if 7000 in ports:
            w.append("frp 控制端口 7000 已被占用，部署时会自动改用空闲端口")
        if not res["arch"] in ("x86_64", "amd64"):
            w.append("架构为 %s，需要对应架构的 frp 二进制" % res["arch"])
        return res
    finally:
        try:
            ssh.close()
        except Exception:
            pass


# ---------------------------------------------------------------- HTTP
class UnixHTTPServer(ThreadingHTTPServer):
    """绑定 Unix domain socket，仅供飞牛统一网关转发。"""
    address_family = socket.AF_UNIX

    def server_bind(self):
        try:
            if os.path.exists(self.server_address):
                os.unlink(self.server_address)
        except Exception:
            pass
        socketserver.TCPServer.server_bind(self)
        try:
            os.chmod(self.server_address, 0o777)
        except Exception:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "PubHelper/" + APP_VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ---------- 网关 ----------
    def norm_path(self, path):
        p = (PREFIX or "").rstrip("/")
        if p and path.startswith(p):
            path = path[len(p):]
            if not path.startswith("/"):
                path = "/" + path
        return path or "/"

    def gateway_user(self):
        for h in GATEWAY_USER_HEADERS:
            v = (self.headers.get(h) or "").strip()
            if v:
                return v
        return ""

    def need_login(self):
        if not REQUIRE_AUTH:
            return False
        if STORE is not None and not STORE.cfg.get("require_gateway_auth", True):
            return False
        return not self.gateway_user()

    def deny_login(self):
        self.send_json({"ok": False, "need_login": True,
                        "error": "未登录飞牛，请先登录 fnOS"}, 401)

    # ---------- helpers ----------
    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def err(self, msg, code=400):
        self.send_json({"ok": False, "error": msg}, code)

    def body_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8")) or {}
        except Exception:
            return {}

    def q(self):
        u = urllib.parse.urlparse(self.path)
        return self.norm_path(u.path), urllib.parse.parse_qs(u.query)

    # ---------- static ----------
    def serve_static(self, path):
        rel = path.lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(WWW_DIR, rel))
        if not full.startswith(os.path.realpath(WWW_DIR)):
            return self.err("forbidden", 403)
        if not os.path.isfile(full):
            return self.err("not found", 404)
        ctype = {".html": "text/html; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".png": "image/png", ".svg": "image/svg+xml",
                 ".ico": "image/x-icon"}.get(
                     os.path.splitext(full)[1].lower(), "application/octet-stream")
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if getattr(self, "head_only", False):
            return
        self.wfile.write(data)

    # ---------- GET ----------
    def do_GET(self):
        path, qs = self.q()
        try:
            if path.startswith("/api/"):
                if self.need_login():
                    return self.deny_login()
                return self.api_get(path, qs)
            return self.serve_static(path)
        except BrokenPipeError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            try:
                self.err("服务端异常：%s" % e, 500)
            except Exception:
                pass

    def do_HEAD(self):
        self.head_only = True
        try:
            return self.do_GET()
        finally:
            self.head_only = False

    def api_get(self, path, qs):
        if path == "/api/cfg":
            return self.send_json({"ok": True, "cfg": STORE.public_cfg()})
        if path == "/api/ports":
            force = (qs.get("force") or [""])[0] in ("1", "true")
            ports = cached_ports(force=force)
            return self.send_json({"ok": True, "ports": ports,
                                   "local": local_addrs()})
        if path == "/api/status":
            c = STORE.cfg
            return self.send_json({"ok": True, "version": APP_VERSION,
                                   "name": APP_NAME,
                                   "installed": bool(c.get("installed")),
                                   "last_test": c.get("last_test"),
                                   "last_deploy": c.get("last_deploy"),
                                   "need_restart": code_stale(),
                                   "local": local_addrs()})
        if path == "/api/runtime":
            c = STORE.cfg
            # 先算服务地址（内部会顺便把域名解析成 IP 并回写 vps.ip）
            svcs = deploy.service_urls(c)
            vps = c.get("vps") or {}
            if vps.get("ip"):
                with LOCK:
                    if not (STORE.cfg.get("vps") or {}).get("ip"):
                        STORE.cfg["vps"]["ip"] = vps["ip"]
                        STORE.save()
            data = {
                "ok": True,
                "version": APP_VERSION,
                "deployed": bool(c.get("installed")),
                "domain": c.get("domain") or "",
                "host": vps.get("host") or "",
                "ip": vps.get("ip") or "",
                "frp_port": c.get("frp_port") or 0,
                "last_deploy": c.get("last_deploy"),
                "tunnel": deploy.frpc_state(STORE.data),
                "log": deploy.frpc_log_tail(STORE.data, 30),
                "deploying": bool(DEPLOYER and DEPLOYER.running),
                "local": local_addrs(),
                "services": svcs,
                "need_restart": code_stale(),
            }
            if (qs.get("probe") or [""])[0] in ("1", "true"):
                try:
                    data["services"] = deploy.probe_services(c, timeout=5)
                except Exception as e:
                    log("探测服务可达性失败：%s" % e)
            return self.send_json(data)
        if path == "/api/deploy/status":
            if DEPLOYER is None:
                return self.send_json({"ok": True, "running": False, "done": False,
                                       "success": False, "error": "", "steps": [],
                                       "logs": [], "result": {}, "elapsed": 0})
            return self.send_json(DEPLOYER.snapshot())
        return self.err("not found", 404)

    # ---------- POST ----------
    def do_POST(self):
        path, qs = self.q()
        if not path.startswith("/api/"):
            return self.err("not found", 404)
        if self.need_login():
            return self.deny_login()
        try:
            return self.api_post(path, self.body_json())
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self.err("服务端异常：%s" % e, 500)
            except Exception:
                pass

    def api_post(self, path, body):
        if path == "/api/cfg":
            return self.save_cfg(body)
        if path == "/api/ssh/test":
            return self.ssh_test(body)
        if path == "/api/ssh/reset-key":
            return self.ssh_reset_key(body)
        if path == "/api/deploy":
            return self.deploy_start(body, "full")
        if path == "/api/apply":
            return self.deploy_start(body, "reconfigure")
        if path == "/api/tunnel":
            return self.tunnel_ctl(body)
        if path == "/api/deploy/cancel":
            return self.deploy_cancel()
        if path == "/api/deploy/uninstall":
            return self.deploy_uninstall(body)
        return self.err("not found", 404)

    # ---------- 业务 ----------
    def save_cfg(self, body):
        err = self._apply_cfg(body)
        if err:
            return self.err(err)
        return self.send_json({"ok": True, "cfg": STORE.public_cfg()})

    def _apply_cfg(self, body):
        """把前端提交写进配置，返回错误字符串（None 表示成功）。"""
        with LOCK:
            c = STORE.cfg
            vps = body.get("vps") or {}
            old_host = (c["vps"].get("host") or "").strip()
            for k in ("host", "user", "keyfile"):
                if k in vps:
                    c["vps"][k] = (vps.get(k) or "").strip()
            new_host = (c["vps"].get("host") or "").strip()
            if new_host != old_host:
                c["vps"]["ip"] = ""       # 地址变了，旧解析结果作废
                # 换了服务器，之前部署的东西不存在了：状态归零，下次走完整部署
                c["installed"] = False
                c["last_deploy"] = None
                c["tunnel_token"] = ""
                log("服务器地址变更 %s -> %s，部署状态已重置" % (old_host or "(空)", new_host))
            if "port" in vps:
                try:
                    p = int(vps.get("port") or 22)
                except Exception:
                    return "SSH 端口不是合法数字"
                if not (1 <= p <= 65535):
                    return "SSH 端口超出范围"
                c["vps"]["port"] = p
            for k in ("auth", "family"):
                if vps.get(k) in ("password", "key", "auto", "ipv4", "ipv6"):
                    c["vps"][k] = vps[k]
            pw = vps.get("password")
            if isinstance(pw, str) and pw and not vps.get("password_keep"):
                STORE.set_password(pw)

            dom = (body.get("domain") or "").strip()
            if dom and not re.match(r"^[0-9A-Za-z_.\-]+\.[A-Za-z]{2,}$", dom):
                return "域名格式不正确，例如 nas.example.com"
            c["domain"] = dom
            c["email"] = (body.get("email") or "").strip()
            c["use_https"] = bool(body.get("use_https", c.get("use_https", False)))
            if body.get("mode") in ("port", "subdomain"):
                c["mode"] = body["mode"]
            if isinstance(body.get("services"), list):
                svc = []
                for s in body["services"]:
                    if not isinstance(s, dict):
                        continue
                    try:
                        lp = int(s.get("port") or 0)
                        pp = int(s.get("public") or lp)
                    except Exception:
                        continue
                    if not (1 <= lp <= 65535 and 1 <= pp <= 65535):
                        continue
                    svc.append({"port": lp, "public": pp,
                                "proto": "udp" if s.get("proto") == "udp" else "tcp",
                                "name": str(s.get("name") or "")[:64],
                                "on": bool(s.get("on"))})
                c["services"] = svc
            c["direct_expose"] = bool(body.get("direct_expose", c["direct_expose"]))
            # 基础认证已移除：对 fnOS 这类重 XHR 的单页应用不可用，统一关掉
            c["basic_auth"] = False
            c["basic_pass"] = ""
            STORE.save()
        return None

    # ---------- 隧道控制 ----------
    def tunnel_ctl(self, body):
        act = (body.get("action") or "").strip()
        try:
            if act == "start":
                msg = deploy.frpc_start(STORE.data)
            elif act == "stop":
                msg = deploy.frpc_stop(STORE.data)
            elif act == "restart":
                deploy.frpc_stop(STORE.data)
                msg = deploy.frpc_start(STORE.data)
            else:
                return self.err("未知动作：%s" % act)
        except sshx.SSHError as e:
            log("隧道 %s 失败：%s" % (act, e))
            return self.send_json({"ok": False, "error": str(e),
                                   "tunnel": deploy.frpc_state(STORE.data)})
        except Exception as e:
            return self.send_json({"ok": False, "error": "操作失败：%s" % e})
        log("隧道 %s：%s" % (act, msg))
        return self.send_json({"ok": True, "msg": msg,
                               "tunnel": deploy.frpc_state(STORE.data)})

    # ---------- 部署 ----------
    def deploy_start(self, body, mode="full"):
        global DEPLOYER
        err = self._apply_cfg(body or {})
        if err:
            return self.err(err)
        cfg = deep_copy(STORE.cfg)
        cfg["vps"]["password"] = ""
        err = deploy.validate(cfg)
        if err:
            return self.err(err)
        pw = STORE.get_password()
        if not pw and not cfg["vps"].get("keyfile"):
            return self.err("请先填写 SSH 密码，或选择私钥登录")
        with LOCK:
            if DEPLOYER is not None and DEPLOYER.running:
                return self.err("已有部署任务在运行，请先等待或取消")

        def on_finish(snap, dcfg):
            with LOCK:
                try:
                    STORE.cfg["tunnel_token"] = dcfg.get("tunnel_token") or ""
                    iv = (dcfg.get("vps") or {}).get("ip")
                    if iv:
                        STORE.cfg["vps"]["ip"] = iv
                    if dcfg.get("frp_port"):
                        try:
                            STORE.cfg["frp_port"] = int(dcfg["frp_port"])
                        except Exception:
                            pass
                    STORE.cfg["installed"] = bool(snap.get("success"))
                    STORE.cfg["last_deploy"] = {
                        "at": now(),
                        "ok": bool(snap.get("success")),
                        "error": snap.get("error") or "",
                        "urls": (snap.get("result") or {}).get("urls") or [],
                    }
                    STORE.save()
                except Exception as e:
                    log("保存部署结果失败：%s" % e)

        DEPLOYER = deploy.Deployer(cfg, pw, STORE.data, STORE.conf,
                                   on_finish=on_finish, mode=mode)
        DEPLOYER.start()
        log("%s任务已启动 -> %s" % ("部署" if mode == "full" else "重配", cfg["vps"]["host"]))
        return self.send_json({"ok": True, "started": True, "mode": mode})

    def deploy_cancel(self):
        global DEPLOYER
        if DEPLOYER is None or not DEPLOYER.running:
            return self.err("当前没有运行中的部署任务")
        DEPLOYER.cancel()
        return self.send_json({"ok": True})

    def deploy_uninstall(self, body):
        global DEPLOYER
        cfg = deep_copy(STORE.cfg)
        cfg["vps"]["password"] = ""
        pw = STORE.get_password()
        job = deploy.Deployer(cfg, pw, STORE.data, STORE.conf)
        try:
            lines = job.uninstall(purge_cert=bool(body.get("purge_cert")))
        except Exception as e:
            return self.send_json({"ok": False, "error": "清理失败：%s" % e})
        with LOCK:
            STORE.cfg["installed"] = False
            STORE.cfg["last_deploy"] = None
            STORE.cfg["tunnel_token"] = ""
            STORE.save()
        log("清理完成：%s" % "；".join(lines))
        return self.send_json({"ok": True, "lines": lines})

    def ssh_reset_key(self, body):
        """清掉旧的主机指纹（服务器重装 / 换机器后必须走这一步）。"""
        host = (body.get("host") or STORE.cfg["vps"].get("host") or "").strip()
        port = body.get("port") or STORE.cfg["vps"].get("port") or 22
        if not host:
            return self.err("请先填写服务器地址")
        wd = os.path.join(STORE.data, "ssh")
        changed, n = sshx.forget_host(wd, host, port)
        log("清除主机指纹 %s:%s -> 改动=%s 条目=%d" % (host, port, changed, n))
        if changed:
            return self.send_json({"ok": True,
                                   "msg": "已清除 %s 的旧指纹（%d 条），可以重新连接" % (host, n)})
        return self.send_json({"ok": True, "msg": "没有找到可清除的旧指纹记录，直接重连即可"})

    def ssh_test(self, body):
        with LOCK:
            cfg = {
                "vps": {
                    "host": (body.get("host") or STORE.cfg["vps"].get("host") or "").strip(),
                    "port": body.get("port") or STORE.cfg["vps"].get("port") or 22,
                    "user": (body.get("user") or STORE.cfg["vps"].get("user") or "root").strip(),
                    "keyfile": (body.get("keyfile") or STORE.cfg["vps"].get("keyfile") or "").strip(),
                    "family": body.get("family") or STORE.cfg["vps"].get("family") or "auto",
                }
            }
            pw = body.get("password")
            if not isinstance(pw, str) or not pw:
                pw = STORE.get_password()
            if not cfg["vps"]["host"]:
                return self.err("请先填写服务器地址")
            if not pw and not cfg["vps"]["keyfile"]:
                return self.err("请填写 SSH 密码，或选择私钥登录")
        host = cfg["vps"]["host"]
        port = cfg["vps"]["port"]
        fam = cfg["vps"]["family"]
        # 先做纯 TCP 拨号：把 DNS / 路由 / 端口 三层问题分清楚，不笼统报超时
        try:
            d = sshx.dial(host, port, fam, timeout=6)
        except sshx.SSHError as e:
            log("ssh_test FAIL(tcp) %s:%s family=%s -> %s" % (host, port, fam, e))
            return self.send_json({"ok": False, "stage": "tcp", "error": str(e)})
        log("ssh_test tcp ok %s:%s -> %s %sms" % (host, port, d.get("ip"), d.get("ms")))
        try:
            res = probe_vps(cfg, pw)
        except sshx.SSHError as e:
            log("ssh_test FAIL(ssh) %s:%s -> %s" % (host, port, e))
            msg = str(e)
            # 指纹不一致是「换了机器」，不是攻击，给前端一个显式的重置入口
            return self.send_json({"ok": False, "stage": "ssh", "error": msg,
                                   "dial": d, "need_reset": "指纹" in msg})
        except Exception as e:
            log("ssh_test FAIL(other) %s:%s -> %s" % (host, port, e))
            return self.send_json({"ok": False, "stage": "probe",
                                   "error": "探测失败：%s" % e, "dial": d})
        res["dial"] = d
        with LOCK:
            if d.get("ip"):
                STORE.cfg["vps"]["ip"] = d["ip"]   # 记住解析结果，供访问地址使用
            STORE.cfg["last_test"] = {"ok": True, "at": now(),
                                      "host": res.get("host"),
                                      "ip": d.get("ip"),
                                      "os": res.get("os_name")}
            STORE.save()
        return self.send_json({"ok": True, "probe": res})


# ---------------------------------------------------------------- main
def main():
    global STORE, PREFIX, REQUIRE_AUTH
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", default="", help="Unix socket 路径（统一网关模式）")
    ap.add_argument("--prefix", default=os.environ.get("FNNAS_GATEWAY_PREFIX", "/app/pubhelper"))
    ap.add_argument("--port", type=int, default=0, help="调试用 TCP 端口（绑定 127.0.0.1）")
    ap.add_argument("--no-auth", action="store_true", help="调试用：跳过网关登录校验")
    ap.add_argument("--data", default=os.path.join(APP_DIR, "..", "data"))
    ap.add_argument("--conf", default=os.path.join(APP_DIR, "..", "etc"))
    args = ap.parse_args()

    STORE = Store(os.path.abspath(args.data), os.path.abspath(args.conf))
    PREFIX = (args.prefix or "").rstrip("/")
    REQUIRE_AUTH = not args.no_auth

    if args.socket:
        srv = UnixHTTPServer(args.socket, Handler)
        print("%s listening on unix:%s prefix=%s auth=%s www=%s"
              % (APP_NAME, args.socket, PREFIX, REQUIRE_AUTH, WWW_DIR), flush=True)
    else:
        port = args.port or 8390
        srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        print("%s listening on 127.0.0.1:%d prefix=%s auth=%s www=%s"
              % (APP_NAME, port, PREFIX, REQUIRE_AUTH, WWW_DIR), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
