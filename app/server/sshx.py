#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公网小助手 - SSH 执行层。

零第三方依赖：调用系统 openssh 客户端，用 SSH_ASKPASS 免交互喂密码。
远端脚本统一 base64 传入，彻底规避 shell 引号地狱。
sudo 用 SUDO_ASKPASS -A，密码同样不落盘、不进命令行。
"""

import base64
import errno
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time


class SSHError(Exception):
    pass


def _sq(s):
    """POSIX 单引号转义。"""
    return "'" + str(s).replace("'", "'\\''") + "'"


_ASKPASS_BODY = "#!/bin/sh\nprintf '%%s\\n' %s\n"

_HOST_RE = re.compile(r"^[0-9A-Za-z_.\-:\[\]]+$")
_USER_RE = re.compile(r"^[0-9A-Za-z_.\-]+$")


def is_fake_ip(ip):
    """识别常见代理 fake-ip 段：Clash 默认 198.18.0.0/15 与 fc00::/7。"""
    ip = (ip or "").strip()
    if not ip:
        return False
    if ":" in ip:
        low = ip.lower()
        return low.startswith("fc") or low.startswith("fd")
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "198" and parts[1] == "18":
        return True
    return False


def _oserr(e):
    """把 socket 异常翻成可判断层级的说明。"""
    if isinstance(e, socket.timeout):
        return "TCP 握手超时（包被防火墙/安全组丢弃，或服务器不在线）"
    code = getattr(e, "errno", None)
    if isinstance(e, ConnectionRefusedError) or code == errno.ECONNREFUSED:
        return "连接被拒绝（端口没开 / SSH 服务没起）"
    if code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "网络不可达（该地址族没有路由）"
    if code == errno.EACCES:
        return "被本机策略拒绝"
    return "%s" % e


def dial(host, port=22, family="auto", timeout=6):
    """拨号前先做一次纯 TCP 连通性测试。

    这样能把「DNS 错 / 路由不通 / 端口没开 / SSH 认证失败」彻底分层，
    不会所有问题都笼统报成「连接超时」。
    """
    host = (host or "").strip()
    try:
        port = int(port or 22)
    except Exception:
        raise SSHError("SSH 端口不是合法数字")
    if not host:
        raise SSHError("未填写服务器地址")
    if not _HOST_RE.match(host):
        raise SSHError("服务器地址包含非法字符")

    host = host.strip("[]")
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSHError("域名无法解析：%s（%s）" % (host, e))
    except Exception as e:
        raise SSHError("解析地址失败：%s" % e)

    if family == "ipv4":
        want = [socket.AF_INET]
    elif family == "ipv6":
        want = [socket.AF_INET6]
    else:
        want = [socket.AF_INET, socket.AF_INET6]

    cand, seen = [], set()
    for fam in want:
        for it in infos:
            if it[0] != fam:
                continue
            ip = it[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            cand.append((fam, ip))
    if not cand:
        fam_name = {"ipv4": "IPv4", "ipv6": "IPv6"}.get(family, "IPv4/IPv6")
        raise SSHError("地址 %s 没有可用的 %s 记录，请检查连接地址族设置" % (host, fam_name))

    errs = []
    for fam, ip in cand:
        t0 = time.time()
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            ms = int((time.time() - t0) * 1000)
            return {"ip": ip, "ms": ms, "all": [c[1] for c in cand],
                    "family": "ipv6" if fam == socket.AF_INET6 else "ipv4",
                    "fake": is_fake_ip(ip)}
        except Exception as e:
            errs.append("%s(%s) %s" % (ip, "v6" if fam == socket.AF_INET6 else "v4", _oserr(e)))
        finally:
            try:
                s.close()
            except Exception:
                pass

    detail = "；".join(errs)
    hint = ""
    if any(is_fake_ip(c[1]) for c in cand):
        hint = "。注意：该地址被解析成了代理的 fake-ip，请改用真实 IP 或关掉本机代理的 DNS 劫持"
    raise SSHError("TCP 连不上 %s:%d —— %s%s" % (host, port, detail, hint))


def known_hosts_path(workdir):
    return os.path.join(workdir, "known_hosts")


def forget_host(workdir, host, port=22):
    """忘掉某台服务器的主机指纹（重装系统后指纹会变）。

    返回 (是否改动, 删掉的条目数)。注意：ssh 写入的条目可能是
    `host` 或 `[host]:port` 两种形式，hashed 形式则直接清空文件兜底——
    这个目录只存本应用要连的服务器。
    """
    p = known_hosts_path(workdir)
    if not os.path.isfile(p):
        return False, 0
    host = (host or "").strip().strip("[]")
    if not host:
        return False, 0
    try:
        port = int(port or 22)
    except Exception:
        port = 22
    # 按 OpenSSH 的写法约定匹配：默认端口 22 存成 `host`，
    # 非默认端口存成 `[host]:port`。清 2222 时不该顺手删掉 22 那条。
    if port == 22:
        keys = {host, "[%s]:22" % host}
    else:
        keys = {"[%s]:%d" % (host, port)}
    kept, removed, hashed = [], 0, 0
    try:
        with open(p, "r", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    kept.append(line)
                    continue
                first = s.split()[0] if s.split() else ""
                if first.startswith("|1|"):
                    hashed += 1
                    kept.append(line)
                    continue
                names = set(first.split(","))
                if names & keys:
                    removed += 1
                    continue
                kept.append(line)
        if removed == 0 and hashed > 0:
            # 指纹被哈希存储，无法逐条匹配，直接清空（只影响本应用）
            kept, removed = [], hashed
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(kept)
    except Exception:
        return False, 0
    return removed > 0, removed


class SSH(object):
    """一次部署会话内的 SSH 连接封装。用完务必 close()。"""

    def __init__(self, host, port=22, user="root", password="", keyfile="",
                 family="auto", connect_timeout=12, workdir="", timeout=90):
        self.host = (host or "").strip()
        self.user = (user or "root").strip()
        self.password = password or ""
        self.keyfile = (keyfile or "").strip()
        self.family = (family or "auto").strip().lower()
        self.connect_timeout = int(connect_timeout or 12)
        self.timeout = int(timeout or 90)
        self._askpass = ""
        self._tmpdir = ""
        self._known = ""
        self._own_tmp = False

        try:
            self.port = int(port or 22)
        except Exception:
            raise SSHError("SSH 端口不是合法数字")
        if not self.host:
            raise SSHError("未填写服务器地址")
        if not _HOST_RE.match(self.host):
            raise SSHError("服务器地址包含非法字符")
        if not _USER_RE.match(self.user):
            raise SSHError("用户名包含非法字符")
        if not (1 <= self.port <= 65535):
            raise SSHError("SSH 端口超出范围")
        if self.family not in ("auto", "ipv4", "ipv6"):
            self.family = "auto"

        self._setup(workdir)

    # ---------- 本地临时文件 ----------
    def _setup(self, workdir):
        if workdir:
            d = workdir
            os.makedirs(d, exist_ok=True)
        else:
            d = tempfile.mkdtemp(prefix="pq_ssh_")
            self._own_tmp = True
        try:
            os.chmod(d, 0o700)
        except Exception:
            pass
        self._tmpdir = d
        self._known = os.path.join(d, "known_hosts")
        if not os.path.exists(self._known):
            try:
                with open(self._known, "w", encoding="utf-8") as f:
                    f.write("")
            except Exception:
                pass
        if self.password:
            p = os.path.join(d, "askpass_%d.sh" % (os.getpid() % 100000))
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(_ASKPASS_BODY % _sq(self.password))
            try:
                os.chmod(p, 0o700)
            except Exception:
                pass
            self._askpass = p

    def _env(self):
        env = dict(os.environ)
        env.pop("SSH_ASKPASS", None)
        env.pop("SSH_ASKPASS_REQUIRE", None)
        if self._askpass:
            env["SSH_ASKPASS"] = self._askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY") or ":0"
        env["LC_ALL"] = "C"
        return env

    def _argv(self, remote):
        argv = []
        setsid = shutil.which("setsid")
        if setsid:
            argv.append(setsid)
        argv += ["ssh",
                 "-p", str(self.port),
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "UserKnownHostsFile=" + self._known,
                 "-o", "ConnectTimeout=%d" % self.connect_timeout,
                 "-o", "ConnectionAttempts=1",
                 "-o", "ServerAliveInterval=10",
                 "-o", "ServerAliveCountMax=3",
                 "-o", "NumberOfPasswordPrompts=1",
                 # 关键：CentOS/RHEL 默认宣告 gssapi-with-mic，客户端会先去试 Kerberos，
                 # 找不到 KDC 就静默挂到超时（实测 12s+ 才放弃）。必须显式关掉。
                 "-o", "GSSAPIAuthentication=no",
                 "-o", "GSSAPIKeyExchange=no",
                 "-o", "HostbasedAuthentication=no",
                 "-o", "LogLevel=ERROR"]
        if self.family == "ipv4":
            argv.append("-4")
        elif self.family == "ipv6":
            argv.append("-6")
        if self.keyfile:
            argv += ["-i", self.keyfile, "-o", "IdentitiesOnly=yes",
                     "-o", "PubkeyAuthentication=yes",
                     "-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
        else:
            argv += ["-o", "PubkeyAuthentication=no",
                     "-o", "PreferredAuthentications=password,keyboard-interactive"]
        argv += ["%s@%s" % (self.user, self.host), remote]
        return argv

    # ---------- 执行 ----------
    def run(self, script, sudo=False, timeout=0):
        """在远端执行一段 bash 脚本，返回 (rc, stdout, stderr)。"""
        rid = "%d_%d" % (int(time.time()) % 1000000, os.getpid() % 10000)
        runf = "/tmp/pq_run_%s.sh" % rid
        askf = "/tmp/pq_ask_%s.sh" % rid
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")

        lines = ["umask 077",
                 "printf %s " + b64 + " | base64 -d > " + runf,
                 "chmod 700 " + runf]
        if sudo:
            ab64 = base64.b64encode(
                (_ASKPASS_BODY % _sq(self.password)).encode("utf-8")).decode("ascii")
            lines += ["printf %s " + ab64 + " | base64 -d > " + askf,
                      "chmod 700 " + askf,
                      "SUDO_ASKPASS=" + askf + " sudo -A -p '' bash " + runf + "; rc=$?",
                      "rm -f " + runf + " " + askf]
        else:
            lines += ["bash " + runf + "; rc=$?",
                      "rm -f " + runf]
        lines.append("exit $rc")
        remote = "\n".join(lines)

        t = int(timeout or self.timeout)
        try:
            r = subprocess.run(self._argv(remote), capture_output=True, text=True,
                               timeout=t, env=self._env())
        except subprocess.TimeoutExpired:
            raise SSHError("连接 %s:%d 超时（%d 秒）" % (self.host, self.port, t))
        except FileNotFoundError:
            raise SSHError("本机没有 ssh 客户端，无法发起连接")
        except Exception as e:
            raise SSHError("发起 SSH 连接失败：%s" % e)
        return r.returncode, r.stdout or "", r.stderr or ""

    def run_ok(self, script, sudo=False, timeout=0):
        """执行并要求 rc==0，否则抛错（带远端 stderr 摘要）。"""
        rc, out, err = self.run(script, sudo=sudo, timeout=timeout)
        if rc != 0:
            msg = (err or "").strip() or (out or "").strip() or ("退出码 %d" % rc)
            raise SSHError(_friendly(msg))
        return out

    def _scp_base(self, legacy=False):
        argv = []
        setsid = shutil.which("setsid")
        if setsid:
            argv.append(setsid)
        argv += ["scp", "-P", str(self.port),
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "UserKnownHostsFile=" + self._known,
                 "-o", "ConnectTimeout=%d" % self.connect_timeout,
                 "-o", "GSSAPIAuthentication=no",
                 "-o", "GSSAPIKeyExchange=no",
                 "-o", "LogLevel=ERROR"]
        if legacy:
            argv.append("-O")
        if self.family == "ipv4":
            argv.append("-4")
        elif self.family == "ipv6":
            argv.append("-6")
        if self.keyfile:
            argv += ["-i", self.keyfile, "-o", "IdentitiesOnly=yes",
                     "-o", "PubkeyAuthentication=yes",
                     "-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
        else:
            argv += ["-o", "PubkeyAuthentication=no",
                     "-o", "PreferredAuthentications=password,keyboard-interactive"]
        return argv

    def get_file(self, remote_path, local_path, timeout=1800):
        """从远端拉文件回本机（scp pull），用于借服务器网络下载。"""
        last = ""
        for legacy in (False, True):
            argv = self._scp_base(legacy)
            argv += ["%s@%s:%s" % (self.user, self.host, remote_path), local_path]
            try:
                r = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=timeout, env=self._env())
            except subprocess.TimeoutExpired:
                last = "回传超时（%d 秒）" % timeout
                continue
            except Exception as e:
                last = "回传失败：%s" % e
                continue
            if r.returncode == 0 and os.path.isfile(local_path):
                return {"bytes": os.path.getsize(local_path)}
            last = _friendly((r.stderr or r.stdout or "").strip() or ("rc=%d" % r.returncode))
        raise SSHError("从服务器回传失败：%s" % last)

    def put_file(self, local_path, remote_path, timeout=900):
        """上传本地文件到远端（scp）。新老服务端都能用：失败后回退 -O 老协议。"""
        if not os.path.isfile(local_path):
            raise SSHError("本地文件不存在：%s" % local_path)
        size = os.path.getsize(local_path)
        last = ""
        for legacy in (False, True):
            argv = []
            setsid = shutil.which("setsid")
            if setsid:
                argv.append(setsid)
            argv += ["scp", "-P", str(self.port),
                     "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "UserKnownHostsFile=" + self._known,
                     "-o", "ConnectTimeout=%d" % self.connect_timeout,
                     "-o", "GSSAPIAuthentication=no",
                     "-o", "GSSAPIKeyExchange=no",
                     "-o", "LogLevel=ERROR"]
            if legacy:
                argv.append("-O")
            if self.family == "ipv4":
                argv.append("-4")
            elif self.family == "ipv6":
                argv.append("-6")
            if self.keyfile:
                argv += ["-i", self.keyfile, "-o", "IdentitiesOnly=yes",
                         "-o", "PubkeyAuthentication=yes",
                         "-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
            else:
                argv += ["-o", "PubkeyAuthentication=no",
                         "-o", "PreferredAuthentications=password,keyboard-interactive"]
            argv += [local_path, "%s@%s:%s" % (self.user, self.host, remote_path)]
            try:
                r = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=timeout, env=self._env())
            except subprocess.TimeoutExpired:
                last = "上传超时（%d 秒）" % timeout
                continue
            except Exception as e:
                last = "上传失败：%s" % e
                continue
            if r.returncode == 0:
                return {"bytes": size, "legacy": legacy}
            last = _friendly((r.stderr or r.stdout or "").strip() or ("rc=%d" % r.returncode))
        raise SSHError("上传 %s 失败：%s" % (os.path.basename(local_path), last))

    # ---------- 连通性 ----------
    def ping(self):
        """最小代价探活 + 基础身份信息。"""
        rc, out, err = self.run(
            "echo PQ_OK; id -u; whoami; uname -m; hostname", timeout=min(30, self.timeout))
        if rc != 0 or "PQ_OK" not in out:
            raise SSHError(_friendly((err or out or "").strip() or "无法连接"))
        lines = [x.strip() for x in out.splitlines() if x.strip()]
        info = {"uid": 0, "user": "", "arch": "", "hostname": ""}
        for ln in lines:
            if ln.isdigit():
                info["uid"] = int(ln)
                break
        idx = lines.index("PQ_OK") if "PQ_OK" in lines else -1
        tail = lines[idx + 1:]
        if len(tail) >= 3:
            info["user"], info["arch"], info["hostname"] = tail[1], tail[2], tail[3] if len(tail) > 3 else ""
        return info

    def close(self):
        try:
            if self._askpass and os.path.exists(self._askpass):
                os.unlink(self._askpass)
        except Exception:
            pass
        try:
            if self._own_tmp and self._tmpdir and os.path.isdir(self._tmpdir):
                shutil.rmtree(self._tmpdir, ignore_errors=True)
        except Exception:
            pass


def _friendly(msg):
    """把 openssh 的英文报错翻成人话。"""
    m = (msg or "").strip()
    low = m.lower()
    if "permission denied" in low:
        if "publickey" in low and "password" not in low:
            return "认证失败：服务器禁用了密码登录，请改用私钥"
        return "认证失败：账号或密码不正确"
    if "connection refused" in low:
        return "连接被拒绝：端口不对或 SSH 服务未开启"
    if "no route to host" in low:
        return "无法路由到该地址：IP 不对或网络不通"
    if "network is unreachable" in low:
        return "网络不可达：尝试切换 IPv4 / IPv6"
    if "connection timed out" in low or "timed out" in low:
        return "连接超时：检查防火墙、安全组是否放行 SSH 端口"
    if "host key verification failed" in low:
        return "服务器指纹与本机记录不一致（可能存在中间人），已阻止连接"
    if "could not resolve hostname" in low:
        return "域名无法解析"
    if m.count("\n") > 12:
        m = "\n".join(m.splitlines()[:12]) + "\n..."
    return m or "未知错误"
