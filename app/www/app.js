'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.prototype.slice.call(document.querySelectorAll(s));

const S = {
  step: 1,
  cfg: null,
  vpsIp: '',
  probeCache: {},
  ports: [],
  deployed: false,
  dirty: false,
  snap: '',
  pollTimer: 0,
  rtTimer: 0,
  probing: false
};

/* ================= 基础工具 ================= */
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

let toastTimer = 0;
function toast(msg, type) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast ' + (type || '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

async function api(path, body) {
  const opt = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : {};
  let r;
  try {
    r = await fetch(path, opt);
  } catch (e) {
    throw new Error('无法连接后端服务');
  }
  let j = null;
  try { j = await r.json(); } catch (e) { /* ignore */ }
  if (!j) throw new Error('服务返回异常（HTTP ' + r.status + '）');
  if (!j.ok) {
    const err = new Error(j.error || ('请求失败 HTTP ' + r.status));
    err.stage = j.stage || '';
    err.dial = j.dial || null;
    err.needReset = !!j.need_reset;
    throw err;
  }
  return j;
}

function fmtUp(sec) {
  sec = parseInt(sec, 10) || 0;
  if (!sec) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return d + ' 天 ' + h + ' 小时';
  if (h) return h + ' 小时 ' + m + ' 分';
  return m + ' 分 ' + (sec % 60) + ' 秒';
}

/* ================= 步骤导航 ================= */
function go(n, silent) {
  n = Math.max(1, Math.min(4, n));
  S.step = n;
  $$('.pane').forEach((el) => { el.hidden = (parseInt(el.dataset.pane, 10) !== n); });
  $$('.stp').forEach((el) => {
    const i = parseInt(el.dataset.step, 10);
    el.classList.toggle('cur', i === n);
    el.classList.toggle('done', i < n);
  });
  $('#btnPrev').disabled = (n === 1);
  $('#dots').innerHTML = [1, 2, 3, 4].map(
    (i) => '<i class="' + (i <= n ? 'on' : '') + '"></i>').join('');
  if (n === 4) {
    $('#btnNext').textContent = S.deployed ? '应用变更并重部署' : '开始部署';
    loadRuntime(false);
    startRtTimer();
    if (!silent) stopRtTimerIfLeft();
  } else {
    stopRtTimer();
    $('#btnNext').textContent = '下一步';
  }
  document.querySelector('.wrap').scrollTop = 0;
}

function stopRtTimerIfLeft() { /* 占位：保持 timer 在步骤 4 内 */ }

/* ================= 本机信息 ================= */
function renderLocal(loc) {
  if (!loc) return;
  const p = [];
  if (loc.hostname) p.push(loc.hostname);
  if (loc.ipv4 && loc.ipv4.length) p.push('IPv4 ' + loc.ipv4[0]);
  if (loc.ipv6 && loc.ipv6.length) p.push('IPv6 ' + loc.ipv6[0]);
  else p.push('无公网 IPv6');
  $('#localInfo').textContent = p.join(' · ');
}

/* ================= 表单 ================= */
function fillForm(c) {
  const v = c.vps || {};
  $('#vpsHost').value = v.host || '';
  $('#vpsPort').value = v.port || 22;
  $('#vpsUser').value = v.user || 'root';
  $('#vpsAuth').value = v.auth === 'key' ? 'key' : 'password';
  $('#vpsKey').value = v.keyfile || '';
  $('#vpsFamily').value = v.family || 'auto';
  S.vpsIp = v.ip || '';
  $('#pwSaved').hidden = !v.password_set;
  $('#vpsPass').placeholder = v.password_set ? '已保存密码，留空沿用' : 'SSH 登录密码';

  $('#domain').value = c.domain || '';
  $('#email').value = c.email || '';
  $('#useHttps').checked = !!c.use_https;

  syncAuthRows();
  syncHttpsRow();
  S.deployed = !!c.installed;
}

function syncAuthRows() {
  const key = $('#vpsAuth').value === 'key';
  $('#pwField').hidden = key;
  $('#keyField').hidden = !key;
}

function syncHttpsRow() {
  $('#emailRow').hidden = !$('#useHttps').checked;
}

function httpsOn() {
  return $('#useHttps').checked && !!($('#domain').value || '').trim();
}

/* ================= 端口表 ================= */
const LEVEL_LABEL = { ok: '推荐', care: '谨慎', block: '禁止', unknown: '未知' };

function urlFor(p) {
  if (!p.on) return '—';
  const dom = ($('#domain').value || '').trim();
  // 服务器地址可能填的是域名，优先用解析出来的 IP
  const host = S.vpsIp || ($('#vpsHost').value || '').trim() || '服务器IP';
  const port = p.pub || p.port;
  if (p.proto === 'udp') return 'udp://' + esc(dom || host) + ':' + port;
  // 只有「填了域名 + 勾了 HTTPS」才用 https，其余一律 http
  const scheme = httpsOn() ? 'https' : 'http';
  const base = dom || host;
  return scheme + '://' + esc(base) + (String(port) === '443' ? '' : ':' + port);
}

function renderPorts() {
  const body = $('#portBody');
  if (!S.ports.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">没有扫描到监听端口</td></tr>';
    return;
  }
  body.innerHTML = S.ports.map((p) => {
    const blocked = p.level === 'block';
    const k = p.port + ':' + p.proto;
    const lvlBadge = (p.level === 'ok' || p.level === 'care')
      ? '<span class="lvl ' + esc(p.level) + '">' + esc(LEVEL_LABEL[p.level]) + '</span>'
      : '';
    return '<tr data-k="' + k + '" class="' + (blocked ? 'blocked' : '') + '">'
      + '<td class="c-chk"><input type="checkbox" data-act="on"'
      + (p.on ? ' checked' : '') + (blocked ? ' disabled' : '') + '></td>'
      + '<td><div class="svc">' + lvlBadge + '<span class="nm" title="'
      + esc(p.name) + '">' + esc(p.name) + '</span></div></td>'
      + '<td><span class="proc" title="' + esc(p.proc) + '">' + esc(p.proc || '—') + '</span></td>'
      + '<td class="num">' + p.port + '</td>'
      + '<td><input type="number" min="1" max="65535" data-act="pub" value="'
      + (p.pub || p.port) + '"' + (p.on ? '' : ' disabled') + '></td>'
      + '<td class="c-proto">' + esc(p.proto)
      + ((p.scheme === 'http' || p.scheme === 'https')
        ? '<i class="sch ' + esc(p.scheme) + '">' + esc(p.scheme) + '</i>' : '')
      + '</td>'
      + '<td class="url">' + urlFor(p) + '</td></tr>';
  }).join('');
}

function portByKey(k) {
  return S.ports.find((p) => (p.port + ':' + p.proto) === k);
}

async function loadPorts(force) {
  try {
    const r = await api('api/ports' + (force ? '?force=1' : ''));
    if (r.local) renderLocal(r.local);
    const saved = (S.cfg && S.cfg.services) || [];
    const map = {};
    saved.forEach((s) => { map[s.port + ':' + s.proto] = s; });

    S.ports = (r.ports || []).map((p) => {
      const s = map[p.port + ':' + p.proto];
      return {
        port: p.port, proto: p.proto, name: p.name, proc: p.proc, level: p.level,
        scheme: p.scheme || '',
        on: s ? !!s.on : !!p.on,
        pub: s ? (s.public || s.port) : p.port
      };
    });
    saved.forEach((s) => {
      const k = s.port + ':' + s.proto;
      if (!S.ports.some((p) => (p.port + ':' + p.proto) === k)) {
        S.ports.push({
          port: s.port, proto: s.proto, name: s.name || '手动添加', proc: '',
          level: 'unknown', on: !!s.on, pub: s.public || s.port
        });
      }
    });
    renderPorts();
    // 端口表是异步补上的，快照要跟着重算，否则会误报「配置已改动」
    if (!S.dirty) S.snap = snapOf(collect());
  } catch (e) {
    $('#portBody').innerHTML = '<tr><td colspan="7" class="empty">扫描失败：'
      + esc(e.message) + '</td></tr>';
  }
}

/* ================= 收集 & 校验 ================= */
function collect() {
  return {
    vps: {
      host: $('#vpsHost').value.trim(),
      port: parseInt($('#vpsPort').value, 10) || 22,
      user: $('#vpsUser').value.trim() || 'root',
      auth: $('#vpsAuth').value,
      family: $('#vpsFamily').value,
      keyfile: $('#vpsKey').value.trim(),
      password: $('#vpsPass').value
    },
    domain: $('#domain').value.trim(),
    email: $('#email').value.trim(),
    use_https: $('#useHttps').checked,
    services: S.ports.filter((p) => p.on && p.level !== 'block').map((p) => ({
      port: p.port, proto: p.proto, public: p.pub || p.port, name: p.name, on: true
    }))
  };
}

function snapOf(c) {
  const d = JSON.parse(JSON.stringify(c));
  d.vps.password = '';
  return JSON.stringify(d);
}

function markDirty() {
  if (!S.deployed) return;
  S.dirty = (snapOf(collect()) !== S.snap);
  $('#dirtyBanner').hidden = !S.dirty;
}

function validateStep(n) {
  const c = collect();
  if (n === 1) {
    if (!c.vps.host) return '请填写服务器地址';
    if (!c.vps.user) return '请填写登录账号';
    if (c.vps.auth === 'key') {
      if (!c.vps.keyfile) return '请填写私钥路径';
    } else if (!c.vps.password && !(S.cfg && S.cfg.vps && S.cfg.vps.password_set)) {
      return '请填写 SSH 密码';
    }
    return null;
  }
  if (n === 2) {
    if (c.domain && !/^[0-9A-Za-z_.\-]+\.[A-Za-z]{2,}$/.test(c.domain)) {
      return '域名格式不正确';
    }
    if (c.use_https) {
      if (!c.domain) return '启用 HTTPS 需要填写域名';
      if (!c.email) return '启用 HTTPS 需要填写证书邮箱';
    }
    return null;
  }
  if (n === 3) {
    if (!c.services.length) return '请至少勾选一个要发布的端口';
    const seen = {};
    for (const s of c.services) {
      if ([22, 80, 443, 7000, 7500].indexOf(s.public) >= 0) {
        return '端口 ' + s.public + ' 不能作为公网端口（要留给服务器自身）';
      }
      if (seen[s.public]) return '公网端口 ' + s.public + ' 重复了';
      seen[s.public] = 1;
    }
    return null;
  }
  return null;
}

/* ================= 保存 ================= */
async function save(silent) {
  const r = await api('api/cfg', collect());
  S.cfg = r.cfg;
  $('#vpsPass').value = '';
  $('#pwSaved').hidden = !(r.cfg.vps && r.cfg.vps.password_set);
  // 以服务端为准同步部署状态，避免按钮文案和实际状态不一致
  if (r.cfg && typeof r.cfg.installed !== 'undefined') {
    S.deployed = !!r.cfg.installed;
    if (S.step === 4) {
      $('#btnNext').textContent = S.deployed ? '应用变更并重部署' : '开始部署';
    }
  }
  if (!silent) toast('配置已保存', 'ok');
  return r;
}

/* ================= 测试连接 ================= */
function renderProbe(p) {
  const box = $('#probeBox');
  box.hidden = false;
  box.className = 'probe ok';
  const has = p.has || {};
  const rows = [
    ['解析', p.dial ? (p.dial.ip + ' (' + p.dial.family + ', ' + p.dial.ms + ' ms)') : '—'],
    ['主机名', p.hostname || '—'],
    ['系统', (p.os_name || '—') + (p.os_version ? ' (' + p.os_version + ')' : '')],
    ['包管理', p.pkg === 'apt' ? 'apt' : p.pkg === 'dnf' ? 'dnf' : p.pkg === 'yum7' ? 'yum (CentOS 7)' : '未知'],
    ['架构', p.arch || '—'],
    ['权限', p.is_root ? 'root' : (p.sudo ? '普通用户 + sudo' : '普通用户（无 sudo）')],
    ['nginx', has.nginx ? (p.nginx_version || '已安装') : '未安装'],
    ['已占用', (p.used_tcp || []).slice(0, 12).join(', ') || '无']
  ];
  let html = '<div class="ptitle"><span class="dot"></span>连接成功 · '
    + esc(p.host || '') + ':' + esc(p.port) + '</div><div class="kv">';
  rows.forEach(([k, v]) => { html += '<b>' + esc(k) + '</b><span>' + esc(v) + '</span>'; });
  html += '</div>';
  if (p.warns && p.warns.length) {
    html += '<ul class="warns">'
      + p.warns.map((w) => '<li>' + esc(w) + '</li>').join('') + '</ul>';
  }
  box.innerHTML = html;
}

const STAGE_LABEL = {
  tcp: 'TCP 层不通（DNS / 路由 / 端口）',
  ssh: 'SSH 层失败（端口通了，但握手或认证没过）',
  probe: '探测脚本执行失败（SSH 已登录）'
};

function renderProbeError(msg, stage, dial, needReset) {
  const box = $('#probeBox');
  box.hidden = false;
  box.className = 'probe bad';
  let html = '<div class="ptitle"><span class="dot"></span>连接失败</div><div class="kv">';
  if (stage) html += '<b>失败层</b><span>' + esc(STAGE_LABEL[stage] || stage) + '</span>';
  if (dial && dial.ip) {
    html += '<b>TCP 拨号</b><span>已连通 ' + esc(dial.ip) + ' (' + esc(dial.family)
      + ', ' + esc(dial.ms) + ' ms)</span>';
  }
  html += '<b>原因</b><span>' + esc(msg) + '</span></div>';
  if (needReset) {
    html += '<div class="fixrow">'
      + '<span class="fixtip">服务器重装或换机后指纹会变，确认是你自己更换的服务器，即可清除旧记录。</span>'
      + '<button class="btn small" data-act="resetKey">清除旧指纹并重连</button>'
      + '</div>';
  }
  box.innerHTML = html;
}

async function resetHostKey() {
  const v = collect().vps;
  if (!v.host) { toast('请先填写服务器地址', 'err'); return; }
  try {
    const r = await api('api/ssh/reset-key', { host: v.host, port: v.port });
    toast(r.msg || '已清除旧指纹', 'ok');
    await testConn();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function testConn() {
  const btn = $('#btnTest');
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = '连接中…';
  $('#probeBox').hidden = true;
  try {
    const v = collect().vps;
    if (!v.host) throw new Error('请先填写服务器地址');
    const r = await api('api/ssh/test', v);
    renderProbe(r.probe);
    if (r.probe && r.probe.dial && r.probe.dial.ip) {
      S.vpsIp = r.probe.dial.ip;
      renderPorts();
    }
    toast('连接成功', 'ok');
  } catch (e) {
    renderProbeError(e.message, e.stage, e.dial, e.needReset);
    toast(e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

/* ================= 部署 ================= */
function renderSteps(steps) {
  const box = $('#deploySteps');
  if (!steps || !steps.length) {
    box.innerHTML = '<div class="hint">还没开始部署。</div>';
    return;
  }
  box.innerHTML = steps.map((s) => {
    const cls = s.state || 'pending';
    return '<div class="step ' + esc(cls) + '"><span class="sd"></span><span class="st">'
      + esc(s.title) + (s.detail ? '<span class="sd2">' + esc(s.detail) + '</span>' : '')
      + '</span></div>';
  }).join('');
}

function renderLog(logs) {
  const pre = $('#deployLog');
  pre.hidden = false;
  pre.textContent = (logs || []).join('\n');
  pre.scrollTop = pre.scrollHeight;
}

function renderResult(result) {
  const box = $('#deployResult');
  const urls = (result && result.urls) || [];
  if (!urls.length) { box.hidden = true; return; }
  let html = '<div class="rt">部署完成，访问地址：</div>';
  urls.forEach((u) => {
    html += '<div class="ru"><span class="code">' + esc(u.code || '') + '</span>'
      + '<span>' + esc(u.name || '') + '</span>'
      + '<a href="' + esc(u.url) + '" target="_blank" rel="noopener">'
      + esc(u.url) + '</a></div>';
  });
  box.innerHTML = html;
  box.hidden = false;
}

function stopPoll() {
  if (S.pollTimer) { clearInterval(S.pollTimer); S.pollTimer = 0; }
}

// 已部署完成后，部署面板整个隐藏，只留运行状态
function showDeployCard(show) {
  $('#deployCard').hidden = !show;
}

function setDeploying(on) {
  const b = $('#btnNext');
  b.disabled = on;
  b.textContent = on ? '执行中…' : (S.deployed ? '应用变更并重部署' : '开始部署');
  $('#btnCancel').hidden = !on;
}

async function tickDeploy() {
  let d = null;
  try { d = await api('api/deploy/status'); } catch (e) { return; }
  renderSteps(d.steps);
  if (d.logs && d.logs.length) renderLog(d.logs);
  if (d.running) {
    $('#btnCancel').hidden = false;
    showDeployCard(true);
  }
  if (d.done) {
    stopPoll();
    if (d.success) {
      renderResult(d.result);
      // 先置位再恢复按钮文案，否则文案会按旧状态算成「开始部署」
      S.deployed = true;
      S.dirty = false;
      $('#dirtyBanner').hidden = true;
      S.snap = snapOf(collect());
      S.probeCache = {};          // 拓扑变了，旧的检测结果作废
      setDeploying(false);
      toast('部署成功', 'ok');
      showDeployCard(false);
      loadRuntime(false);
      startRtTimer();             // 部署完就开始 6 秒自动刷新
    } else {
      setDeploying(false);
      showDeployCard(true);
      toast(d.error || '部署失败', 'err');
    }
  }
}

function startPoll() {
  stopPoll();
  S.pollTimer = setInterval(tickDeploy, 1200);
  tickDeploy();
}

async function startDeploy() {
  const c = collect();
  setDeploying(true);
  showDeployCard(true);
  $('#deployLog').hidden = false;
  $('#deployLog').textContent = '正在启动任务…';
  $('#deployResult').hidden = true;
  try {
    await api(S.deployed ? 'api/apply' : 'api/deploy', c);
    S.snap = snapOf(c);
    startPoll();
  } catch (e) {
    toast(e.message, 'err');
    setDeploying(false);
  }
}

/* ================= 运行状态 ================= */
function startRtTimer() {
  stopRtTimer();
  if (!S.deployed) return;
  S.rtTimer = setInterval(() => {
    if (S.step === 4 && !S.pollTimer && !S.probing) loadRuntime(false, true);
  }, 6000);
}

function stopRtTimer() {
  if (S.rtTimer) { clearInterval(S.rtTimer); S.rtTimer = 0; }
}

function renderRuntime(d) {
  const t = d.tunnel || {};
  const chip = $('#chipTunnel');
  chip.hidden = false;
  chip.className = 'chip ' + (t.running ? 'on' : 'off');
  chip.textContent = t.running ? '隧道运行中' : '隧道已停止';

  $('#runCard').hidden = !(d.deployed || t.running);

  const stTunnel = $('#stTunnel');
  stTunnel.textContent = t.running ? ('运行中 (pid ' + t.pid + ')') : '已停止';
  stTunnel.className = 'sv ' + (t.running ? 'ok' : 'bad');
  $('#stUptime').textContent = t.running ? fmtUp(t.uptime) : '—';
  $('#stDomain').textContent = d.domain || '未配置（HTTP）';
  $('#stFrpPort').textContent = d.frp_port ? String(d.frp_port) : '部署后分配';
  $('#stHost').textContent = d.ip || d.host || '—';
  const ld = d.last_deploy || {};
  $('#stLast').textContent = ld.at ? (ld.at + (ld.ok ? ' 成功' : ' 失败')) : '—';

  const rows = (d.services || []).map((s) => {
    const ck = s.port + ':' + s.proto;
    let r = s.result || null;
    if (r) {
      // 记住检测结果，避免 6 秒自动刷新把徽章刷回「未检测」
      S.probeCache[ck] = { code: r.code, ms: r.ms, at: Date.now() };
    } else {
      r = S.probeCache[ck] || null;
    }
    let badge = '<span class="badge na">未检测</span>';
    if (r) {
      const t = r.at ? new Date(r.at).toLocaleTimeString('zh-CN', { hour12: false }) : '';
      if (r.code > 0) {
        badge = '<span class="badge up" title="' + esc(t) + ' 检测">'
          + r.code + ' · ' + r.ms + 'ms</span>';
      } else {
        badge = '<span class="badge down" title="' + esc(t) + ' 检测">不通</span>';
      }
    }
    const link = s.proto === 'udp' ? esc(s.url)
      : '<a href="' + esc(s.url) + '" target="_blank" rel="noopener">' + esc(s.url) + '</a>';
    return '<tr><td>' + esc(s.name) + '</td><td class="num">' + s.port + '</td>'
      + '<td>' + esc(s.proto) + '</td><td class="url">' + link + '</td>'
      + '<td class="c-state">' + badge + '</td></tr>';
  }).join('');
  $('#runBody').innerHTML = rows || '<tr><td colspan="5" class="empty">没有已发布的服务</td></tr>';

  const logEl = $('#tunnelLog');
  logEl.textContent = (d.log && d.log.length) ? d.log.join('\n') : '暂无日志';
  logEl.scrollTop = logEl.scrollHeight;

  $('#btnStart').disabled = !!t.running;
  $('#btnStop').disabled = !t.running;
  $('#btnRestart').disabled = !t.running;

  // 已部署完成且没有任务在跑 → 隐藏部署面板，只留运行状态
  showDeployCard(!(d.deployed && !d.deploying));
}

async function loadRuntime(probe, quiet) {
  if (probe) {
    S.probing = true;
    $('#btnProbe').disabled = true;
    $('#btnProbe').textContent = '检测中…';
  }
  try {
    const d = await api('api/runtime' + (probe ? '?probe=1' : ''));
    renderRuntime(d);
    setRestartHint(d.need_restart);
    if (!quiet && probe) toast('检测完成', 'ok');
  } catch (e) {
    if (!quiet) toast(e.message, 'err');
  } finally {
    if (probe) {
      S.probing = false;
      $('#btnProbe').disabled = false;
      $('#btnProbe').textContent = '检测可达性';
    }
  }
}

async function tunnel(action, label) {
  const btn = $('#btn' + label);
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = '处理中…';
  try {
    const r = await api('api/tunnel', { action: action });
    toast(r.msg || '完成', 'ok');
    S.probeCache = {};          // 隧道重启过，旧结果不再可信
    await loadRuntime(false, true);
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

/* ================= 移除服务 ================= */
async function removeService() {
  const ok = confirm(
    '将移除本机与服务器上的全部发布配置：\n\n'
    + '· 本机：停止 frpc、删除隧道配置与日志\n'
    + '· 服务器：停止并删除 frps、删除反向代理站点\n'
    + '· nginx 本体与证书默认保留\n\n确定继续？');
  if (!ok) return;
  const purge = confirm(
    '是否同时删除服务器上的 HTTPS 证书与 ACME 记录？\n\n'
    + '确定 = 一并删除（换域名 / 彻底清空时用）\n'
    + '取消 = 保留证书（推荐，重签有频率限制）');
  const btn = $('#btnRemove');
  btn.disabled = true;
  btn.textContent = '清理中…';
  try {
    const r = await api('api/deploy/uninstall', { purge_cert: purge });
    const lines = r.lines || [];
    $('#deploySteps').innerHTML = lines.length
      ? lines.map((l) => '<div class="step ok"><span class="sd"></span><span class="st">'
        + esc(l) + '</span></div>').join('')
      : '<div class="hint">已清理</div>';
    $('#deployResult').hidden = true;
    $('#deployLog').hidden = true;
    S.deployed = false;
    S.dirty = false;
    $('#dirtyBanner').hidden = true;
    $('#runCard').hidden = true;
    $('#chipTunnel').hidden = true;
    $('#btnNext').textContent = '开始部署';
    // 部署完成后这张卡片是隐藏的，不重新显示就会出现「一片空白」
    stopRtTimer();
    showDeployCard(true);
    document.querySelector('.wrap').scrollTop = 0;
    toast('已移除', 'ok');
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = '移除服务';
  }
}

/* ================= 加载 ================= */
function setRestartHint(v) {
  $('#restartBar').hidden = !v;
}

async function loadAll() {
  try {
    const st = await api('api/status');
    renderLocal(st.local);
    setRestartHint(st.need_restart);
  } catch (e) {
    $('#localInfo').textContent = '本机信息读取失败：' + e.message;
  }
  try {
    const c = await api('api/cfg');
    S.cfg = c.cfg;
    fillForm(S.cfg);
    S.snap = snapOf(collect());
  } catch (e) {
    toast('读取配置失败：' + e.message, 'err');
  }
  // 先跳转，别让端口扫描（1~2 秒）挡住首屏
  go(S.deployed ? 4 : 1, true);
  if (S.deployed) loadRuntime(false, true);
  loadPorts();

  // 若上次任务还在跑，接上进度
  try {
    const d = await api('api/deploy/status');
    if (d.running) {
      go(4, true);
      renderSteps(d.steps);
      setDeploying(true);
      startPoll();
    } else if (d.done && d.steps && d.steps.length) {
      renderSteps(d.steps);
      if (d.logs && d.logs.length) renderLog(d.logs);
      if (d.success) {
        renderResult(d.result);
        if (!S.deployed) {               // 配置里还没标记，但上次是成功的
          S.deployed = true;
          if (S.step === 4) $('#btnNext').textContent = '应用变更并重部署';
        }
      }
      showDeployCard(!d.success);
    }
  } catch (e) { /* ignore */ }
}

/* ================= 事件 ================= */
function bind() {
  $$('.stp').forEach((el) => {
    el.addEventListener('click', () => go(parseInt(el.dataset.step, 10)));
  });

  $('#btnPrev').addEventListener('click', () => go(S.step - 1));
  $('#btnNext').addEventListener('click', async () => {
    if (S.step < 4) {
      const err = validateStep(S.step);
      if (err) { toast(err, 'err'); return; }
      try { await save(true); } catch (e) { toast('保存失败：' + e.message, 'err'); return; }
      go(S.step + 1);
      return;
    }
    const err = validateStep(1) || validateStep(2) || validateStep(3);
    if (err) { toast(err, 'err'); return; }
    startDeploy();
  });

  $('#vpsAuth').addEventListener('change', syncAuthRows);
  $('#useHttps').addEventListener('change', () => {
    syncHttpsRow();
    renderPorts();
    markDirty();
  });
  ['#domain', '#vpsHost'].forEach((sel) => {
    $(sel).addEventListener('input', () => {
      if (sel === '#vpsHost') S.vpsIp = '';   // 地址改了，旧的解析结果作废
      renderPorts();
      markDirty();
    });
  });
  ['#vpsPort', '#vpsUser', '#vpsKey', '#vpsFamily', '#vpsPass',
    '#email'].forEach((sel) => {
    $(sel).addEventListener('input', markDirty);
    $(sel).addEventListener('change', markDirty);
  });

  $('#portBody').addEventListener('change', (ev) => {
    const tr = ev.target.closest('tr[data-k]');
    if (!tr) return;
    const p = portByKey(tr.dataset.k);
    if (!p) return;
    if (ev.target.dataset.act === 'on') {
      p.on = ev.target.checked;
      renderPorts();
    } else if (ev.target.dataset.act === 'pub') {
      const n = parseInt(ev.target.value, 10);
      p.pub = (n >= 1 && n <= 65535) ? n : p.port;
      renderPorts();
    }
    markDirty();
  });

  $('#btnPickOk').addEventListener('click', () => {
    S.ports.forEach((p) => { p.on = (p.level === 'ok'); });
    renderPorts();
    markDirty();
  });
  $('#btnClear').addEventListener('click', () => {
    S.ports.forEach((p) => { p.on = false; });
    renderPorts();
    markDirty();
  });
  $('#btnAdd').addEventListener('click', () => {
    const port = parseInt($('#addPort').value, 10);
    const proto = $('#addProto').value;
    const name = ($('#addName').value || '').trim() || ('手动:' + port);
    if (!(port >= 1 && port <= 65535)) return toast('端口不合法', 'err');
    const k = port + ':' + proto;
    if (S.ports.some((p) => (p.port + ':' + p.proto) === k)) return toast('该端口已存在', 'err');
    S.ports.push({
      port: port, proto: proto, name: name, proc: '', level: 'unknown',
      on: true, pub: port
    });
    $('#addPort').value = '';
    $('#addName').value = '';
    renderPorts();
    markDirty();
  });
  $('#addName').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); $('#btnAdd').click(); }
  });
  $('#addPort').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); $('#btnAdd').click(); }
  });

  $('#btnReloadPage').addEventListener('click', () => location.reload());
  $('#btnRefreshPorts').addEventListener('click', () => loadPorts(true));
  $('#btnScanPorts').addEventListener('click', () => loadPorts(true));
  $('#btnTest').addEventListener('click', testConn);
  $('#probeBox').addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-act="resetKey"]');
    if (b) resetHostKey();
  });

  $('#btnProbe').addEventListener('click', () => loadRuntime(true));
  $('#btnStart').addEventListener('click', () => tunnel('start', 'Start'));
  $('#btnStop').addEventListener('click', () => tunnel('stop', 'Stop'));
  $('#btnRestart').addEventListener('click', () => tunnel('restart', 'Restart'));
  $('#btnRemove').addEventListener('click', removeService);
  $('#btnApply').addEventListener('click', startDeploy);

  $('#btnCancel').addEventListener('click', async () => {
    try {
      await api('api/deploy/cancel', {});
      toast('已请求取消', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  bind();
  loadAll();
});
