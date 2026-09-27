(function () {
  'use strict';

  var API = location.origin + '/extapi';
  var EXTVER = '41';

  function tok() {
    try { return localStorage.getItem('safeline_auth') || ''; } catch (e) { return ''; }
  }

  function api(path, opts) {
    opts = opts || {};
    var h = { 'Content-Type': 'application/json' };
    var t = tok();
    if (t) h['Authorization'] = 'Bearer ' + t;
    return fetch(API + path, {
      method: opts.method || 'GET',
      headers: h,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      if (r.status === 401) { toast('SLExt: войдите в панель SafeLine', true); }
      return r.json().catch(function () { return {}; });
    }).catch(function (e) {
      toast('SLExt: нет связи с API (' + (e && e.message ? e.message : e) + ')', true);
      return { ok: false, error: 'network' };
    });
  }

  function apiBlob(path) {
    var h = {};
    var t = tok();
    if (t) h['Authorization'] = 'Bearer ' + t;
    return fetch(API + path, { headers: h }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.blob();
    });
  }

  function el(html) {
    var t = document.createElement('template');
    t.innerHTML = html.trim();
    return t.content.firstChild;
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function toast(msg, bad) {
    var t = document.getElementById('sl-toast');
    if (!t) {
      t = el('<div id="sl-toast" class="sl-toast"></div>');
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.className = bad ? 'sl-toast sl-toast-bad' : 'sl-toast';
    t.style.opacity = '1';
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.style.opacity = '0'; }, 3500);
  }

  function themeEnabled() {
    return document.documentElement.classList.contains('slext-dark');
  }

  function applyTheme(dark) {
    document.documentElement.classList.toggle('slext-dark', !!dark);
    try { localStorage.setItem('slext_dark', dark ? '1' : '0'); } catch (e) {}
  }

  function initTheme() {
    try {
      if (localStorage.getItem('slext_dark') === '1') {
        document.documentElement.classList.add('slext-dark');
      }
    } catch (e) {}
  }

  function themeBtn() {
    if (document.getElementById('sl-theme-btn')) return;
    var header = document.querySelector('header');
    if (!header) return;
    var btns = header.querySelectorAll('button');
    if (!btns.length) return;
    var svg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">' +
      '<path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.39 5.39 0 0 1-4.4 2.26 5.4 5.4 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/></svg>';
    var b = el('<button id="sl-theme-btn" title="SLExt: тёмная / светлая тема">' + svg + '</button>');
    b.addEventListener('click', function () { applyTheme(!themeEnabled()); });
    var last = btns[btns.length - 1];
    last.parentNode.insertBefore(b, last);
  }

  function visibleDialog() {
    var dlgs = document.querySelectorAll('[role=dialog]');
    for (var i = 0; i < dlgs.length; i++) {
      var d = dlgs[i];
      if (d.offsetParent !== null && d.textContent.length > 20) return d;
    }
    return null;
  }

  function findByText(root, text) {
    var all = root.querySelectorAll('button,span,p,h6,div,label,a');
    var best = null, bestDepth = -1;
    for (var i = 0; i < all.length; i++) {
      var t = (all[i].textContent || '').trim();
      if (!t || t.toLowerCase().indexOf(text.toLowerCase()) === -1) continue;
      var depth = 0, n = all[i];
      while (n) { depth++; n = n.parentElement; }
      if (depth > bestDepth) { bestDepth = depth; best = all[i]; }
    }
    return best;
  }

  function findByTextDeep(root, text, excludeSel) {
    var all = root.querySelectorAll('button,span,p,h6,div,label,a');
    var best = null, bestDepth = -1;
    for (var i = 0; i < all.length; i++) {
      var t = (all[i].textContent || '').trim();
      if (!t || t.toLowerCase().indexOf(text.toLowerCase()) === -1) continue;
      if (excludeSel && all[i].closest && all[i].closest(excludeSel)) continue;
      var depth = 0, n = all[i];
      while (n) { depth++; n = n.parentElement; }
      if (depth > bestDepth) { bestDepth = depth; best = all[i]; }
    }
    return best;
  }

  function paperOf(node) {
    var n = node;
    while (n && n !== document.body) {
      if (n.classList && (n.classList.contains('MuiPaper-root') || n.classList.contains('MuiCard-root'))) return n;
      n = n.parentElement;
    }
    return node;
  }

  var SL_TABS = [
    ['overview', 'Обзор'],
    ['proxy', 'Проксирование'],
    ['dns', 'DNS и TLS'],
    ['wr', 'Зал ожидания'],
    ['lt', 'Тест ёмкости'],
    ['pages', 'Страницы'],
    ['sec', 'Безопасность'],
    ['notify', 'Уведомления']
  ];
  var SL_TAB = 'overview';
  var SL_ME = null;
  var TAB_PERM = {
    overview: 'overview.view', proxy: 'proxy.view', dns: 'dns.view', wr: 'wr.view',
    lt: 'lt.view', pages: 'pages.view', sec: 'skip.view', notify: 'notify.view'
  };

  function can(p) {
    return !SL_ME || (SL_ME.perms || []).indexOf(p) >= 0;
  }

  function slLoadMe() {
    api('/api/me').then(function (d) {
      if (d && d.ok && d.user) SL_ME = d.user;
      slApplyAccess();
    });
  }

  function slApplyAccess() {
    var btns = document.querySelectorAll('#sl-app-tabs .sl-tabbtn');
    var first = null, i;
    for (i = 0; i < btns.length; i++) {
      var tab = btns[i].getAttribute('data-tab');
      var perm = TAB_PERM[tab];
      var ok = !perm || can(perm) || (tab === 'sec' && (can('skip.view') || can('geo.view')));
      btns[i].style.display = ok ? '' : 'none';
      if (ok && !first) first = tab;
    }
    var cur = document.querySelector('#sl-app-tabs .sl-tabbtn[data-tab="' + SL_TAB + '"]');
    if (cur && cur.style.display === 'none' && first) slSetTab(first, true);
    var chip = document.getElementById('sl-app-user');
    if (chip && SL_ME) {
      var rl = { admin: 'Администратор', operator: 'Оператор', viewer: 'Наблюдатель', custom: 'Настраиваемый' }[SL_ME.role] || SL_ME.role;
      chip.textContent = SL_ME.username + ' · ' + rl +
        (SL_ME.domains && SL_ME.domains.length ? (' · домены: ' + SL_ME.domains.join(', ')) : '');
    }
  }

  function lockBtn(root, id, perm) {
    var b = root.querySelector('#' + id);
    if (b && !can(perm)) {
      b.disabled = true;
      b.title = 'Нет доступа (' + perm + ')';
      b.classList.add('sl-dis');
    }
    return b;
  }

  function slWorkOpen() {
    var a = document.getElementById('sl-app');
    return !!(a && a.classList.contains('open'));
  }

  function slNav() {
    if (document.getElementById('sl-nav-item')) return;
    if (location.pathname.indexOf('/login') === 0) return;
    var anchor = null;
    var all = document.querySelectorAll('.MuiDrawer-paper *');
    for (var i = 0; i < all.length; i++) {
      var t = (all[i].textContent || '').trim();
      if ((t === 'Settings' || t === 'Настройки') && all[i].children.length === 0) { anchor = all[i]; break; }
    }
    var list = null;
    if (anchor) {
      var item = anchor;
      while (item && item.parentElement && item.parentElement !== document.body) {
        if (item.parentElement.children.length >= 3) { list = item.parentElement; break; }
        item = item.parentElement;
      }
    }
    if (!list) list = document.querySelector('.MuiDrawer-paper ul') || document.querySelector('.MuiDrawer-paper');
    if (!list) return;
    var li = el('<div id="sl-nav-item" class="sl-nav">' +
      '<span class="sl-nav-ic">' +
      '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2 4 5v6c0 5.2 3.4 9.8 8 11 4.6-1.2 8-5.8 8-11V5l-8-3zm0 5.2 4 1.5V11c0 3.2-1.9 6.1-4 7.1-2.1-1-4-3.9-4-7.1V8.7l4-1.5z"/></svg>' +
      '</span><span>SLExt</span></div>');
    list.appendChild(li);
    li.addEventListener('click', function () { slOpen(); });
  }

  function ensureApp() {
    var a = document.getElementById('sl-app');
    if (a) { slNav(); return a; }
    if (location.pathname.indexOf('/login') === 0) return null;
    var tabs = SL_TABS.map(function (t) {
      return '<button class="sl-tabbtn" data-tab="' + t[0] + '">' + t[1] + '</button>';
    }).join('');
    var panes = SL_TABS.map(function (t) {
      return '<div class="sl-tabpane" id="sl-tab-' + t[0] + '"></div>';
    }).join('');
    a = el('<div id="sl-app">' +
      '<div id="sl-app-head"><b>SLExt</b><span class="sl-badge">расширения SafeLine</span>' +
      '<span class="sl-badge" id="sl-app-user"></span>' +
      '<span class="sl-hint" id="sl-app-status" style="margin:0"></span>' +
      '<button id="sl-app-close" title="Закрыть">&times;</button></div>' +
      '<div id="sl-app-tabs">' + tabs + '</div>' +
      '<div id="sl-app-body">' + panes + '</div></div>');
    document.body.appendChild(a);
    a.querySelector('#sl-app-close').addEventListener('click', function () { slClose(); });
    a.querySelector('#sl-app-tabs').addEventListener('click', function (e) {
      var b = e.target.closest('[data-tab]');
      if (b) slSetTab(b.getAttribute('data-tab'));
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') slClose(); });
    tipInit();
    document.addEventListener('click', function (e) {
      if (!slWorkOpen()) return;
      var nav = document.getElementById('sl-nav-item');
      if (nav && nav.contains(e.target)) return;
      var paper = document.querySelector('.MuiDrawer-paper');
      if (paper && paper.contains(e.target)) slClose();
    }, true);
    slAppTop();
    try { SL_TAB = localStorage.getItem('slext_tab') || 'overview'; } catch (e1) {}
    slSetTab(SL_TAB, true);
    var open = false;
    try { open = localStorage.getItem('slext_app') === '1'; } catch (e2) {}
    if (open) slOpen(SL_TAB);
    slNav();
    slLoadMe();
    return a;
  }

  function slAppTop() {
    var a = document.getElementById('sl-app');
    if (!a) return;
    var hd = document.querySelector('header') || document.querySelector('.MuiAppBar-root');
    var top = hd ? Math.round(hd.getBoundingClientRect().height) : 64;
    if (top < 40) top = 64;
    a.style.top = top + 'px';
  }

  function slUnselOthers(on) {
    var nodes = document.querySelectorAll('.MuiDrawer-paper .Mui-selected');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].classList.toggle('sl-unsel', !!on);
    }
  }

  function slSetTab(tab, silent) {
    SL_TAB = tab || 'overview';
    try { localStorage.setItem('slext_tab', SL_TAB); } catch (e) {}
    var btns = document.querySelectorAll('#sl-app-tabs .sl-tabbtn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('on', btns[i].getAttribute('data-tab') === SL_TAB);
    }
    var panes = document.querySelectorAll('#sl-app .sl-tabpane');
    for (var j = 0; j < panes.length; j++) {
      panes[j].style.display = (panes[j].id === 'sl-tab-' + SL_TAB) ? 'block' : 'none';
    }
    if (!silent && slWorkOpen()) {
      renderWorkspaceTab();
      slStatus();
    }
  }

  function slOpen(tab) {
    var a = ensureApp();
    if (!a) return;
    if (tab) SL_TAB = tab;
    a.classList.add('open');
    slAppTop();
    try { localStorage.setItem('slext_app', '1'); } catch (e) {}
    var nav = document.getElementById('sl-nav-item');
    if (nav) nav.classList.add('active');
    slUnselOthers(true);
    slSetTab(SL_TAB, true);
    renderWorkspaceTab();
    slStatus();
    slLoadMe();
  }

  function slClose() {
    var a = document.getElementById('sl-app');
    if (a) a.classList.remove('open');
    try { localStorage.setItem('slext_app', '0'); } catch (e) {}
    var nav = document.getElementById('sl-nav-item');
    if (nav) nav.classList.remove('active');
    slUnselOthers(false);
  }

  function slStatus() {
    var elx = document.getElementById('sl-app-status');
    if (!elx) return;
    Promise.all([api('/api/waiting'), api('/api/skip')]).then(function (r) {
      var wr = !!(r[0] && r[0].ok && r[0].mgt && r[0].mgt.is_enabled);
      var sk = !!(r[1] && r[1].ok && r[1].skip && r[1].skip.enabled);
      elx.textContent = 'зал ожидания: ' + (wr ? 'включён' : 'выключен') +
        ' · skip decryption: ' + (sk ? 'вкл' : 'выкл');
    }).catch(function () {});
  }

  function renderWorkspaceTab() {
    var host = document.getElementById('sl-tab-' + SL_TAB);
    if (!host) return;
    if (SL_TAB === 'overview') { renderStatsCard(host); renderCrowdSecCard(host); }
    else if (SL_TAB === 'proxy') { renderProxyCard(host); }
    else if (SL_TAB === 'dns') { renderDnsCard(host); }
    else if (SL_TAB === 'wr') { renderWaitingCard(host); }
    else if (SL_TAB === 'lt') { renderLoadTestCard(host); ltPoll(); }
    else if (SL_TAB === 'pages') { renderPageCard(host); }
    else if (SL_TAB === 'sec') { renderSkipCard(host); renderGeoCard(host); }
    else if (SL_TAB === 'notify') { renderNotifyCard(null, null, host); }
  }

  function refreshWrCard() {
    removeSection('sl-wr-sec');
    if (SL_TAB === 'wr') renderWorkspaceTab();
  }

  function removeSection(id) {
    var e = document.getElementById(id);
    if (e) e.remove();
  }

  function sectionAlive(id, ctx) {
    var e = document.getElementById(id);
    return !!(e && ctx && ctx.contains(e));
  }

  function fmtNum(n) { return (n || 0).toLocaleString('ru-RU'); }

  function fmtTime(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString('ru-RU');
  }

  function fmtSize(n) {
    if (n > 1048576) return (n / 1048576).toFixed(1) + ' МБ';
    if (n > 1024) return (n / 1024).toFixed(1) + ' КБ';
    return n + ' Б';
  }

  function canvasLine(canvas, values) {
    if (!canvas || !values.length) return;
    var dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = 64 * dpr;
    var ctx = canvas.getContext('2d');
    var max = Math.max.apply(null, values.concat([1]));
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.beginPath();
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--sl-primary').trim() || '#0fc6c2';
    ctx.lineWidth = 2 * dpr;
    values.forEach(function (v, i) {
      var x = (i / Math.max(1, values.length - 1)) * (canvas.width - 6) + 3;
      var y = canvas.height - (v / max) * (canvas.height - 10) - 5;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  function echartsLine(node, points, label) {
    if (!window.echarts || !node) return false;
    try {
      var chart = window.echarts.getInstanceByDom(node) || window.echarts.init(node);
      chart.setOption({
        grid: { left: 40, right: 12, top: 20, bottom: 26 },
        tooltip: { trigger: 'axis' },
        xAxis: { type: 'category', data: points.map(function (p) { return p.label; }),
                 axisLabel: { fontSize: 10 } },
        yAxis: { type: 'value', splitLine: { lineStyle: { opacity: 0.2 } } },
        series: [{ type: 'line', smooth: true, areaStyle: { opacity: 0.15 },
                   name: label || 'count', data: points.map(function (p) { return p.value; }) }]
      });
      return true;
    } catch (e) { return false; }
  }

  function renderBars(node, rows) {
    if (!node) return;
    node.innerHTML = barsHtml(rows || []);
  }

  /* ------------------------------ notifications ------------------------------ */

  function notifyCardHtml(n) {
    var tg = n.telegram || {};
    var dc = n.discord || {};
    var al = n.alarm || { enabled: false, rules: [] };
    var sl = n.syslog || {};
    var bk = n.backup || {};
    var rules = (al.rules || []).map(function (r, i) {
      return '<tr>' +
        '<td><input class="sl-input" data-al-name="' + i + '" value="' + esc(r.name) + '"></td>' +
        '<td><select class="sl-input" data-al-metric="' + i + '">' +
        [['attacks', 'атаки'], ['blocked', 'блокировки'], ['high_risk', 'высокий риск']].map(function (m) {
          return '<option value="' + m[0] + '"' + (r.metric === m[0] ? ' selected' : '') + '>' + m[1] + '</option>';
        }).join('') + '</select></td>' +
        '<td><input class="sl-input sl-w" type="number" min="1" data-al-th="' + i + '" value="' + esc(r.threshold) + '"></td>' +
        '<td><input class="sl-input sl-w" type="number" min="1" max="1440" data-al-win="' + i + '" value="' + esc(r.window) + '"></td>' +
        '<td><input class="sl-input sl-w" type="number" min="1" max="1440" data-al-cd="' + i + '" value="' + esc(r.cooldown) + '"></td>' +
        '<td><input type="checkbox" data-al-on="' + i + '"' + (r.enabled ? ' checked' : '') + '></td>' +
        '<td><button class="sl-btn sl-btn-x" data-al-del="' + i + '">&times;</button></td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="7" class="sl-hint">Пока нет правил</td></tr>';
    var files = (n._files || []).map(function (f) {
      return '<div class="sl-mono sl-file">' + esc(f.name) + ' — ' + fmtSize(f.size) +
        ' — ' + fmtTime(f.mtime) + '</div>';
    }).join('') || '<div class="sl-hint">Бэкапов ещё нет</div>';
    return '<div class="sl-card" id="sl-notify-sec">' +
      '<div class="sl-card-title">Уведомления и автоматизация <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Telegram, Discord, алерты, syslog и резервные копии. Последняя отправка: TG ' +
      (tg.last_send ? fmtTime(tg.last_send) : '—') + ', Discord ' + (dc.last_send ? fmtTime(dc.last_send) : '—') + '</div>' +
      '<details class="sl-details" open><summary>Telegram</summary>' +
      '<div class="sl-row"><label>Bot token</label><input class="sl-input sl-wide" id="sl-tg-token" value="' + esc(tg.bot_token) + '" placeholder="123456:ABC..."></div>' +
      '<div class="sl-row"><label>Chat ID</label><input class="sl-input" id="sl-tg-chat" value="' + esc(tg.chat_id) + '" placeholder="-1001234567890">' +
      '<label>Мин. риск</label><input class="sl-input sl-w" id="sl-tg-risk" type="number" min="0" max="10" value="' + esc(tg.min_risk) + '">' +
      '<label><input type="checkbox" id="sl-tg-on"' + (tg.enabled ? ' checked' : '') + '> включено</label></div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-tg-save">Сохранить</button>' +
      '<button class="sl-btn" id="sl-tg-test">Тест</button></div>' +
      (tg.last_error ? '<div class="sl-err">Ошибка: ' + esc(tg.last_error) + '</div>' : '') +
      '</details>' +
      '<details class="sl-details"><summary>Discord</summary>' +
      '<div class="sl-row"><label>Webhook URL</label><input class="sl-input sl-wide" id="sl-dc-hook" value="' + esc(dc.webhook) + '" placeholder="https://discord.com/api/webhooks/..."></div>' +
      '<div class="sl-row"><label>Мин. риск</label><input class="sl-input sl-w" id="sl-dc-risk" type="number" min="0" max="10" value="' + esc(dc.min_risk) + '">' +
      '<label><input type="checkbox" id="sl-dc-on"' + (dc.enabled ? ' checked' : '') + '> включено</label></div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-dc-save">Сохранить</button>' +
      '<button class="sl-btn" id="sl-dc-test">Тест</button></div>' +
      (dc.last_error ? '<div class="sl-err">Ошибка: ' + esc(dc.last_error) + '</div>' : '') +
      '</details>' +
      '<details class="sl-details"><summary>Алерты (пороговые правила)</summary>' +
      '<div class="sl-row"><label><input type="checkbox" id="sl-al-on"' + (al.enabled ? ' checked' : '') + '> алерты включены</label></div>' +
      '<table class="sl-table"><tr><th>Название</th><th>Метрика</th><th>Порог</th><th>Окно, мин</th><th>Пауза, мин</th><th>Вкл</th><th></th></tr>' +
      rules + '</table>' +
      '<div class="sl-row"><button class="sl-btn" id="sl-al-add">+ правило</button>' +
      '<button class="sl-btn sl-btn-pri" id="sl-al-save">Сохранить</button></div></details>' +
      '<details class="sl-details"><summary>Syslog</summary>' +
      '<div class="sl-row"><label>Сервер</label><input class="sl-input" id="sl-sl-host" value="' + esc(sl.host) + '" placeholder="10.10.0.10">' +
      '<label>Порт</label><input class="sl-input sl-w" id="sl-sl-port" type="number" min="1" max="65535" value="' + esc(sl.port) + '">' +
      '<label>Протокол</label><select class="sl-input sl-w" id="sl-sl-proto">' +
      '<option value="udp"' + (sl.proto !== 'tcp' ? ' selected' : '') + '>UDP</option>' +
      '<option value="tcp"' + (sl.proto === 'tcp' ? ' selected' : '') + '>TCP</option></select>' +
      '<label><input type="checkbox" id="sl-sl-on"' + (sl.enabled ? ' checked' : '') + '> включено</label></div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-sl-save">Сохранить</button>' +
      '<button class="sl-btn" id="sl-sl-test">Тест</button></div>' +
      (sl.last_error ? '<div class="sl-err">Ошибка: ' + esc(sl.last_error) + '</div>' : '') +
      '</details>' +
      '<details class="sl-details"><summary>Резервные копии (конфиг + база)</summary>' +
      '<div class="sl-row"><label><input type="checkbox" id="sl-bk-on"' + (bk.enabled ? ' checked' : '') + '> включено</label>' +
      '<label>Час</label><input class="sl-input sl-w" id="sl-bk-hour" type="number" min="0" max="23" value="' + esc(bk.hour) + '">' +
      '<label>Хранить, дней</label><input class="sl-input sl-w" id="sl-bk-keep" type="number" min="1" max="365" value="' + esc(bk.keep_days) + '"></div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-bk-save">Сохранить</button>' +
      '<button class="sl-btn" id="sl-bk-run">Сделать бэкап сейчас</button></div>' +
      (bk.last_error ? '<div class="sl-err">Ошибка: ' + esc(bk.last_error) + '</div>' : '') +
      '<div class="sl-sub">Последний: ' + (bk.last_run ? fmtTime(bk.last_run) : '—') + '</div>' + files +
      '</details></div>';
  }

  function collectAlarm(card) {
    var rules = [];
    card.querySelectorAll('[data-al-name]').forEach(function (inp) {
      var i = inp.getAttribute('data-al-name');
      rules.push({
        id: 'rule_' + i,
        name: inp.value.trim() || ('rule ' + i),
        metric: card.querySelector('[data-al-metric="' + i + '"]').value,
        threshold: parseInt(card.querySelector('[data-al-th="' + i + '"]').value, 10) || 1,
        window: parseInt(card.querySelector('[data-al-win="' + i + '"]').value, 10) || 5,
        cooldown: parseInt(card.querySelector('[data-al-cd="' + i + '"]').value, 10) || 30,
        enabled: card.querySelector('[data-al-on="' + i + '"]').checked
      });
    });
    return { enabled: document.getElementById('sl-al-on').checked, rules: rules };
  }

  function renderNotifyCard(ctx, preloaded, host) {
    function show(d) {
      if (document.getElementById('sl-notify-sec')) return;
      var n = d.notify || {};
      n.alarm = (preloaded && preloaded.alarm) || { enabled: false, rules: [] };
      n.syslog = (preloaded && preloaded.syslog) || {};
      n.backup = (preloaded && preloaded.backup) || {};
      n._files = (preloaded && preloaded.files) || [];
      var card = el(notifyCardHtml(n));
      if (!host) return;
      host.appendChild(card);
      bindNotify(card);
      if (!can('notify.edit')) {
        card.querySelectorAll('button').forEach(function (b) {
          b.disabled = true;
          b.title = 'Нет доступа (notify.edit)';
          b.classList.add('sl-dis');
        });
        var h = el('<div class="sl-warn">Только просмотр: нет права notify.edit.</div>');
        card.insertBefore(h, card.children[1] || null);
      }
    }
    if (preloaded) return show(preloaded);
    Promise.all([
      api('/api/notify'), api('/api/alarm'), api('/api/syslog'), api('/api/backup')
    ]).then(function (r) {
      show({ notify: r[0].notify, alarm: (r[1] || {}).alarm, syslog: (r[2] || {}).syslog,
             backup: (r[3] || {}).backup, files: (r[3] || {}).files });
    });
  }

  function bindNotify(card) {
    card.addEventListener('click', function (e) {
      var id = e.target.id;
      if (id === 'sl-tg-save') {
        api('/api/notify', { method: 'POST', body: { notify: { telegram: {
          bot_token: document.getElementById('sl-tg-token').value.trim(),
          chat_id: document.getElementById('sl-tg-chat').value.trim(),
          min_risk: parseInt(document.getElementById('sl-tg-risk').value, 10) || 0,
          enabled: document.getElementById('sl-tg-on').checked
        } } } }).then(function (r) { toast(r.ok ? 'Telegram сохранён' : 'Ошибка', !r.ok); });
      }
      if (id === 'sl-tg-test') {
        api('/api/notify/test', { method: 'POST', body: { channel: 'telegram' } })
          .then(function (r) { toast(r.ok ? 'Тест отправлен' : ('Ошибка: ' + (r.results && r.results.telegram)), !r.ok); });
      }
      if (id === 'sl-dc-save') {
        api('/api/notify', { method: 'POST', body: { notify: { discord: {
          webhook: document.getElementById('sl-dc-hook').value.trim(),
          min_risk: parseInt(document.getElementById('sl-dc-risk').value, 10) || 0,
          enabled: document.getElementById('sl-dc-on').checked
        } } } }).then(function (r) { toast(r.ok ? 'Discord сохранён' : 'Ошибка', !r.ok); });
      }
      if (id === 'sl-dc-test') {
        api('/api/notify/test', { method: 'POST', body: { channel: 'discord' } })
          .then(function (r) { toast(r.ok ? 'Тест отправлен' : ('Ошибка: ' + (r.results && r.results.discord)), !r.ok); });
      }
      if (id === 'sl-al-add') {
        var al = collectAlarm(card);
        al.rules.push({ id: 'rule_new', name: 'Новое правило', metric: 'attacks', threshold: 20, window: 5, cooldown: 30, enabled: true });
        api('/api/alarm', { method: 'POST', body: { alarm: al } }).then(function (r) {
          toast(r.ok ? 'Правило добавлено' : 'Ошибка', !r.ok);
          if (r.ok) location.reload();
        });
      }
      if (id === 'sl-al-del') {
        var al2 = collectAlarm(card);
        al2.rules.splice(parseInt(e.target.getAttribute('data-al-del'), 10), 1);
        api('/api/alarm', { method: 'POST', body: { alarm: al2 } }).then(function (r) {
          toast(r.ok ? 'Правило удалено' : 'Ошибка', !r.ok);
          if (r.ok) location.reload();
        });
      }
      if (id === 'sl-al-save') {
        api('/api/alarm', { method: 'POST', body: { alarm: collectAlarm(card) } })
          .then(function (r) { toast(r.ok ? 'Алерты сохранены' : 'Ошибка', !r.ok); });
      }
      if (id === 'sl-sl-save') {
        api('/api/syslog', { method: 'POST', body: { syslog: {
          enabled: document.getElementById('sl-sl-on').checked,
          host: document.getElementById('sl-sl-host').value.trim(),
          port: parseInt(document.getElementById('sl-sl-port').value, 10) || 514,
          proto: document.getElementById('sl-sl-proto').value
        } } }).then(function (r) { toast(r.ok ? 'Syslog сохранён' : 'Ошибка', !r.ok); });
      }
      if (id === 'sl-sl-test') {
        api('/api/syslog/test', { method: 'POST', body: {} })
          .then(function (r) { toast(r.ok ? 'Syslog тест отправлен' : 'Не отправлено', !r.ok); });
      }
      if (id === 'sl-bk-save') {
        api('/api/backup', { method: 'POST', body: { backup: {
          enabled: document.getElementById('sl-bk-on').checked,
          hour: parseInt(document.getElementById('sl-bk-hour').value, 10) || 4,
          keep_days: parseInt(document.getElementById('sl-bk-keep').value, 10) || 7
        } } }).then(function (r) { toast(r.ok ? 'Бэкап сохранён' : 'Ошибка', !r.ok); });
      }
      if (id === 'sl-bk-run') {
        toast('Делаю бэкап...');
        api('/api/backup/run', { method: 'POST', body: {} }).then(function (r) {
          toast(r.ok ? ('Готово: ' + r.info) : ('Ошибка: ' + (r.info || '')), !r.ok);
        });
      }
    });
  }

  /* ------------------------------ load balancer ------------------------------ */

  var ALGO_INFO = {
    round_robin: 'По очереди — запросы идут по кругу с учётом веса. Базовый вариант.',
    least_conn: 'На узел с наименьшим числом активных соединений — лучший выбор при разной длительности запросов.',
    ip_hash: 'Каждый клиент всегда попадает на свой узел по IP. Простая липкая сессия без cookie.',
    hash_uri: 'Один и тот же URL всегда обслуживает один узел. Удобно для кэширования.',
    hash_cookie: 'Липкая сессия по cookie slext, при её отсутствии — по IP.',
    random_two: 'Берутся два случайных узла, выбирается лучший из них (least_conn). Хорошо против перекосов.'
  };

  function lbNodesRows(backends, byAddr) {
    return (backends || []).map(function (b, i) {
      var st = byAddr[b.addr] || {};
      var dot = !b.enabled ? 'sl-dot-off' : (st.up === false ? 'sl-dot-down' : 'sl-dot-up');
      var label = !b.enabled ? 'выкл' : (st.up === false ? 'недоступен' : 'доступен');
      return '<tr>' +
        '<td><input class="sl-input" data-sl-addr="' + i + '" value="' + esc(b.addr) + '"></td>' +
        '<td><input class="sl-input sl-w" data-sl-weight="' + i + '" type="number" min="1" max="100" value="' + esc(b.weight) + '"></td>' +
        '<td><select class="sl-input sl-w" data-sl-role="' + i + '">' +
        '<option value="primary"' + (b.role !== 'backup' ? ' selected' : '') + '>основной</option>' +
        '<option value="backup"' + (b.role === 'backup' ? ' selected' : '') + '>резерв</option>' +
        '</select></td>' +
        '<td><input class="sl-input sl-w" data-sl-maxconns="' + i + '" type="number" min="0" max="100000" value="' + esc(b.max_conns || 0) + '"></td>' +
        '<td><input type="checkbox" data-sl-on="' + i + '"' + (b.enabled ? ' checked' : '') + '></td>' +
        '<td><span class="sl-dot ' + dot + '"></span>' + label + '</td>' +
        '<td><button class="sl-btn sl-btn-x" data-sl-del="' + i + '">&times;</button></td>' +
        '</tr>';
    }).join('') || '<tr><td colspan="7" class="sl-hint">Пока нет узлов</td></tr>';
  }

  function lbTableHtml(backends, byAddr) {
    return '<table class="sl-table"><tr><th>Узел (host:port)</th><th>Вес</th><th>Роль</th>' +
      '<th>Макс. соед.</th><th>Вкл</th><th>Статус</th><th></th></tr>' +
      lbNodesRows(backends, byAddr) + '</table>';
  }

  function lbCardHtml(lb, status) {
    var byAddr = {};
    (status || []).forEach(function (s) { byAddr[s.addr] = s; });
    var h = lb.health || {};
    var o = lb.options || {};
    return '<div class="sl-card" id="sl-lb-sec">' +
      '<div class="sl-card-title">Балансировка нагрузки <span class="sl-badge">SLExt</span>' +
      '<span class="sl-badge">upstream: 127.0.0.1:8081</span></div>' +
      '<div class="sl-hint">В поле Upstream приложения укажите <b>http://127.0.0.1:8081</b>, а реальные серверы настройте здесь. «Резерв» включается только когда основные узлы недоступны.</div>' +
      '<div class="sl-row"><label>Метод распределения</label>' +
      '<select class="sl-input sl-wide" id="sl-lb-algo">' +
      [['round_robin', 'По очереди (round-robin)'], ['least_conn', 'Наименьшее число соединений'],
       ['ip_hash', 'Привязка по IP (липкая сессия)'], ['hash_uri', 'Привязка по URL'],
       ['hash_cookie', 'Липкая сессия по cookie'], ['random_two', 'Случайные два (random two)']]
        .map(function (a) {
          return '<option value="' + a[0] + '"' + (lb.algorithm === a[0] ? ' selected' : '') + '>' + a[1] + '</option>';
        }).join('') +
      '</select></div>' +
      '<div class="sl-hint" id="sl-lb-algo-info"></div>' +
      lbTableHtml(lb.backends, byAddr) +
      '<div class="sl-row"><button class="sl-btn" id="sl-lb-add">+ узел</button>' +
      '<button class="sl-btn" id="sl-lb-add-backup">+ резервный узел</button>' +
      '<button class="sl-btn sl-btn-pri" id="sl-lb-save">Сохранить</button>' +
      '<button class="sl-btn" id="sl-lb-test">Проверить (12 запросов)</button></div>' +
      '<details class="sl-details"><summary>Проверка доступности (health-check)</summary>' +
      '<div class="sl-row"><label>Интервал, с</label><input class="sl-input sl-w" id="sl-h-int" type="number" min="5" max="300" value="' + esc(h.interval || 15) + '">' +
      '<label>Таймаут, с</label><input class="sl-input sl-w" id="sl-h-to" type="number" min="1" max="30" value="' + esc(h.timeout || 3) + '">' +
      '<label>Путь</label><input class="sl-input sl-w" id="sl-h-path" value="' + esc(h.path || '/') + '">' +
      '<label>Ошибок подряд</label><input class="sl-input sl-w" id="sl-h-fails" type="number" min="1" max="20" value="' + esc(h.failures || 3) + '">' +
      '<label><input type="checkbox" id="sl-h-notify"' + (h.notify !== false ? ' checked' : '') + '> уведомлять</label></div></details>' +
      '<details class="sl-details"><summary>Дополнительно: keepalive, таймауты, повторы</summary>' +
      '<div class="sl-row"><label>keepalive</label><input class="sl-input sl-w" id="sl-o-ka" type="number" min="0" max="1024" value="' + esc(o.keepalive) + '">' +
      '<label>connect, с</label><input class="sl-input sl-w" id="sl-o-ct" type="number" min="1" max="600" value="' + esc(o.connect_timeout) + '">' +
      '<label>read, с</label><input class="sl-input sl-w" id="sl-o-rt" type="number" min="1" max="3600" value="' + esc(o.read_timeout) + '">' +
      '<label>send, с</label><input class="sl-input sl-w" id="sl-o-st" type="number" min="1" max="3600" value="' + esc(o.send_timeout) + '"></div>' +
      '<div class="sl-row"><label>повторов на другой узел</label><input class="sl-input sl-w" id="sl-o-tries" type="number" min="1" max="10" value="' + esc(o.tries) + '">' +
      '<label><input type="checkbox" id="sl-o-retry"' + (o.retry_5xx !== false ? ' checked' : '') + '> повторять при ошибках и 5xx</label>' +
      '<label>пассивных ошибок</label><input class="sl-input sl-w" id="sl-o-mf" type="number" min="0" max="100" value="' + esc(o.passive_max_fails) + '">' +
      '<label>fail_timeout, с</label><input class="sl-input sl-w" id="sl-o-mft" type="number" min="1" max="3600" value="' + esc(o.passive_fail_timeout) + '"></div></details>' +
      '<div class="sl-hint sl-mono" id="sl-lb-out"></div>' +
      '</div>';
  }

  function renderLbCard(ctx) {
    api('/api/lb').then(function (d) {
      if (!d.ok) return;
      var card = el(lbCardHtml(d.lb, d.status));
      var anchor = findByText(ctx, 'add upstream');
      if (!anchor) return;
      var block = anchor.closest('div');
      if (block && block.parentElement) {
        block.parentElement.insertBefore(card, block.nextSibling);
      } else {
        anchor.parentElement.insertBefore(card, anchor.nextSibling);
      }
      bindLb(card);
      algoInfo();
    });
  }

  function collectLb() {
    var lb = { algorithm: document.getElementById('sl-lb-algo').value, backends: [], health: {
      enabled: true,
      interval: parseInt(document.getElementById('sl-h-int').value, 10) || 15,
      timeout: parseInt(document.getElementById('sl-h-to').value, 10) || 3,
      path: document.getElementById('sl-h-path').value || '/',
      failures: parseInt(document.getElementById('sl-h-fails').value, 10) || 3,
      notify: document.getElementById('sl-h-notify').checked
    }, options: {
      keepalive: parseInt(document.getElementById('sl-o-ka').value, 10) || 0,
      connect_timeout: parseInt(document.getElementById('sl-o-ct').value, 10) || 5,
      read_timeout: parseInt(document.getElementById('sl-o-rt').value, 10) || 300,
      send_timeout: parseInt(document.getElementById('sl-o-st').value, 10) || 60,
      tries: parseInt(document.getElementById('sl-o-tries').value, 10) || 3,
      retry_5xx: document.getElementById('sl-o-retry').checked,
      passive_max_fails: parseInt(document.getElementById('sl-o-mf').value, 10) || 0,
      passive_fail_timeout: parseInt(document.getElementById('sl-o-mft').value, 10) || 10
    } };
    document.querySelectorAll('[data-sl-addr]').forEach(function (inp) {
      var i = inp.getAttribute('data-sl-addr');
      lb.backends.push({
        addr: inp.value.trim(),
        weight: parseInt(document.querySelector('[data-sl-weight="' + i + '"]').value, 10) || 1,
        role: document.querySelector('[data-sl-role="' + i + '"]').value,
        max_conns: parseInt(document.querySelector('[data-sl-maxconns="' + i + '"]').value, 10) || 0,
        enabled: document.querySelector('[data-sl-on="' + i + '"]').checked
      });
    });
    return lb;
  }

  function algoInfo() {
    var box = document.getElementById('sl-lb-algo-info');
    var sel = document.getElementById('sl-lb-algo');
    if (box && sel && ALGO_INFO[sel.value]) box.textContent = ALGO_INFO[sel.value];
  }

  function bindLb(card) {
    card.addEventListener('change', function (e) {
      if (e.target.id === 'sl-lb-algo') algoInfo();
    });
    card.addEventListener('click', function (e) {
      var del = e.target.closest('[data-sl-del]');
      if (del) {
        var lb = collectLb();
        lb.backends.splice(parseInt(del.getAttribute('data-sl-del'), 10), 1);
        spliceBackends(card, lb);
        return;
      }
      if (e.target.id === 'sl-lb-add' || e.target.id === 'sl-lb-add-backup') {
        var l2 = collectLb();
        l2.backends.push({
          addr: '10.8.0.2:8080', weight: 1,
          role: e.target.id === 'sl-lb-add-backup' ? 'backup' : 'primary',
          max_conns: 0, enabled: true
        });
        spliceBackends(card, l2);
        return;
      }
      if (e.target.id === 'sl-lb-save') {
        api('/api/lb', { method: 'POST', body: { lb: collectLb() } }).then(function (r) {
          toast(r.ok ? 'Балансировка сохранена' : ('Ошибка: ' + (r.error || '')), !r.ok);
        });
        return;
      }
      if (e.target.id === 'sl-lb-test') {
        var out = document.getElementById('sl-lb-out');
        out.textContent = 'Проверяю...';
        api('/api/lb/test?n=12').then(function (r) {
          if (!r.ok) { out.textContent = 'Ошибка'; return; }
          var res = r.results || [];
          var counts = {};
          res.forEach(function (x) { counts[x] = (counts[x] || 0) + 1; });
          out.textContent = res.map(function (x, i) { return (i + 1) + '. ' + x; }).join('\n') +
            '\n\nИтого:\n' + Object.keys(counts).map(function (k) { return counts[k] + ' x ' + k; }).join('\n');
        });
      }
    });
  }

  function spliceBackends(card, lb) {
    var t = card.querySelector('table');
    t.outerHTML = lbTableHtml(lb.backends, {});
  }

  /* ------------------------------ stats ------------------------------ */

  var STATS_HOURS = 24;

  function statsCardHtml() {
    return '<div class="sl-card" id="sl-stats-sec">' +
      '<div class="sl-card-title">Анализ трафика и атак <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Считаются только реальные атаки из журнала SafeLine; служебные записи (Deny/Allow/Non-Attack) не учитываются.</div>' +
      '<div class="sl-row sl-tabs">' +
      '<button class="sl-btn" data-sl-hours="1">1ч</button>' +
      '<button class="sl-btn" data-sl-hours="24">24ч</button>' +
      '<button class="sl-btn" data-sl-hours="168">7д</button>' +
      '<button class="sl-btn" data-sl-hours="720">30д</button>' +
      '<button class="sl-btn" id="sl-st-export-csv">Экспорт CSV</button>' +
      '<button class="sl-btn" id="sl-st-export-json">JSON</button>' +
      '<button class="sl-btn" id="sl-st-refresh">Обновить</button></div>' +
      '<div class="sl-kpis" id="sl-st-kpis"><div class="sl-hint">Загрузка…</div></div>' +
      '<div class="sl-chart" id="sl-st-chart" style="width:100%;height:64px"><canvas id="sl-st-spark" style="width:100%;height:64px"></canvas></div>' +
      '<div class="sl-grid2">' +
      '<div><div class="sl-sub">Типы атак</div><div id="sl-st-types" class="sl-bars"></div></div>' +
      '<div><div class="sl-sub">Страны</div><div id="sl-st-countries" class="sl-bars"></div></div>' +
      '<div><div class="sl-sub">Топ сайтов</div><div id="sl-st-sites" class="sl-bars"></div></div>' +
      '<div><div class="sl-sub">Топ IP</div><div id="sl-st-ips" class="sl-bars"></div></div>' +
      '<div><div class="sl-sub">Топ URL</div><div id="sl-st-paths" class="sl-bars"></div></div>' +
      '<div><div class="sl-sub">Действия</div><div id="sl-st-actions" class="sl-bars"></div></div>' +
      '</div></div>';
  }

  function renderStatsCard(host) {
    if (document.getElementById('sl-stats-sec') || !host) return;
    var card = el(statsCardHtml());
    host.appendChild(card);
    card.addEventListener('click', function (e) {
      var hb = e.target.closest('[data-sl-hours]');
      if (hb) {
        STATS_HOURS = parseInt(hb.getAttribute('data-sl-hours'), 10) || 24;
        load();
        return;
      }
      if (e.target.id === 'sl-st-refresh') load();
      if (e.target.id === 'sl-st-export-csv' || e.target.id === 'sl-st-export-json') {
        var fmt = e.target.id.endsWith('json') ? 'json' : 'csv';
        toast('Готовлю экспорт...');
        apiBlob('/api/export?hours=' + STATS_HOURS + '&format=' + fmt).then(function (b) {
          var a = document.createElement('a');
          a.href = URL.createObjectURL(b);
          a.download = 'safeline-attacks.' + fmt;
          document.body.appendChild(a);
          a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
          toast('Экспорт готов');
        }).catch(function (err) { toast('Ошибка экспорта: ' + err.message, true); });
      }
    });
    load();

    function load() {
      document.querySelectorAll('[data-sl-hours]').forEach(function (b) {
        b.classList.toggle('sl-btn-pri', parseInt(b.getAttribute('data-sl-hours'), 10) === STATS_HOURS);
      });
      api('/api/attacks?hours=' + STATS_HOURS).then(function (d) {
        if (!d || d.error) {
          document.getElementById('sl-st-kpis').innerHTML = '<div class="sl-err">' + esc((d && d.error) || 'нет данных') + '</div>';
          return;
        }
        var blocked = (d.actions && (d.actions['1'] || d.actions[1])) || 0;
        var delta = d.prev_total ? Math.round(((d.total - d.prev_total) / d.prev_total) * 100) : 0;
        document.getElementById('sl-st-kpis').innerHTML =
          kpi(fmtNum(d.total), 'Атак за период',
              'Только реальные атаки из журнала SafeLine (детекты угроз). Служебные записи Deny/Allow/Non-Attack не считаются.') +
          kpi(fmtNum(blocked), 'Заблокировано',
              'Из них заблокировано WAF (действие Block).') +
          kpi(fmtNum(d.uniq_ips), 'Уникальных IP',
              'Число разных IP-источников атак за период.') +
          kpi((d.by_type || []).length + '', 'Типов атак',
              'Сколько различных типов атак зафиксировано: SQL Inj, XSS, Cmd Inj и другие.') +
          kpi((delta > 0 ? '+' : '') + delta + '%', 'Динамика',
              'Изменение числа атак к предыдущему такому же периоду: рост или снижение.');
        var pts = (d.timeline || []).map(function (x) {
          var ts = x.ts / (x.scale || 1);
          return { label: new Date(ts * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit' }),
                   value: x.count };
        });
        var chartOk = window.echarts && echartsLine(document.getElementById('sl-st-chart'), pts, 'атаки');
        if (!chartOk) {
          canvasLine(document.getElementById('sl-st-spark'), pts.slice(-48).map(function (p) { return p.value; }));
        }
        renderBars(document.getElementById('sl-st-types'),
          (d.by_type || []).slice(0, 8).map(function (x) { return { label: x.name || x.type, count: x.count }; }));
        renderBars(document.getElementById('sl-st-countries'),
          (d.by_country || []).slice(0, 8).map(function (x) { return { label: x.country || '—', count: x.count }; }));
        renderBars(document.getElementById('sl-st-sites'),
          (d.top_hosts || []).slice(0, 8).map(function (x) { return { label: x.host, count: x.count }; }));
        renderBars(document.getElementById('sl-st-ips'),
          (d.top_ips || []).slice(0, 8).map(function (x) { return { label: x.ip, count: x.count }; }));
        renderBars(document.getElementById('sl-st-paths'),
          (d.top_paths || []).slice(0, 8).map(function (x) { return { label: x.path, count: x.count }; }));
        renderBars(document.getElementById('sl-st-actions'),
          Object.keys(d.actions || {}).map(function (k) {
            return { label: { '1': 'Blocked', '2': 'Inspected', '3': 'Audited' }[k] || ('action ' + k), count: d.actions[k] };
          }));
      });
    }
  }

  function kpi(v, t, tip) {
    return '<div class="sl-kpi"' + (tip ? ' data-sl-tip="' + esc(tip) + '"' : '') + '>' +
      '<div class="sl-kpi-v">' + esc(v) + '</div><div class="sl-kpi-t">' + esc(t) + '</div></div>';
  }

  function kpiRaw(vhtml, t, tip) {
    return '<div class="sl-kpi"' + (tip ? ' data-sl-tip="' + esc(tip) + '"' : '') + '>' +
      '<div class="sl-kpi-v">' + vhtml + '</div><div class="sl-kpi-t">' + esc(t) + '</div></div>';
  }

  var TIP_EL = null;

  function tipShow(target) {
    var t = target && target.closest ? target.closest('[data-sl-tip]') : null;
    if (!t) return;
    var txt = t.getAttribute('data-sl-tip');
    if (!txt) return;
    if (!TIP_EL) {
      TIP_EL = el('<div id="sl-tip"></div>');
      document.body.appendChild(TIP_EL);
    }
    TIP_EL.textContent = txt;
    TIP_EL.classList.add('on');
    var r = t.getBoundingClientRect();
    var w = TIP_EL.offsetWidth, h = TIP_EL.offsetHeight;
    var left = Math.min(window.innerWidth - w - 10, Math.max(10, r.left + r.width / 2 - w / 2));
    var top = r.top - h - 8;
    if (top < 8) top = r.bottom + 8;
    TIP_EL.style.left = Math.round(left) + 'px';
    TIP_EL.style.top = Math.round(top) + 'px';
  }

  function tipHide(e) {
    if (!TIP_EL) return;
    if (e && e.target && e.target.closest && e.target.closest('[data-sl-tip]')) {
      TIP_EL.classList.remove('on');
    } else if (!e) {
      TIP_EL.classList.remove('on');
    }
  }

  function tipInit() {
    if (document.body.__slTipInit) return;
    document.body.__slTipInit = true;
    document.addEventListener('mouseover', function (e) { tipShow(e.target); });
    document.addEventListener('mouseout', function (e) { if (e.target.closest && e.target.closest('[data-sl-tip]')) tipHide(); });
    document.addEventListener('touchstart', function (e) { tipShow(e.target); setTimeout(tipHide, 2600); }, { passive: true });
    document.addEventListener('scroll', function () { tipHide(); }, true);
  }

  /* --------------------------- pro boards (traffic) --------------------------- */

  var TRAFFIC = null, TRAFFIC_AT = 0;

  function barsHtml(rows) {
    var max = (rows || []).reduce(function (m, r) { return Math.max(m, r.count || 0); }, 1);
    return '<div class="sl-bars">' + ((rows || []).map(function (r) {
      var w = Math.round(((r.count || 0) / max) * 100);
      return '<div class="sl-bar"><div class="sl-bar-label">' + esc(r.label) + '</div>' +
        '<div class="sl-bar-track"><div class="sl-bar-fill" style="width:' + w + '%"></div></div>' +
        '<div class="sl-bar-val">' + fmtNum(r.count) + '</div></div>';
    }).join('') || '<div class="sl-hint">Нет данных</div>') + '</div>';
  }

  function tableHtml(headers, rows) {
    return '<table class="sl-table"><tr>' + headers.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') + '</tr>' +
      (rows.map(function (r) {
        return '<tr>' + r.map(function (c) { return '<td>' + esc(c) + '</td>'; }).join('') + '</tr>';
      }).join('') || '<tr><td colspan="' + headers.length + '" class="sl-hint">Нет данных</td></tr>') + '</table>';
  }

  function loadTraffic(cb) {
    var now = Date.now();
    if (TRAFFIC && now - TRAFFIC_AT < 60000) return cb(TRAFFIC);
    api('/api/traffic?hours=24').then(function (d) {
      if (d && d.ok) { TRAFFIC = d; TRAFFIC_AT = now; }
      cb(TRAFFIC);
    });
  }

  function fillPb(idx, box, d) {
    if (!d) { box.innerHTML = '<div class="sl-err">Нет данных</div>'; return; }
    var total = d.total || 1;
    if (idx === 1) {
      box.innerHTML = '<div class="sl-sub">Браузеры</div>' + barsHtml((d.browsers || []).map(function (x) { return { label: x.name, count: x.count }; })) +
        '<div class="sl-sub">Устройства</div>' + barsHtml((d.devices || []).map(function (x) { return { label: x.name, count: x.count }; })) +
        '<div class="sl-sub">ОС</div>' + barsHtml((d.os || []).map(function (x) { return { label: x.name, count: x.count }; }));
    } else if (idx === 2) {
      var c = d.status_classes || {};
      box.innerHTML = '<div class="sl-sub">Классы ответов</div>' +
        barsHtml(['2xx', '3xx', '4xx', '5xx'].map(function (k) { return { label: k + ' (' + Math.round((c[k] || 0) * 100 / total) + '%)', count: c[k] || 0 }; })) +
        '<div class="sl-sub">Коды</div>' +
        barsHtml(((d.simple || {}).status_by_name || []).slice(0, 6).map(function (x) { return { label: 'HTTP ' + x.code, count: x.count }; }));
    } else if (idx === 3) {
      box.innerHTML = '<div class="sl-sub">Переходы (Referer)</div>' +
        tableHtml(['Источник', 'Страница', 'Запросов'], (d.referers || []).map(function (x) {
          return [x.host || 'direct', x.path || '/', fmtNum(x.count)];
        }));
    } else if (idx === 4) {
      box.innerHTML = '<div class="sl-sub">Домены</div>' +
        barsHtml((d.hosts || []).map(function (x) { return { label: x.host, count: x.count }; })) +
        '<div class="sl-sub">Популярные страницы</div>' +
        tableHtml(['Метод', 'Путь', 'Запросов'], (d.paths || []).map(function (x) {
          return [x.method, x.path, fmtNum(x.count)];
        }));
    }
    box.insertAdjacentHTML('beforeend',
      '<div class="sl-hint">Всего запросов за период: ' + fmtNum(d.total) + '</div>');
  }

  function renderProBoards(ctx) {
    var imgs = ctx.querySelectorAll('img[data-sl-src*="pro_board"], img[src*="pro_board"]');
    for (var i = 0; i < imgs.length; i++) {
      (function (img) {
        var src = img.getAttribute('data-sl-src') || img.getAttribute('src') || '';
        var m = /pro_board_(\d)/.exec(src);
        if (!m) return;
        var idx = parseInt(m[1], 10);
        var paper = img.closest('.MuiPaper-root') || img.parentElement;
        if (!paper || paper.querySelector('#sl-pb-' + idx)) return;
        var box = el('<div class="sl-proboard" id="sl-pb-' + idx + '"><div class="sl-hint">Загрузка…</div></div>');
        img.parentNode.replaceChild(box, img);
        loadTraffic(function (d) {
          if (document.getElementById('sl-pb-' + idx) !== box) return;
          fillPb(idx, box, d);
        });
      })(imgs[i]);
    }
  }

  /* --------------------------- security posture boards --------------------------- */

  var SEC = null, SEC_AT = 0;

  function secData(cb) {
    var now = Date.now();
    if (SEC && now - SEC_AT < 60000) return cb(SEC);
    api('/api/security?hours=24').then(function (d) {
      if (d && d.ok) { SEC = d; SEC_AT = now; }
      cb(SEC);
    });
  }

  var SEC_NAMES = {
    'rate limiting trends': 'rate_limit',
    'waiting room trends': 'waiting_room',
    'auth trends': 'auth',
    'allow & deny rule hit': 'acl_rule',
    'attacked pages': 'pages',
    'attacked applications': 'apps'
  };

  function fillSec(key, box, d) {
    if (key === 'waiting_room') {
      box.innerHTML = '<div class="sl-hint">Загрузка…</div>';
      api('/api/waiting').then(function (w) {
        if (!w || !w.ok) { box.innerHTML = '<div class="sl-hint">Нет данных</div>'; return; }
        var last = (w.stats && w.stats.history && w.stats.history[0]) || null;
        if (!last) { box.innerHTML = '<div class="sl-hint">Не использовался</div>'; return; }
        var when = last.started_at
          ? new Date(last.started_at * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
          : '—';
        box.innerHTML = '<div class="sl-hint">Последняя: ' + esc(when) +
          ' · прошло ' + fmtNum(last.total_waiting || 0) +
          ' · пик ' + fmtNum(last.top_waiting || 0) +
          ' · ср. ' + fmtNum(last.avg_wait_sec || 0) + ' с</div>';
      });
      return;
    }
    if (!d) { box.innerHTML = '<div class="sl-err">Нет данных</div>'; return; }
    if (key === 'pages') {
      box.innerHTML = '<div class="sl-sub">Цели атак (URL)</div>' +
        barsHtml((d.pages || []).map(function (x) { return { label: x.path, count: x.count }; }));
      return;
    }
    if (key === 'apps') {
      box.innerHTML = '<div class="sl-sub">Атакованные приложения</div>' +
        barsHtml((d.apps || []).map(function (x) { return { label: x.host, count: x.count }; }));
      return;
    }
    if (key === 'acl_rule') {
      var ar = d.acl_rule || { total: 0, rules: [], timeline: [] };
      if (!ar.total) {
        box.innerHTML = '<div class="sl-hint">Срабатываний правил за период нет</div>';
        return;
      }
      box.innerHTML = '<div class="sl-kpi-inline">Срабатываний правил: <b>' + fmtNum(ar.total || 0) + '</b></div>' +
        '<canvas class="sl-sec-spark" style="width:100%;height:44px"></canvas>' +
        '<div class="sl-sub">Правила</div>' +
        barsHtml((ar.rules || []).map(function (x) { return { label: x.rule, count: x.count }; }));
      var c1 = box.querySelector('canvas');
      if (c1) canvasLine(c1, (ar.timeline || []).map(function (x) { return x.count; }));
      return;
    }
    var cat = d[key] || { total: 0, top_ips: [], timeline: [] };
    if (!cat.total) {
      box.innerHTML = '<div class="sl-hint">Событий за период нет</div>';
      return;
    }
    box.innerHTML = '<div class="sl-kpi-inline">Всего: <b>' + fmtNum(cat.total || 0) + '</b></div>' +
      '<canvas class="sl-sec-spark" style="width:100%;height:44px"></canvas>' +
      '<div class="sl-sub">Топ IP</div>' +
      barsHtml((cat.top_ips || []).map(function (x) { return { label: x.ip, count: x.count }; }));
    var c2 = box.querySelector('canvas');
    if (c2) canvasLine(c2, (cat.timeline || []).map(function (x) { return x.count; }));
  }

  function renderSecurityBoards(ctx) {
    if (location.pathname.indexOf('/statistics/security') !== 0) return;
    var cards = [];
    ctx.querySelectorAll('.MuiPaper-root').forEach(function (card) {
      var key = null, titleEl = null;
      card.querySelectorAll('*').forEach(function (e) {
        if (key || e.children.length > 1) return;
        var t = (e.textContent || '').trim().toLowerCase();
        if (SEC_NAMES[t]) { key = SEC_NAMES[t]; titleEl = e; }
      });
      if (!key || card.querySelector('#sl-sec-' + key)) return;
      cards.push({ card: card, key: key, titleEl: titleEl });
    });
    if (!cards.length) return;
    secData(function (d) {
      cards.forEach(function (item) {
        var card = item.card;
        if (card.querySelector('#sl-sec-' + item.key)) return;
        card.querySelectorAll('img').forEach(function (im) {
          var src = im.getAttribute('data-sl-src') || im.getAttribute('src') || '';
          if (/pro-logo|empty-|empty-pro/i.test(src)) im.style.display = 'none';
        });
        card.querySelectorAll('*').forEach(function (e) {
          if (e.children.length === 0 && /^pro only$/i.test((e.textContent || '').trim())) e.style.display = 'none';
        });
        var header = item.titleEl.closest('.MuiBox-root') || item.titleEl.parentElement;
        var hdrTop = header;
        while (hdrTop && hdrTop.parentElement !== card) hdrTop = hdrTop.parentElement;
        Array.prototype.slice.call(card.children).forEach(function (ch) {
          if (ch !== hdrTop) ch.style.display = 'none';
        });
        var box = el('<div class="sl-secbox" id="sl-sec-' + item.key + '"></div>');
        if (hdrTop && hdrTop.parentElement === card) card.insertBefore(box, hdrTop.nextSibling);
        else card.appendChild(box);
        fillSec(item.key, box, d);
      });
    });
  }

  /* ------------------------------ geo blocking ------------------------------ */

  function renderGeoCard(host) {
    if (document.getElementById('sl-geo-sec') || !host) return;
    api('/api/geo').then(function (d) {
      if (!d.ok) return;
      if (document.getElementById('sl-geo-sec')) return;
      var g = d.geo || {};
      var selected = (d.selected || []).map(function (s) {
        return '<span class="sl-chip" data-cc="' + esc(s.code) + '">' + esc(s.code) + ' · ' + esc(s.name) +
          ' <b>' + esc(s.cidrs) + '</b><i data-sl-chip-x>&times;</i></span>';
      }).join('') || '<span class="sl-hint">Страны не выбраны</span>';
      var card = el('<div class="sl-card" id="sl-geo-sec">' +
        '<div class="sl-card-title">Гео-блокировка <span class="sl-badge">SLExt</span></div>' +
        '<div class="sl-hint">Блокировка или белый список по странам (данные ipdeny). Применяется ко всем сайтам SafeLine. После изменений нажмите «Синхронизировать» — списки CIDR скачаются и применятся.</div>' +
        '<div class="sl-row"><label><input type="checkbox" id="sl-geo-on"' + (g.enabled ? ' checked' : '') + '> включено</label>' +
        '<label>Режим</label><select class="sl-input" id="sl-geo-mode">' +
        '<option value="block"' + (g.mode !== 'allow' ? ' selected' : '') + '>Блокировать выбранные</option>' +
        '<option value="allow"' + (g.mode === 'allow' ? ' selected' : '') + '>Разрешать только выбранные</option>' +
        '</select>' +
        '<input class="sl-input" id="sl-geo-add" list="sl-geo-list" placeholder="Код страны, напр. RU">' +
        '<datalist id="sl-geo-list">' +
        Object.keys(d.countries || {}).map(function (c) { return '<option value="' + esc(c) + '">' + esc(d.countries[c]) + '</option>'; }).join('') +
        '</datalist>' +
        '<button class="sl-btn" id="sl-geo-add-btn">+ страна</button></div>' +
        '<div class="sl-chips" id="sl-geo-chips">' + selected + '</div>' +
        '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-geo-save">Сохранить</button>' +
        '<button class="sl-btn" id="sl-geo-sync">Синхронизировать списки</button></div>' +
        (g.last_error ? '<div class="sl-err">' + esc(g.last_error) + '</div>' : '') +
        '<div class="sl-hint sl-mono" id="sl-geo-out">Обновлено: ' + (g.updated_at ? fmtTime(g.updated_at) : '—') + '</div>' +
        '</div>');
      host.appendChild(card);
      lockBtn(card, 'sl-geo-add-btn', 'geo.edit');
      lockBtn(card, 'sl-geo-save', 'geo.edit');
      lockBtn(card, 'sl-geo-sync', 'geo.edit');
      var cc = (g.countries || []).slice();
      card.addEventListener('click', function (e) {
        if (e.target.hasAttribute && e.target.hasAttribute('data-sl-chip-x')) {
          var chip = e.target.closest('[data-cc]');
          if (chip) {
            cc = cc.filter(function (x) { return x !== chip.getAttribute('data-cc'); });
            chip.remove();
          }
          return;
        }
        if (e.target.id === 'sl-geo-add-btn') {
          var v = (document.getElementById('sl-geo-add').value || '').trim().toUpperCase();
          if (/^[A-Z]{2}$/.test(v) && cc.indexOf(v) < 0) {
            cc.push(v);
            var names = d.countries || {};
            document.getElementById('sl-geo-chips').insertAdjacentHTML('beforeend',
              '<span class="sl-chip" data-cc="' + v + '">' + v + ' · ' + esc(names[v] || v) + ' <b>0</b> <i data-sl-chip-x>&times;</i></span>');
            document.getElementById('sl-geo-add').value = '';
          } else {
            toast('Введите двухбуквенный код страны', true);
          }
          return;
        }
        if (e.target.id === 'sl-geo-save') {
          api('/api/geo', { method: 'POST', body: { geo: {
            enabled: document.getElementById('sl-geo-on').checked,
            mode: document.getElementById('sl-geo-mode').value,
            countries: cc
          } } }).then(function (r) { toast(r.ok ? 'Гео-настройки сохранены' : 'Ошибка', !r.ok); });
          return;
        }
        if (e.target.id === 'sl-geo-sync') {
          var out = document.getElementById('sl-geo-out');
          out.textContent = 'Скачиваю списки CIDR и применяю...';
          api('/api/geo/sync', { method: 'POST', body: { countries: cc } }).then(function (r) {
            var f = Object.keys(r.fetched || {}).length;
            var fa = Object.keys(r.failed || {});
            out.textContent = (r.ok ? 'Применено' : 'Ошибка') + '. Стран загружено: ' + f +
              (fa.length ? ('. Не удалось: ' + fa.join(', ')) : '') +
              (r.apply && r.apply.cidrs !== undefined ? ('. CIDR: ' + r.apply.cidrs) : '');
            toast(r.ok ? 'Гео-блокировка применена' : 'Ошибка применения', !r.ok);
          });
        }
      });
    });
  }

  /* ------------------------------ custom page ------------------------------ */

  /* ------------------------------ error pages ------------------------------ */

  var PAGE_ORDER = ['403', '404', '429', '466', '502', '504'];
  var PAGE_LABELS = {
    '403': '403 · Заблокировано', '404': '404 · Не найдено', '429': '429 · Лимит запросов',
    '465': '465 · Зал ожидания', '466': '466 · Обслуживание', '502': '502 · Сервис недоступен',
    '504': '504 · Таймаут'
  };

  function renderPageCard(host) {
    if (document.getElementById('sl-page-sec') || !host) return;
    api('/api/page').then(function (d) {
      if (!d.ok) return;
      if (document.getElementById('sl-page-sec')) return;
      var p = d.page || {};
      var pages = p.pages || {};
      var rows = PAGE_ORDER.filter(function (c) { return pages[c]; }).map(function (code) {
        var x = pages[code];
        return '<tr>' +
          '<td><input type="checkbox" data-pg-en="' + code + '"' + (x.enabled ? ' checked' : '') + '></td>' +
          '<td class="sl-mono">' + esc(PAGE_LABELS[code] || code) + '</td>' +
          '<td><input class="sl-input" data-pg-title="' + code + '" value="' + esc(x.title) + '"></td>' +
          '<td><input class="sl-input sl-wide" data-pg-msg="' + code + '" value="' + esc(x.message) + '"></td>' +
          '<td><button class="sl-btn" data-pg-prev="' + code + '">Превью</button></td></tr>';
      }).join('');
      var card = el('<div class="sl-card" id="sl-page-sec">' +
        '<div class="sl-card-title">Страницы ошибок <span class="sl-badge">SLExt</span></div>' +
        '<div class="sl-hint">Заменяют стандартные страницы SafeLine (403 · 404 · 429 · 465 · 466 · 502 · 504) на свои и работают вместо заблокированного раздела Blocking Pages → Custom HTML. Применяется ко всем сайтам.</div>' +
        '<div class="sl-row"><label><input type="checkbox" id="sl-pg-en"' + (p.enabled ? ' checked' : '') + '> включено</label>' +
        '<label>Бренд</label><input class="sl-input" id="sl-pg-brand" value="' + esc(p.brand) + '">' +
        '<label>Цвет</label><input class="sl-input sl-w" id="sl-pg-color" value="' + esc(p.color) + '"></div>' +
        '<table class="sl-table"><tr><th>Вкл</th><th>Код</th><th>Заголовок</th><th>Текст</th><th></th></tr>' + rows + '</table>' +
        '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-pg-save">Сохранить и применить</button></div></div>');
      host.appendChild(card);
      lockBtn(card, 'sl-pg-save', 'pages.edit');
      card.addEventListener('click', function (e) {
        var code = e.target.getAttribute && e.target.getAttribute('data-pg-prev');
        if (code) {
          var w = window.open('', '_blank');
          api('/api/page', { method: 'POST', body: { preview: 1, code: code, page: collectPage() } })
            .then(function (d2) { if (w && d2 && d2.html) { w.document.write(d2.html); w.document.close(); } });
          return;
        }
        if (e.target.id === 'sl-pg-save') {
          api('/api/page', { method: 'POST', body: { page: collectPage() } })
            .then(function (r) { toast(r.ok ? 'Страницы применены' : ('Ошибка: ' + (r.info || '')), !r.ok); });
        }
      });
    });

    function collectPage() {
      var pages = {};
      PAGE_ORDER.forEach(function (code) {
        var on = document.querySelector('[data-pg-en="' + code + '"]');
        if (!on) return;
        pages[code] = {
          enabled: on.checked,
          title: ((document.querySelector('[data-pg-title="' + code + '"]') || {}).value || ''),
          message: ((document.querySelector('[data-pg-msg="' + code + '"]') || {}).value || '')
        };
      });
      return {
        enabled: !!((document.getElementById('sl-pg-en') || {}).checked),
        brand: ((document.getElementById('sl-pg-brand') || {}).value || 'SafeLine'),
        color: ((document.getElementById('sl-pg-color') || {}).value || '#0fc6c2'),
        pages: pages
      };
    }
  }

  /* --------------------------- skip decryption --------------------------- */

  function renderSkipCard(host) {
    if (document.getElementById('sl-skip-sec') || !host) return;
    api('/api/skip').then(function (d) {
      if (!d || !d.ok || document.getElementById('sl-skip-sec')) return;
      var on = !!(d.skip && d.skip.enabled);
      var card = el('<div class="sl-card" id="sl-skip-sec">' +
        '<div class="sl-card-title">Skip decryption page <span class="sl-badge">SLExt</span></div>' +
        '<div class="sl-hint">Наш аналог Pro-функции. Первый заход — мгновенная проверка (без страницы расшифровки и без document.write), дальше сайт отдаётся сразу. Работает на всех устройствах, защита сохраняется.</div>' +
        '<div class="sl-row"><label><input type="checkbox" id="sl-skip-on"' + (on ? ' checked' : '') + '> включено</label>' +
        '<span class="sl-badge" id="sl-skip-st">' + (on ? 'включено' : 'выключено') + '</span>' +
        '<button class="sl-btn sl-btn-pri" id="sl-skip-save">Применить</button></div></div>');
      host.appendChild(card);
      lockBtn(card, 'sl-skip-save', 'skip.control');
      card.addEventListener('click', function (e) {
        if (e.target.id !== 'sl-skip-save') return;
        api('/api/skip', { method: 'POST', body: { skip: { enabled: document.getElementById('sl-skip-on').checked } } })
          .then(function (r) {
            var st = document.getElementById('sl-skip-st');
            if (st) st.textContent = document.getElementById('sl-skip-on').checked ? 'включено' : 'выключено';
            toast(r.ok ? 'Skip decryption: применено' : ('Ошибка: ' + (r.info || '')), !r.ok);
          });
      });
    });
  }

  /* --------------------------- sites / bot / auth / pro pages --------------------------- */

  function fixDashError(ctx) {
    if (location.pathname.indexOf('/business_dashboard') !== 0) { removeSection('sl-dash-fix'); return; }
    var up = findByTextDeep(ctx, 'unexpected application error', '#sl-dash-fix');
    if (!up) { removeSection('sl-dash-fix'); return; }
    if (document.getElementById('sl-dash-fix')) return;
    var box = up.closest('[class*="MuiPaper"],[class*="MuiBox"]') || up.parentElement;
    if (box && box !== document.body) box.style.display = 'none';
    var card = el('<div class="sl-card" id="sl-dash-fix">' +
      '<div class="sl-card-title">Pro-дашборд недоступен <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Раздел SafeLine требует Pro-лицензию и в CE падает. Используйте наш дашборд: Statistics → TRAFFIC ANALYSIS / SECURITY POSTURE.</div></div>');
    document.body.appendChild(card);
  }

  /* --------------------------- bot protect dialog --------------------------- */

  function hideRowByText(dlg, text) {
    var elx = findByTextDeep(dlg, text, '#sl-dlg-skip');
    if (!elx) return null;
    var row = elx;
    while (row && row.parentElement && row.parentElement !== dlg) {
      if (row.querySelector && row.querySelector('[class*="MuiSwitch"],[type="checkbox"]')) break;
      row = row.parentElement;
    }
    if (row && row.style) {
      row.style.display = 'none';
      row.setAttribute('data-sl-hidden', '1');
      return row;
    }
    return elx;
  }

  function renderBotDialog(dlg) {
    var stock = findByTextDeep(dlg, 'skip decryption page', '#sl-dlg-skip');
    if (!stock) { removeSection('sl-dlg-skip'); return; }
    var row = hideRowByText(dlg, 'skip decryption page');
    hideRowByText(dlg, 'js dynamic encryption');
    hideRowByText(dlg, 'picture dynamic watermark');
    hideRowByText(dlg, 'anti-replay');
    if (document.getElementById('sl-dlg-skip')) return;
    api('/api/skip').then(function (d) {
      if (document.getElementById('sl-dlg-skip') || !document.body.contains(dlg)) return;
      var on = !!(d && d.ok && d.skip && d.skip.enabled);
      var node = el('<div class="sl-row" id="sl-dlg-skip" style="padding:6px 0">' +
        '<label style="display:flex;align-items:center;gap:8px;font-size:14px">' +
        '<input type="checkbox" id="sl-dlg-skip-on"' + (on ? ' checked' : '') + '> Skip decryption page ' +
        '<span class="sl-badge">SLExt</span></label>' +
        '<span class="sl-badge" id="sl-dlg-skip-st">' + (on ? 'включено' : 'выключено') + '</span>' +
        '<span class="sl-hint" style="margin:0">наш аналог Pro: мгновенный пропуск для прошедших расшифровку</span></div>');
      if (row && row.parentElement) row.parentElement.insertBefore(node, row.nextSibling);
      else dlg.appendChild(node);
      node.addEventListener('change', function (e) {
        if (e.target.id !== 'sl-dlg-skip-on') return;
        api('/api/skip', { method: 'POST', body: { skip: { enabled: e.target.checked } } })
          .then(function (r) {
            var st = document.getElementById('sl-dlg-skip-st');
            if (st) st.textContent = e.target.checked ? 'включено' : 'выключено';
            toast(r.ok ? 'Skip decryption: применено' : ('Ошибка: ' + (r.info || '')), !r.ok);
          });
      });
    });
  }

  /* ------------------------------ waiting room ------------------------------ */

  function wrKpis(stats) {
    var agg = (stats && stats.agg) || {};
    return kpi(fmtNum(agg.sessions || 0), 'активаций за 30 дней',
        'Сколько раз зал ожидания включался за последние 30 дней.') +
      kpi(fmtNum(agg.entered || agg.total_queued || 0), 'встали в очередь',
        'Все посетители, которым показали страницу очереди за 30 дней.') +
      kpi(fmtNum(agg.served || 0), 'обслужено (прошли)',
        'Из них дождались и были пропущены на сайт.') +
      kpi(fmtNum(agg.peak || 0), 'пик очереди',
        'Максимум одновременно ожидающих за одну активацию.') +
      kpi((agg.avg_wait_sec || 0) + ' с', 'средний wait обслуженных',
        'Среднее время ожидания тех, кто дождался: общее время ожидания / число обслуженных.') +
      kpi(Math.round((agg.bounce_rate || 0) * 100) + '%', 'ушли, не дождавшись',
        'Доля посетителей, закрывших страницу очереди, не дождавшись (bounce rate).');
  }

  function wrHistoryHtml(history) {
    var rows = (history || []).slice(0, 8).map(function (x) {
      return '<tr><td>' + esc(x.started_at ? new Date(x.started_at * 1000).toLocaleString('ru-RU') : '—') + '</td>' +
        '<td>' + fmtNum(x.dur_sec || 0) + ' с</td>' +
        '<td>' + fmtNum(x.total_waiting || 0) + '</td>' +
        '<td>' + fmtNum(x.top_waiting || 0) + '</td>' +
        '<td>' + fmtNum(x.total_serving || 0) + '</td>' +
        '<td>' + fmtNum(x.avg_wait_sec || 0) + ' с</td>' +
        '<td>' + Math.round((x.bounce_rate || 0) * 100) + '%</td></tr>';
    }).join('');
    return '<table class="sl-table"><tr><th>Начало</th><th>Длит.</th><th>В очереди</th><th>Пик</th><th>Обслужено</th><th>Сред. wait</th><th>Отказы</th></tr>' +
      (rows || '<tr><td colspan="7" class="sl-hint">Активаций ещё не было</td></tr>') + '</table>';
  }

  function renderWaitingCard(host) {
    if (document.getElementById('sl-wr-sec') || !host) return;
    api('/api/waiting').then(function (d) {
      if (!d || !d.ok || document.getElementById('sl-wr-sec')) return;
      var cfg = d.cfg || {};
      var page = cfg.page || {}, sch = cfg.schedule || {}, au = cfg.auto || {}, nf = cfg.notify || {}, st = cfg.state || {};
      var aru = cfg.auto_run || {}, alog = cfg.auto_log || [];
      var liveNote = (d.live_rate === null || d.live_rate === undefined) ? '—' : (esc(d.live_rate) + ' зап/мин');
      var autoLive = 'Сейчас: ' + liveNote +
        '. Последняя проверка: ' + (aru.last_eval ? new Date(aru.last_eval * 1000).toLocaleTimeString('ru-RU') : 'ещё не было') +
        (aru.rate !== undefined ? (', тогда трафик ' + esc(aru.rate) + ' зап/мин') : '') +
        (aru.above !== undefined ? (', счётчики: выше порога ' + esc(aru.above) + '/' + esc(au.hold || 3) +
                                    ', ниже ' + esc(aru.below) + '/' + esc(au.hold_off || 4)) : '') + '.';
      var autoLogHtml = alog.length
        ? ('<div class="sl-sub">Журнал авто-режима</div><table class="sl-table"><tr><th>Время</th><th>Трафик</th><th>Решение</th><th>Причина</th></tr>' +
           alog.slice(0, 10).map(function (x) {
             var act = x.action === 'on' ? '<b class="sl-err">включил</b>' :
                       (x.action === 'off' ? '<b>выключил</b>' : 'ждёт');
             return '<tr><td>' + (x.ts ? new Date(x.ts * 1000).toLocaleTimeString('ru-RU') : '—') + '</td>' +
               '<td>' + esc(x.rate) + ' зап/мин</td><td>' + act + '</td><td>' + esc(x.reason) + '</td></tr>';
           }).join('') + '</table>')
        : '<div class="sl-hint">Журнал авто-режима пуст (авто выключено или ещё не было проверок).</div>';
      var mgt = d.mgt || {};
      var sites = (d.sites || []).map(function (s) {
        var h = (s.hosts || [''])[0];
        return '<option value="' + esc(h) + '"' + (h === d.host ? ' selected' : '') + '>' + esc(h || ('#' + s.id)) + '</option>';
      }).join('');
      var dayNames = [['1', 'Пн'], ['2', 'Вт'], ['3', 'Ср'], ['4', 'Чт'], ['5', 'Пт'], ['6', 'Сб'], ['7', 'Вс']];
      var days = dayNames.map(function (x) {
        return '<label><input type="checkbox" data-wr-day="' + x[0] + '"' +
          ((sch.days || []).indexOf(parseInt(x[0], 10)) >= 0 ? ' checked' : '') + '> ' + x[1] + '</label>';
      }).join(' ');
      var srcNames = { auto: 'авто по нагрузке', schedule: 'расписание', manual: 'вручную', 'manual-retry': 'вручную (повтор)' };
      var src = srcNames[st.source] || 'вручную';
      var last = (d.stats && d.stats.history && d.stats.history[0]) || null;
      var wrStatus = (mgt.is_enabled ? 'включён' : 'выключен');
      var wrLast = last
        ? ('последняя активация ' + new Date(last.started_at * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }))
        : 'активаций не было';
      var wrOpen = ' open';
      var card = el('<div class="sl-card" id="sl-wr-sec">' +
        '<details class="sl-details"' + wrOpen + '><summary><b>Зал ожидания</b> <span class="sl-badge">SLExt</span> ' +
        '<span class="sl-hint" style="display:inline;margin:0">' + esc(wrStatus + ' · ' + wrLast) + '</span></summary>' +
        '<div class="sl-hint">Лимиты CE: порог ' + esc(mgt.max_concurrent || '-') +
        ', таймаут ' + esc(mgt.session_timeout || '-') + ' с. Страница очереди — наша, с живой позицией.</div>' +
        '<div class="sl-row"><label>Сайт</label><select class="sl-input" id="sl-wr-site">' + sites + '</select>' +
        '<span class="sl-badge" id="sl-wr-status">' + (mgt.is_enabled ? 'включён' : 'выключен') + '</span>' +
        '<span class="sl-hint">источник: ' + esc(src) + '</span>' +
        '<button class="sl-btn sl-btn-pri" id="sl-wr-toggle">' + (mgt.is_enabled ? 'Выключить' : 'Включить') + '</button>' +
        '<button class="sl-btn" id="sl-wr-refresh">Обновить</button></div>' +
        '<div class="sl-kpis">' + wrKpis(d.stats) + '</div>' +
        '<div class="sl-sub">Активации по дням</div>' +
        barsHtml((d.stats && d.stats.timeline || []).map(function (x) {
          return { label: x.date + ' · людей ' + fmtNum(x.queued || 0), count: x.sessions || 0 };
        })) +
        '<details class="sl-details"><summary>Автоматизация: расписание, авто-режим, уведомления</summary>' +
        '<div class="sl-row"><label><input type="checkbox" id="sl-wr-sch-on"' + (sch.enabled ? ' checked' : '') + '> по расписанию</label>' + days + '</div>' +
        '<div class="sl-row"><label>с</label><input class="sl-input sl-w" id="sl-wr-from" value="' + esc(sch.from) + '">' +
        '<label>до</label><input class="sl-input sl-w" id="sl-wr-to" value="' + esc(sch.to) + '"></div>' +
        '<div class="sl-sub">Авто по нагрузке — точный алгоритм (без случайности)</div>' +
        '<div class="sl-hint">Считается реальный трафик: HTML-запросы живых посетителей (метод GET, боты и служебные пути /.safeline/ исключены) за окно, в запросах/мин. Зал включится только если: авто включено И трафик ≥ порога включения K проверок подряд И прошло ≥ «запрета» с ручного выключения. Выключится только если зал включён самим авто И трафик ≤ порога выключения M проверок подряд И зал проработал ≥ «паузы». Ручное переключение всегда приоритетнее авто (авто его не отменяет).</div>' +
        '<div class="sl-row"><label data-sl-tip="Автоматика включается только по этим правилам. Ручное переключение всегда приоритетнее."><input type="checkbox" id="sl-wr-au-on"' + (au.enabled ? ' checked' : '') + '> авто по нагрузке</label>' +
        '<label data-sl-tip="Реальный трафик живых посетителей (HTML-запросы), при котором зал может включиться, в запросах в минуту.">порог вкл, зап/мин</label><input class="sl-input sl-w" id="sl-wr-th" type="number" min="1" value="' + esc(au.threshold) + '">' +
        '<label data-sl-tip="Трафик, при котором авто-режим выключит зал, в запросах в минуту.">порог выкл, зап/мин</label><input class="sl-input sl-w" id="sl-wr-thoff" type="number" min="0" value="' + esc(au.off_threshold) + '">' +
        '<label data-sl-tip="За сколько секунд считается трафик для порога.">окно, с</label><input class="sl-input sl-w" id="sl-wr-win" type="number" min="30" value="' + esc(au.window) + '"></div>' +
        '<div class="sl-row"><label data-sl-tip="Сколько проверок подряд (проверка каждые 30 с) трафик должен держаться выше порога включения.">проверок подряд для вкл</label><input class="sl-input sl-w" id="sl-wr-au-hold" type="number" min="1" value="' + esc(au.hold || 3) + '">' +
        '<label data-sl-tip="Сколько проверок подряд трафик должен быть ниже порога выключения.">для выкл</label><input class="sl-input sl-w" id="sl-wr-au-holdoff" type="number" min="1" value="' + esc(au.hold_off || 4) + '">' +
        '<label data-sl-tip="Минимальное время работы зала, прежде чем авто-режим сможет его выключить.">пауза до авто-выкл, с</label><input class="sl-input sl-w" id="sl-wr-cd" type="number" min="30" value="' + esc(au.cooldown) + '">' +
        '<label data-sl-tip="После ручного выключения авто-режим не включит зал раньше этого времени.">запрет после ручн. выкл, с</label><input class="sl-input sl-w" id="sl-wr-au-minoff" type="number" min="0" value="' + esc(au.min_off || 600) + '"></div>' +
        '<div class="sl-hint" id="sl-wr-au-live">' + autoLive + '</div>' + autoLogHtml +
        '<div class="sl-row"><label><input type="checkbox" id="sl-wr-nf"' + (nf.enabled ? ' checked' : '') + '> уведомления</label></div>' +
        '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-wr-save-ext">Сохранить автоматизацию</button></div></details>' +
        '<details class="sl-details"><summary>Страница очереди: тексты и стиль</summary>' +
        '<div class="sl-row"><label>Заголовок</label><input class="sl-input sl-wide" id="sl-wr-p-title" value="' + esc(page.title) + '"></div>' +
        '<div class="sl-row"><label>Текст</label><input class="sl-input sl-wide" id="sl-wr-p-msg" value="' + esc(page.message) + '"></div>' +
        '<div class="sl-row"><label>Заметка</label><input class="sl-input sl-wide" id="sl-wr-p-note" value="' + esc(page.note) + '"></div>' +
        '<div class="sl-row"><label>Подпись счёта</label><input class="sl-input" id="sl-wr-p-post" value="' + esc(page.posttext) + '">' +
        '<label>Бренд</label><input class="sl-input" id="sl-wr-p-brand" value="' + esc(page.brand) + '">' +
        '<label>Цвет</label><input class="sl-input sl-w" id="sl-wr-p-color" value="' + esc(page.color) + '">' +
        '<label><input type="checkbox" id="sl-wr-p-stats"' + (page.show_stats !== false ? ' checked' : '') + '> статистика на странице</label></div>' +
        '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-wr-p-save">Сохранить страницу</button>' +
        '<button class="sl-btn" id="sl-wr-p-preview">Превью</button></div></details>' +
        '<details class="sl-details"><summary>История активаций</summary>' + wrHistoryHtml(d.stats && d.stats.history) + '</details>' +
        '</details></div>');
      host.appendChild(card);
      lockBtn(card, 'sl-wr-toggle', 'wr.control');
      lockBtn(card, 'sl-wr-save-ext', 'wr.settings');
      lockBtn(card, 'sl-wr-p-save', 'wr.settings');
      card.addEventListener('click', function (e) {
        var siteEl = document.getElementById('sl-wr-site');
        var site = siteEl ? siteEl.value : d.host;
        if (e.target.id === 'sl-wr-toggle') {
          var cur = (document.getElementById('sl-wr-status') || {}).textContent === 'включён';
          api('/api/waiting/config', { method: 'POST', body: { site: site, enabled: !cur } }).then(function (r) {
            toast(r.ok ? ('Зал ожидания ' + (!cur ? 'включён' : 'выключен')) : ('Ошибка: ' + (r.error || '')), !r.ok);
            if (r.ok) setTimeout(function () { refreshWrCard(); slStatus(); }, 900);
          });
          return;
        }
        if (e.target.id === 'sl-wr-refresh') { refreshWrCard(); return; }
        if (e.target.id === 'sl-wr-save-ext') {
          var dd = [];
          document.querySelectorAll('[data-wr-day]').forEach(function (c) { if (c.checked) dd.push(parseInt(c.getAttribute('data-wr-day'), 10)); });
          api('/api/waiting/extras', { method: 'POST', body: { site: site,
            schedule: { enabled: document.getElementById('sl-wr-sch-on').checked, days: dd,
                        from: document.getElementById('sl-wr-from').value, to: document.getElementById('sl-wr-to').value },
            auto: { enabled: document.getElementById('sl-wr-au-on').checked,
                    threshold: parseInt(document.getElementById('sl-wr-th').value, 10) || 60,
                    off_threshold: parseInt(document.getElementById('sl-wr-thoff').value, 10) || 20,
                    window: parseInt(document.getElementById('sl-wr-win').value, 10) || 60,
                    hold: parseInt(document.getElementById('sl-wr-au-hold').value, 10) || 3,
                    hold_off: parseInt(document.getElementById('sl-wr-au-holdoff').value, 10) || 4,
                    cooldown: parseInt(document.getElementById('sl-wr-cd').value, 10) || 600,
                    min_off: parseInt(document.getElementById('sl-wr-au-minoff').value, 10) || 600 },
            notify: { enabled: document.getElementById('sl-wr-nf').checked } } })
            .then(function (r) {
              toast(r.ok ? 'Автоматизация сохранена' : 'Ошибка', !r.ok);
              if (r.ok) setTimeout(function () { location.reload(); }, 600);
            });
          return;
        }
        if (e.target.id === 'sl-wr-p-save' || e.target.id === 'sl-wr-p-preview') {
          var body = { site: site, page: {
            title: document.getElementById('sl-wr-p-title').value,
            message: document.getElementById('sl-wr-p-msg').value,
            note: document.getElementById('sl-wr-p-note').value,
            posttext: document.getElementById('sl-wr-p-post').value,
            brand: document.getElementById('sl-wr-p-brand').value,
            color: document.getElementById('sl-wr-p-color').value,
            show_stats: document.getElementById('sl-wr-p-stats').checked
          } };
          if (e.target.id === 'sl-wr-p-preview') {
            var w = window.open('', '_blank');
            api('/api/waiting/page', { method: 'POST', body: Object.assign({ preview: 1 }, body) })
              .then(function (r) { if (w && r.html) { w.document.write(r.html); w.document.close(); } });
          } else {
            api('/api/waiting/page', { method: 'POST', body: body })
              .then(function (r) { toast(r.ok ? 'Страница очереди обновлена' : ('Ошибка: ' + (r.info || '')), !r.ok); });
          }
        }
      });
    });
  }

  /* ------------------------------ load test ------------------------------ */

  function ltKpis(st) {
    st = st || {};
    return kpi((st.rps !== undefined ? st.rps : '—') + '', 'устойчивый RPS',
        'Достигнутая пропускная способность на последней стадии без деградации.') +
      kpi((st.conc !== undefined ? st.conc : '—') + '', 'параллельно',
        'Число одновременных запросов, с которым выполнялась эта стадия.') +
      kpi((st.p50 !== undefined ? st.p50 : '—') + ' мс', 'p50',
        'Медианная задержка во время теста: половина запросов быстрее.') +
      kpi((st.p95 !== undefined ? st.p95 : '—') + ' мс', 'p95',
        '95-й перцентиль задержки: 95% запросов быстрее этого значения.') +
      kpi((st.err_pct !== undefined ? st.err_pct : '—') + '%', 'ошибки',
        'Доля ошибок на стадии: сбои соединения и ответы 5xx.');
  }

  function ltStagesTable(stages) {
    var rows = (stages || []).map(function (s) {
      var bad = (s.err_pct > 2 || s.p95 > 1000 || s.blocked) ? ' sl-lt-bad' : '';
      return '<tr class="' + bad + '"><td>' + s.conc + '</td><td>' + s.rps + '</td><td>' + s.p50 +
        '</td><td>' + s.p95 + '</td><td>' + s.p99 + '</td><td>' + s.err_pct + '%</td><td>' + s.blocked +
        '</td><td>' + (s.requests !== undefined ? s.requests : '—') + '</td><td>' +
        (s.dur !== undefined ? s.dur : '—') + '</td></tr>';
    }).join('');
    return '<table class="sl-table"><tr><th>Параллельно</th><th>RPS</th><th>p50, мс</th><th>p95, мс</th>' +
      '<th>p99, мс</th><th>Ошибки</th><th>Блок</th><th>Запросов</th><th>Длит, с</th></tr>' +
      (rows || '<tr><td colspan="9" class="sl-hint">Стадий пока нет</td></tr>') + '</table>';
  }

  function ltReportHtml(job) {
    var r = job.report || {};
    var rec = r.recommend || {};
    var base = r.stable || r.peak || {};
    var notes = (r.analysis || {}).notes || [];
    var tot = r.totals || {};
    var prot = r.protection || {};
    var protTxt = prot.paused
      ? ('Защита приостановлена автоматически на время теста (правил SafeLine: ' + (prot.acl_rules || 0) +
         (prot.crowdsec_bouncer ? ', CrowdSec-бансер остановлен' : '') + ') и возвращена после.')
      : (r.mode === 'origin'
          ? 'Тест шёл напрямую в бэкенд — защита не затрагивалась.'
          : 'Тест через WAF; отключение защиты было подтверждено вручную.');
    return '<div class="sl-rep">' +
      '<div class="sl-sub">Итог: ' + esc(r.verdict || 'нет данных') +
      (r.reason ? ' · ' + esc(r.reason) : '') + '</div>' +
      (tot.requests !== undefined ? ('<div class="sl-hint">Всего запросов: <b>' + fmtNum(tot.requests) +
        '</b> · ошибок: <b>' + fmtNum(tot.errors) + '</b> · блокировок: <b>' + fmtNum(tot.blocked) +
        '</b> · стадий: ' + (tot.stages || 0) + '.</div>') : '') +
      (notes.length ? ('<div class="sl-sub" data-sl-tip="Автоматический разбор результатов теста.">Анализ</div><ul class="sl-notes">' +
        notes.map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') + '</ul>') : '') +
      '<div class="sl-kpis">' + ltKpis(base) + '</div>' +
      ltStagesTable(r.stages) +
      '<div class="sl-hint" data-sl-tip="' + esc(protTxt) + '">Защита: ' + esc(protTxt) + '</div>' +
      '<div class="sl-hint">Рекомендации для зала ожидания: лимит одновременных — <b>' + esc(rec.max_concurrent) +
      '</b>, порог включения — <b>' + esc(rec.threshold) + ' зап/мин</b>, порог выключения — <b>' +
      esc(rec.off_threshold) + ' зап/мин</b>, пауза ' + esc(rec.cooldown) + ' с. ' + esc(rec.note || '') + '</div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-lt-apply">Подставить в зал ожидания</button>' +
      '<button class="sl-btn" id="sl-lt-dl">Скачать отчёт HTML</button></div></div>';
  }

  var LT_HASH = '';
  var LT_VIEW = 'last';

  function ltArchiveHtml(items) {
    if (!items || !items.length) return '<div class="sl-hint">Пока нет сохранённых отчётов — они появятся после первого теста.</div>';
    var rows = items.map(function (a) {
      var st = a.stable || {};
      var tot = a.totals || {};
      return '<tr><td>' + (a.started_at ? new Date(a.started_at * 1000).toLocaleString('ru-RU') : '—') + '</td>' +
        '<td>' + esc(a.host || '—') + '</td>' +
        '<td>' + (a.mode === 'origin' ? 'напрямую' : 'через WAF') + '</td>' +
        '<td>' + (st.rps !== undefined ? st.rps : '—') + '</td>' +
        '<td>' + (st.p95 !== undefined ? st.p95 : '—') + '</td>' +
        '<td>' + (st.err_pct !== undefined ? st.err_pct + '%' : '—') + '</td>' +
        '<td>' + (a.duration !== undefined ? a.duration + ' с' : '—') + '</td>' +
        '<td>' + (tot.blocked ? ('<span class="sl-err">' + tot.blocked + '</span>') : '0') + '</td>' +
        '<td class="sl-nowrap">' +
        '<button class="sl-btn" data-lt-arch="' + esc(a.id) + '" data-lt-act="open" title="Открыть отчёт">Открыть</button> ' +
        '<button class="sl-btn" data-lt-arch="' + esc(a.id) + '" data-lt-act="html" title="Скачать HTML">HTML</button> ' +
        '<button class="sl-btn sl-btn-x" data-lt-arch="' + esc(a.id) + '" data-lt-act="del" title="Удалить из архива"' +
        (can('lt.archive_del') ? '' : ' disabled') + '>&times;</button>' +
        '</td></tr>';
    }).join('');
    return '<table class="sl-table"><tr><th>Дата</th><th>Домен</th><th>Режим</th><th>RPS</th><th>p95, мс</th>' +
      '<th>Ошибки</th><th>Длит</th><th>Блок</th><th></th></tr>' + rows + '</table>';
  }

  function ltPoll() {
    api('/api/loadtest').then(function (d) {
      var card = document.getElementById('sl-lt-sec');
      if (!card || !d || !d.ok) return;
      var job = d.job || {};
      var sel = document.getElementById('sl-lt-host');
      if (sel && !sel.options.length && d.sites && d.sites.length) {
        d.sites.forEach(function (s) {
          (s.hosts || []).forEach(function (h) {
            if (SL_ME && SL_ME.domains && SL_ME.domains.length && SL_ME.domains.indexOf(h) < 0) return;
            var o = document.createElement('option');
            o.value = h;
            o.textContent = h + (s.comment ? (' — ' + s.comment) : '');
            sel.appendChild(o);
          });
        });
        if ((job.params || {}).host) sel.value = job.params.host;
      }
      var h = [job.status, job.id, (job.stages || []).length, (job.progress || {}).stage,
               job.error || '', (job.report || {}).finished_at, (d.archive || []).length].join('|');
      if (h === LT_HASH) return;
      LT_HASH = h;
      var runBtn = document.getElementById('sl-lt-run');
      var stopBtn = document.getElementById('sl-lt-stop');
      var stateEl = document.getElementById('sl-lt-state');
      var liveEl = document.getElementById('sl-lt-live');
      var repEl = document.getElementById('sl-lt-report');
      var archEl = document.getElementById('sl-lt-archive');
      var running = job.status === 'running';
      if (runBtn) runBtn.style.display = running ? 'none' : '';
      if (stopBtn) stopBtn.style.display = running ? '' : 'none';
      if (stateEl) {
        stateEl.textContent = running
          ? ('идёт: стадия ' + ((job.progress || {}).stage || 1) + ', параллельно ' + ((job.progress || {}).conc || 1) +
             ', прошло ' + ((job.progress || {}).elapsed || 0) + ' с')
          : (job.status === 'error' ? ('ошибка: ' + (job.error || '')) : '');
      }
      if (liveEl) {
        liveEl.innerHTML = running
          ? ('<div class="sl-sub">Промежуточно</div>' + ltStagesTable(job.stages))
          : '';
      }
      if (repEl && LT_VIEW === 'last') repEl.innerHTML = job.report ? ltReportHtml(job) : '';
      if (archEl) archEl.innerHTML = ltArchiveHtml(d.archive || []);
    });
  }

  function renderLoadTestCard(host) {
    if (document.getElementById('sl-lt-sec')) { ltPoll(); return; }
    if (!host) return;
    var card = el('<div class="sl-card" id="sl-lt-sec">' +
      '<div class="sl-card-title">Тест ёмкости сайта — адаптивный <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-warn" id="sl-lt-warn"><b>Защиту отключать не нужно.</b> По умолчанию тест идёт <b>напрямую в бэкенд</b> (в обход WAF): измеряется чистая ёмкость приложения, SafeLine, CrowdSec и Anti-Bot не мешают и не трогаются.' +
      '<span id="sl-lt-warnwaf" style="display:none"><br><b>Внимание:</b> выбран режим через WAF. Чтобы защита не резала тест, включите авто-паузу ниже — защита будет автоматически приостановлена на время теста (частотные правила SafeLine + CrowdSec-бансер) и возвращена сразу после. Либо подтвердите, что отключили её вручную.</span>' +
      '<label id="sl-lt-ackrow" style="display:none"><input type="checkbox" id="sl-lt-ack"> Я отключил(а) защиту вручную на время теста</label>' +
      '<label id="sl-lt-pauserow" style="display:none"><input type="checkbox" id="sl-lt-autopause" checked> Автоматически приостановить защиту на время теста и вернуть после (рекомендуется)</label></div>' +
      '<div class="sl-row"><label>Домен</label><select class="sl-input" id="sl-lt-host"></select>' +
      '<label data-sl-tip="Путь сайта, который нагружается, например / или /catalog.">Путь</label><input class="sl-input sl-w" id="sl-lt-path" value="/">' +
      '<label data-sl-tip="Напрямую в бэкенд — чистая ёмкость приложения, защита не мешает (по умолчанию). Через WAF — боевой путь WAF+сайт; защита приостанавливается автоматически.">Режим</label><select class="sl-input" id="sl-lt-mode">' +
      '<option value="origin" selected>напрямую в бэкенд (защита не мешает)</option><option value="waf">через WAF (боевой путь, нужна пауза защиты)</option></select></div>' +
      '<div class="sl-row"><label data-sl-tip="Верхний предел одновременных запросов. При достижении тест остановится.">макс. параллельно</label><input class="sl-input sl-w" id="sl-lt-conc" type="number" min="1" max="128" value="48">' +
      '<label data-sl-tip="Длительность замера на каждой ступени нагрузки.">стадия, с</label><input class="sl-input sl-w" id="sl-lt-stage" type="number" min="3" max="30" value="6">' +
      '<label data-sl-tip="Порог деградации: если 95-й перцентиль задержки превысит это значение, тест остановится.">стоп при p95, мс</label><input class="sl-input sl-w" id="sl-lt-p95" type="number" min="200" value="1500">' +
      '<label data-sl-tip="Доля ошибок, при которой тест остановится.">стоп при ошибках, %</label><input class="sl-input sl-w" id="sl-lt-err" type="number" min="0.5" step="0.5" value="3">' +
      '<label data-sl-tip="Общий предохранитель: тест остановится не позже этого времени.">лимит времени, с</label><input class="sl-input sl-w" id="sl-lt-total" type="number" min="30" max="600" value="240"></div>' +
      '<div class="sl-hint">Алгоритм: стадии с ростом параллельных запросов (1 → 2 → 4 → …), на каждой замеряются RPS, p50/p95/p99, ошибки и блокировки. ' +
      'Тест останавливается при деградации (p95 выше порога или ошибок больше нормы), при блокировке защитой, на плато RPS или по лимиту времени. ' +
      'Отчёт с подробным анализом сохраняется в архив ниже.</div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-lt-run">Запустить тест</button>' +
      '<button class="sl-btn" id="sl-lt-stop" style="display:none">Остановить</button>' +
      '<span class="sl-hint" id="sl-lt-state"></span></div>' +
      '<div id="sl-lt-live"></div><div id="sl-lt-report"></div>' +
      '<div class="sl-sub" data-sl-tip="Последние 10 тестов хранятся на сервере: можно открыть отчёт, скачать HTML или удалить запись.">Архив тестов (последние 10)</div>' +
      '<div id="sl-lt-archive"><div class="sl-hint">Загрузка…</div></div></div>');
    host.appendChild(card);
    lockBtn(card, 'sl-lt-run', 'lt.run');
    lockBtn(card, 'sl-lt-stop', 'lt.run');
    lockBtn(card, 'sl-lt-apply', 'lt.apply');
    var modeSel = card.querySelector('#sl-lt-mode');
    function ltModeUi() {
      var waf = modeSel.value === 'waf';
      card.querySelector('#sl-lt-warnwaf').style.display = waf ? '' : 'none';
      card.querySelector('#sl-lt-ackrow').style.display = waf ? '' : 'none';
      card.querySelector('#sl-lt-pauserow').style.display = waf ? '' : 'none';
    }
    modeSel.addEventListener('change', ltModeUi);
    ltModeUi();
    card.addEventListener('click', function (e) {
      var arch = e.target.closest('[data-lt-arch]');
      if (arch) {
        var aid = arch.getAttribute('data-lt-arch');
        if (arch.getAttribute('data-lt-act') === 'open') {
          api('/api/loadtest/archive/get?id=' + encodeURIComponent(aid)).then(function (r) {
            if (!r || !r.ok) { toast('Отчёт не найден', true); return; }
            LT_VIEW = aid;
            var repEl = document.getElementById('sl-lt-report');
            if (repEl) {
              repEl.innerHTML = '<div class="sl-hint">Архивный отчёт от ' +
                new Date((r.report.started_at || 0) * 1000).toLocaleString('ru-RU') +
                ' · <a href="#" id="sl-lt-lastlink">вернуться к последнему</a></div>' + ltReportHtml({ report: r.report });
            }
          });
          return;
        }
        if (arch.getAttribute('data-lt-act') === 'html') {
          apiBlob('/api/loadtest/report?id=' + encodeURIComponent(aid)).then(function (b) {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(b);
            a.download = 'slext-loadtest-report-' + aid + '.html';
            document.body.appendChild(a);
            a.click();
            setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
          }).catch(function () { toast('Отчёт недоступен', true); });
          return;
        }
        if (arch.getAttribute('data-lt-act') === 'del') {
          api('/api/loadtest/archive/delete', { method: 'POST', body: { id: aid } }).then(function (r) {
            toast(r && r.ok ? 'Удалено из архива' : 'Ошибка', !(r && r.ok));
            LT_HASH = '';
            ltPoll();
          });
          return;
        }
      }
      if (e.target.id === 'sl-lt-lastlink') {
        e.preventDefault();
        LT_VIEW = 'last';
        LT_HASH = '';
        ltPoll();
        return;
      }
      if (e.target.id === 'sl-lt-run') {
        var wafMode = document.getElementById('sl-lt-mode').value === 'waf';
        var autopause = document.getElementById('sl-lt-autopause').checked;
        if (wafMode && !autopause && !document.getElementById('sl-lt-ack').checked) {
          toast('Подтвердите, что защита отключена на время теста', true);
          return;
        }
        var sel = document.getElementById('sl-lt-host');
        if (!sel.value) { toast('Выберите домен', true); return; }
        api('/api/loadtest/start', { method: 'POST', body: {
          ack: document.getElementById('sl-lt-ack').checked,
          auto_pause: autopause,
          host: sel.value, path: document.getElementById('sl-lt-path').value,
          mode: document.getElementById('sl-lt-mode').value,
          max_conc: parseInt(document.getElementById('sl-lt-conc').value, 10) || 48,
          stage_sec: parseInt(document.getElementById('sl-lt-stage').value, 10) || 6,
          p95_ms: parseInt(document.getElementById('sl-lt-p95').value, 10) || 1500,
          err_pct: parseFloat(document.getElementById('sl-lt-err').value) || 3,
          max_total_sec: parseInt(document.getElementById('sl-lt-total').value, 10) || 240
        } }).then(function (r) {
          toast(r.ok ? 'Тест запущен' : ('Ошибка: ' + (r.error || '')), !r.ok);
          LT_HASH = '';
          ltPoll();
        });
      }
      if (e.target.id === 'sl-lt-stop') {
        api('/api/loadtest/stop', { method: 'POST', body: {} }).then(function () { toast('Останавливаю тест...'); });
      }
      if (e.target.id === 'sl-lt-apply') {
        var hostEl = document.getElementById('sl-lt-host');
        api('/api/loadtest/apply', { method: 'POST', body: { host: hostEl.value } }).then(function (r) {
          toast(r.ok ? 'Значения подставлены (включите «авто по нагрузке» при необходимости)' : ('Ошибка: ' + (r.error || '')), !r.ok);
        });
      }
      if (e.target.id === 'sl-lt-dl') {
        apiBlob('/api/loadtest/report').then(function (b) {
          var a = document.createElement('a');
          a.href = URL.createObjectURL(b);
          a.download = 'slext-loadtest-report.html';
          document.body.appendChild(a);
          a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
        }).catch(function () { toast('Отчёт недоступен', true); });
      }
    });
    ltPoll();
  }

  /* ------------------------------ proxy analytics ------------------------------ */

  var PX_HOURS = 24;

  function pxMb(n) {
    n = n || 0;
    if (n > 1073741824) return (n / 1073741824).toFixed(2) + ' ГБ';
    if (n > 1048576) return (n / 1048576).toFixed(1) + ' МБ';
    if (n > 1024) return (n / 1024).toFixed(1) + ' КБ';
    return n + ' Б';
  }

  function pxTimeLabels(tl) {
    return tl.map(function (x) {
      return new Date(x.ts * 1000).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    });
  }

  var PX_METRIC = 'req';
  var PX_DATA = null;

  function pxChart(node, tl) {
    if (!node || !tl || !tl.length) return;
    var labels = pxTimeLabels(tl);
    if (window.echarts) {
      try {
        var chart = window.echarts.getInstanceByDom(node) || window.echarts.init(node);
        var opt = {
          grid: { left: 50, right: 50, top: 28, bottom: 28 },
          tooltip: { trigger: 'axis' }
        };
        if (PX_METRIC === 'req') {
          opt.legend = { data: ['RPS'], right: 0, top: 0, textStyle: { fontSize: 11 } };
          opt.xAxis = { type: 'category', data: labels, axisLabel: { fontSize: 10 } };
          opt.yAxis = { type: 'value', name: 'RPS', nameTextStyle: { fontSize: 10 }, splitLine: { lineStyle: { opacity: 0.15 } } };
          opt.series = [{ name: 'RPS', type: 'line', smooth: true, areaStyle: { opacity: 0.12 },
                          data: tl.map(function (x) { return x.rps; }) }];
        } else if (PX_METRIC === 'bw') {
          opt.legend = { data: ['отдано, МБ', 'принято, МБ'], right: 0, top: 0, textStyle: { fontSize: 11 } };
          opt.xAxis = { type: 'category', data: labels, axisLabel: { fontSize: 10 } };
          opt.yAxis = { type: 'value', name: 'МБ', nameTextStyle: { fontSize: 10 }, splitLine: { lineStyle: { opacity: 0.15 } } };
          opt.series = [
            { name: 'отдано, МБ', type: 'line', smooth: true, areaStyle: { opacity: 0.12 }, data: tl.map(function (x) { return x.out_mb; }) },
            { name: 'принято, МБ', type: 'line', smooth: true, data: tl.map(function (x) { return x.in_mb; }) }
          ];
        } else if (PX_METRIC === 'p95') {
          opt.legend = { data: ['p50, мс', 'p95, мс'], right: 0, top: 0, textStyle: { fontSize: 11 } };
          opt.xAxis = { type: 'category', data: labels, axisLabel: { fontSize: 10 } };
          opt.yAxis = { type: 'value', name: 'мс', nameTextStyle: { fontSize: 10 }, splitLine: { lineStyle: { opacity: 0.15 } } };
          opt.series = [
            { name: 'p50, мс', type: 'line', smooth: true, data: tl.map(function (x) { return x.p50; }) },
            { name: 'p95, мс', type: 'line', smooth: true, areaStyle: { opacity: 0.12 }, data: tl.map(function (x) { return x.p95; }) }
          ];
        } else {
          opt.legend = { data: ['2xx/3xx', '4xx', '5xx'], right: 0, top: 0, textStyle: { fontSize: 11 } };
          opt.xAxis = { type: 'category', data: labels, axisLabel: { fontSize: 10 } };
          opt.yAxis = { type: 'value', splitLine: { lineStyle: { opacity: 0.15 } } };
          opt.series = [
            { name: '2xx/3xx', type: 'bar', stack: 'e', data: tl.map(function (x) { return Math.max(0, x.count - x.e4 - x.e5); }) },
            { name: '4xx', type: 'bar', stack: 'e', data: tl.map(function (x) { return x.e4; }) },
            { name: '5xx', type: 'bar', stack: 'e', data: tl.map(function (x) { return x.e5; }) }
          ];
        }
        chart.setOption(opt, true);
        return;
      } catch (e) {}
    }
    if (PX_METRIC === 'err') {
      renderBars(node, tl.map(function (x) { return { label: pxTimeLabels([x])[0], count: x.count }; }));
    } else {
      node.innerHTML = '<canvas style="width:100%;height:180px"></canvas>';
      canvasLine(node.querySelector('canvas'),
        tl.map(function (x) { return PX_METRIC === 'bw' ? x.out_mb : (PX_METRIC === 'p95' ? x.p95 : x.rps); }));
    }
  }

  function pxUpstreamHtml(d) {
    return tableHtml(['Метрика', 'Среднее, мс', 'p95, мс'], [
      ['Апстрим (бэкенд, upstream_response_time)', d.up_avg === null ? '—' : d.up_avg, d.up_p95 === null ? '—' : d.up_p95],
      ['Полное время ответа (request_time)', d.tot_avg, d.tot_p95],
      ['Накладные WAF (полное − апстрим)', d.over_avg === null ? '—' : d.over_avg, d.over_p95 === null ? '—' : d.over_p95]
    ]) + '<div class="sl-hint">Данные апстрима есть у ' + (d.up_cov || 0) + '% запросов. «Накладные WAF» — сколько миллисекунд добавляет прокси/защита поверх бэкенда.</div>';
  }

  function pxFill(d) {
    var k = document.getElementById('sl-px-kpis');
    if (!k) return;
    PX_DATA = d;
    var botsPct = d.total ? Math.round(d.bots * 100 / d.total) : 0;
    var apdexCls = d.apdex >= 0.94 ? 'sl-ok' : (d.apdex >= 0.85 ? '' : 'sl-err');
    k.innerHTML =
      kpi(fmtNum(d.total), 'запросов за ' + PX_HOURS + ' ч',
          'Все запросы через прокси за выбранный период. Тестовый трафик SLExt (нагрузочные тесты) не учитывается.') +
      kpi(fmtNum(d.uniq || 0), 'уникальных IP',
          'Число разных клиентских IP за период — оценка размера аудитории.') +
      kpi(d.rps + '', 'RPS (среднее)',
          'Средняя интенсивность трафика: запросов в секунду за период.') +
      kpiRaw('<span class="' + apdexCls + '">' + esc(d.apdex) + '</span>', 'Apdex (T=' + d.apdex_t + ' мс)',
          'Индекс удовлетворённости (0…1): быстрее 250 мс = 1 очко, 250 мс–1 с = 0.5, медленнее = 0. ≥0.94 отлично, 0.85–0.94 приемлемо, ниже — плохо.') +
      kpi(d.p50 + ' мс', 'p50 (медиана)',
          'Медианная задержка: половина запросов быстрее этого значения.') +
      kpi(d.p95 + ' мс', 'p95',
          '95% успешных запросов быстрее этого значения. Рост p95 — ранний признак перегрузки.') +
      kpiRaw('<span class="' + (d.err5_pct > 0 ? 'sl-err' : '') + '">' + esc(d.err5_pct) + '%</span>', '5xx ошибки',
          'Ошибки сервера (500–599): сбой бэкенда или прокси. В норме — 0%.') +
      kpi(d.over_avg === null ? '—' : d.over_avg + ' мс', 'накладные WAF (сред.)',
          'Сколько миллисекунд добавляет прокси/защита поверх бэкенда: полное время минус время апстрима.');
    var st = document.getElementById('sl-px-state');
    if (st) {
      st.innerHTML = 'p99 ' + esc(d.p99) + ' мс · 4xx ' + esc(d.err4_pct) + '% · боты ' + botsPct + '% · p95 ошибок ' +
        (d.p95_err === null || d.p95_err === undefined ? '—' : esc(d.p95_err) + ' мс') +
        ' · отдано ' + esc(pxMb(d.bw_out)) + ' / принято ' + esc(pxMb(d.bw_in)) +
        ' · свой access_log, обновлено ' + new Date().toLocaleTimeString('ru-RU') +
        (d.cut ? ' · данных много' : '') +
        (d.test_total ? ' · тестовый трафик исключён: ' + d.test_total : '');
    }
    var hist = document.getElementById('sl-px-hist');
    if (hist) hist.innerHTML = barsHtml((d.hist || []).map(function (x) { return { label: x.label, count: x.count }; }));
    var stt = document.getElementById('sl-px-status');
    if (stt) stt.innerHTML = tableHtml(['Код', 'Класс', 'Запросов', 'Доля'], (d.statuses || []).map(function (x) {
      return [x.code || '—', x['class'], fmtNum(x.count), x.pct + '%'];
    })) + (d.methods && d.methods.length ? ('<div class="sl-hint">Методы: ' +
      d.methods.map(function (m) { return m.method + ' — ' + fmtNum(m.count); }).join(' · ') + '</div>') : '');
    var paths = document.getElementById('sl-px-paths');
    if (paths) paths.innerHTML = tableHtml(['Путь', 'Запросов', 'Сред., мс', 'p95, мс', 'Ошибки, %'],
      (d.paths || []).map(function (x) { return [x.path, fmtNum(x.count), x.avg, x.p95, x.err_pct]; }));
    var refs = document.getElementById('sl-px-refs');
    if (refs) refs.innerHTML = (d.referers && d.referers.length)
      ? tableHtml(['Источник', 'Переходов'], d.referers.map(function (x) { return [x.host, fmtNum(x.count)]; }))
      : '<div class="sl-hint">Внешних переходов не было (прямые заходы).</div>';
    var up = document.getElementById('sl-px-up');
    if (up) up.innerHTML = pxUpstreamHtml(d);
    var slow = document.getElementById('sl-px-slow');
    if (slow) slow.innerHTML = tableHtml(['Время', 'Метод', 'Путь', 'Статус', 'мс', 'Апстрим, мс', 'IP'],
      (d.slow || []).map(function (x) {
        return [new Date(x.ts * 1000).toLocaleTimeString('ru-RU'), x.method, x.path, x.status, x.ms,
                x.up_ms === null ? '—' : x.up_ms, x.ip];
      })) || '<div class="sl-hint">Медленных запросов нет</div>';
    pxChart(document.getElementById('sl-px-chart'), d.timeline || []);
  }

  function pxLoad() {
    var st = document.getElementById('sl-px-state');
    if (st) st.textContent = 'загружаю...';
    api('/api/proxy?hours=' + PX_HOURS).then(function (d) {
      if (!d || !d.ok) { if (st) st.textContent = 'ошибка: ' + ((d && d.error) || 'нет данных'); return; }
      pxFill(d);
    });
  }

  function renderProxyCard(host) {
    if (document.getElementById('sl-px-sec') || !host) return;
    var hrs = [[1, '1 ч'], [6, '6 ч'], [24, '24 ч'], [168, '7 дней']].map(function (x) {
      return '<button class="sl-btn" data-px-hours="' + x[0] + '">' + x[1] + '</button>';
    }).join('');
    var card = el('<div class="sl-card" id="sl-px-sec">' +
      '<div class="sl-card-title">Проксирование сайта — трафик и качество <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">«Золотые сигналы» из собственного access_log прокси: трафик, задержки, ошибки, Apdex, накладные расходы WAF. Тестовый трафик SLExt исключается.</div>' +
      '<div class="sl-row">' + hrs + '<button class="sl-btn sl-btn-pri" id="sl-px-refresh">Обновить</button>' +
      '<span class="sl-hint" id="sl-px-state" style="margin:0"></span></div>' +
      '<div class="sl-kpis" id="sl-px-kpis"><div class="sl-hint">Загрузка…</div></div>' +
      '<div class="sl-sub" data-sl-tip="Переключайте метрику: запросы в секунду, объём трафика, задержки (p50/p95) или ошибки по классам — всё на одном графике.">Динамика <span class="sl-tabs" id="sl-px-metrics" style="margin-left:8px">' +
      '<button class="sl-btn" data-px-metric="req">Запросы</button>' +
      '<button class="sl-btn" data-px-metric="bw">Трафик</button>' +
      '<button class="sl-btn" data-px-metric="p95">Задержки</button>' +
      '<button class="sl-btn" data-px-metric="err">Ошибки</button></span></div>' +
      '<div id="sl-px-chart" style="width:100%;height:200px"></div>' +
      '<div class="sl-grid2">' +
      '<div><div class="sl-sub" data-sl-tip="Распределение запросов по времени ответа. Длинный правый хвост — медленные запросы.">Распределение задержек</div><div id="sl-px-hist"></div></div>' +
      '<div><div class="sl-sub" data-sl-tip="Разбивка по HTTP-кодам с долями от общего числа запросов.">Статусы и методы</div><div id="sl-px-status"></div></div>' +
      '<div><div class="sl-sub" data-sl-tip="Агрегация по URL без query: количество, средняя задержка, p95 и доля ошибок (4xx+5xx).">Топ путей</div><div id="sl-px-paths"></div></div>' +
      '<div><div class="sl-sub" data-sl-tip="Откуда приходят посетители (заголовок Referer). Прямые заходы не учитываются.">Источники (referer)</div><div id="sl-px-refs"></div></div>' +
      '</div>' +
      '<details class="sl-details" data-sl-tip="Бэкенд (upstream_response_time) против полного времени ответа. Разница — накладные расходы WAF-прокси и защиты."><summary>Апстрим и накладные расходы WAF</summary><div id="sl-px-up"></div></details>' +
      '<details class="sl-details" data-sl-tip="Топ-12 самых долгих запросов за период с деталями: путь, статус, полное и апстрим-время, IP."><summary>Самые медленные запросы</summary><div id="sl-px-slow"></div></details></div>');
    host.appendChild(card);
    card.querySelectorAll('[data-px-metric]').forEach(function (b) {
      b.classList.toggle('sl-btn-pri', b.getAttribute('data-px-metric') === PX_METRIC);
    });
    card.addEventListener('click', function (e) {
      var hb = e.target.closest('[data-px-hours]');
      if (hb) {
        PX_HOURS = parseInt(hb.getAttribute('data-px-hours'), 10) || 24;
        card.querySelectorAll('[data-px-hours]').forEach(function (b) {
          b.classList.toggle('sl-btn-pri', parseInt(b.getAttribute('data-px-hours'), 10) === PX_HOURS);
        });
        pxLoad();
        return;
      }
      var mb = e.target.closest('[data-px-metric]');
      if (mb) {
        PX_METRIC = mb.getAttribute('data-px-metric');
        card.querySelectorAll('[data-px-metric]').forEach(function (b) {
          b.classList.toggle('sl-btn-pri', b.getAttribute('data-px-metric') === PX_METRIC);
        });
        if (PX_DATA) pxChart(document.getElementById('sl-px-chart'), PX_DATA.timeline || []);
        return;
      }
      if (e.target.id === 'sl-px-refresh') pxLoad();
    });
    card.querySelectorAll('[data-px-hours]').forEach(function (b) {
      if (parseInt(b.getAttribute('data-px-hours'), 10) === PX_HOURS) b.classList.add('sl-btn-pri');
    });
    pxLoad();
  }

  /* ------------------------------ dns & tls ------------------------------ */

  var DNS_DATA = null;

  function dnsTlsCell(t) {
    if (!t || t.error) return '<span class="sl-err">' + esc((t && t.error) || 'нет данных') + '</span>';
    var d = t.days_left;
    var cls = (d !== null && d !== undefined && d < 14) ? 'sl-err' : ((d !== null && d !== undefined && d < 30) ? '' : 'sl-ok');
    return '<span class="' + cls + '">' + esc(d === null || d === undefined ? '—' : d + ' дн') + '</span>' +
      '<div class="sl-hint" style="margin:0">' + esc((t.issuer || '').slice(0, 60)) + '</div>';
  }

  function dnsChart(hosts) {
    var node = document.getElementById('sl-dns-chart');
    if (!node || !hosts.length) return;
    var ts = (hosts[0].samples || []).map(function (s) {
      return new Date(s.ts * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    });
    var series = hosts.map(function (h) {
      return { name: h.host, type: 'line', smooth: true,
               data: (h.samples || []).map(function (s) { return s.ms; }) };
    });
    if (window.echarts) {
      try {
        var ch = window.echarts.getInstanceByDom(node) || window.echarts.init(node);
        ch.setOption({
          grid: { left: 48, right: 14, top: 26, bottom: 26 },
          tooltip: { trigger: 'axis' },
          legend: { right: 0, top: 0, textStyle: { fontSize: 11 } },
          xAxis: { type: 'category', data: ts, axisLabel: { fontSize: 10 } },
          yAxis: { type: 'value', name: 'мс', nameTextStyle: { fontSize: 10 }, splitLine: { lineStyle: { opacity: 0.15 } } },
          series: series
        }, true);
        return;
      } catch (e) {}
    }
  }

  function dnsLoad() {
    api('/api/dns').then(function (d) {
      if (!d || !d.ok) return;
      DNS_DATA = d;
      var hosts = d.hosts || [];
      var now = Date.now() / 1000;
      var totalS = 0, okS = 0, msSum = 0, msN = 0, minDays = null;
      hosts.forEach(function (h) {
        (h.samples || []).forEach(function (s) {
          if (now - s.ts < 86400) {
            totalS++;
            if (s.ok) {
              okS++;
              if (s.ms !== null && s.ms !== undefined) { msSum += s.ms; msN++; }
            }
          }
        });
        var dl = h.last && h.last.tls && h.last.tls.days_left;
        if (dl !== null && dl !== undefined) minDays = (minDays === null || dl < minDays) ? dl : minDays;
      });
      var k = document.getElementById('sl-dns-kpis');
      if (k) k.innerHTML =
        kpi(fmtNum(hosts.length), 'доменов сайта',
            'Домены из настроек SafeLine, по которым идут проверки.') +
        kpi(totalS ? Math.round(okS * 100 / totalS) + '%' : '—', 'доступность DNS за 24 ч',
            'Доля успешных DNS-проверок за последние сутки.') +
        kpi(msN ? Math.round(msSum / msN) + ' мс' : '—', 'среднее время DNS',
            'Среднее время ответа резолвера по всем проверкам за сутки.') +
        kpiRaw(minDays === null ? '—' : (minDays < 14 ? '<span class="sl-err">' + minDays + ' дн</span>' : minDays + ' дн'),
            'мин. срок TLS', 'Минимальный остаток дней до истечения TLS-сертификата среди доменов.');
      var st = document.getElementById('sl-dns-state');
      if (st) st.textContent = 'автопроверка каждые 5 мин · обновлено ' + new Date().toLocaleTimeString('ru-RU');
      var rows = hosts.map(function (h) {
        var L = h.last || {};
        var a = (L.a || []).map(function (r) { return r.value + ' (TTL ' + r.ttl + ')'; }).join(', ') || '—';
        var aaaa = (L.aaaa || []).map(function (r) { return r.value; }).join(', ') || '—';
        var flags = [];
        if (L.spf) flags.push('<b class="sl-ok">SPF</b>');
        else if (L.txt) flags.push('<span class="sl-err">нет SPF</span>');
        if (L.dmarc) flags.push('<b class="sl-ok">DMARC</b>');
        else if (L.txt) flags.push('<span class="sl-err">нет DMARC</span>');
        return '<tr><td><b>' + esc(h.host) + '</b>' +
          (L.error ? '<div class="sl-err" style="font-size:11px">' + esc(L.error) + '</div>' : '') + '</td>' +
          '<td class="sl-mono" style="font-size:11px">' + esc(a) + '</td>' +
          '<td class="sl-mono" style="font-size:11px">' + esc(aaaa) + '</td>' +
          '<td>' + (L.ms !== null && L.ms !== undefined ? esc(L.ms) + ' мс' : '—') + '</td>' +
          '<td>' + (flags.join(' · ') || '—') + '</td>' +
          '<td>' + dnsTlsCell(L.tls) + '</td>' +
          '<td>' + (L.at ? new Date(L.at * 1000).toLocaleTimeString('ru-RU') : '—') + '</td></tr>';
      }).join('');
      var tbl = document.getElementById('sl-dns-table');
      if (tbl) tbl.innerHTML = rows
        ? '<table class="sl-table"><tr><th>Домен</th><th>A</th><th>AAAA</th><th>DNS, мс</th><th>Почта</th><th>TLS</th><th>Проверка</th></tr>' + rows + '</table>'
        : '<div class="sl-hint">Пока нет данных — нажмите «Проверить сейчас».</div>';
      dnsChart(hosts);
    });
  }

  function renderDnsCard(host) {
    if (document.getElementById('sl-dns-sec') || !host) return;
    var card = el('<div class="sl-card" id="sl-dns-sec">' +
      '<div class="sl-card-title">DNS и TLS — здоровье доменов <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Живые проверки доменов сайта: A/AAAA-записи и TTL, задержка DNS-ответа, SPF/DMARC, TLS-сертификат (издатель и дни до истечения). Автопроверка каждые 5 минут, история за 2 суток.</div>' +
      '<div class="sl-row"><button class="sl-btn sl-btn-pri" id="sl-dns-run">Проверить сейчас</button>' +
      '<button class="sl-btn" id="sl-dns-refresh">Обновить</button>' +
      '<span class="sl-hint" id="sl-dns-state" style="margin:0"></span></div>' +
      '<div class="sl-kpis" id="sl-dns-kpis"><div class="sl-hint">Загрузка…</div></div>' +
      '<div class="sl-sub" data-sl-tip="Время ответа DNS-резолвера по доменам. Стабильно низкое — DNS в порядке; всплески — проблемы резолвера или сети.">Задержка DNS-ответа</div>' +
      '<div id="sl-dns-chart" style="width:100%;height:180px"></div>' +
      '<div class="sl-sub" data-sl-tip="Текущие DNS-записи и параметры TLS-сертификатов доменов сайта.">Записи и сертификаты</div>' +
      '<div id="sl-dns-table"></div></div>');
    host.appendChild(card);
    lockBtn(card, 'sl-dns-run', 'dns.check');
    card.addEventListener('click', function (e) {
      if (e.target.id === 'sl-dns-refresh') return dnsLoad();
      if (e.target.id === 'sl-dns-run') {
        var st = document.getElementById('sl-dns-state');
        if (st) st.textContent = 'проверяю домены...';
        api('/api/dns/check', { method: 'POST', body: {} }).then(function (r) {
          if (!r || !r.ok) { toast('Ошибка проверки', true); return; }
          toast('Проверено доменов: ' + ((r.results || []).length));
          dnsLoad();
        });
      }
    });
    dnsLoad();
  }

  /* ------------------------------ access matrix ------------------------------ */

  function accessSettingsHost() {
    var w = document.getElementById('sl-access-wrap');
    if (w && document.body.contains(w)) return w;
    var header = findByTextDeep(document, 'management', '#sl-app,#sl-access-sec');
    var host = null, before = null;
    if (header && header.parentElement && header.parentElement.parentElement) {
      var group = header.parentElement;
      host = group.parentElement;
      before = group.nextSibling;
    }
    if (!host) {
      var sc = document.querySelector('div[style*="overflow-y"]');
      host = (sc && sc.children.length) ? sc.children[sc.children.length - 1] : document.body;
    }
    w = el('<div id="sl-access-wrap"></div>');
    if (before && before.parentNode === host) host.insertBefore(w, before);
    else host.appendChild(w);
    return w;
  }

  function renderAccessSettings() {
    if (location.pathname.indexOf('/system') !== 0 || !can('access.manage')) {
      removeSection('sl-access-sec');
      return;
    }
    if (document.getElementById('sl-access-sec')) return;
    var host = accessSettingsHost();
    if (host) renderAccessCard(host);
  }

  function renderAccessCard(host) {
    if (document.getElementById('sl-access-sec') || !host) return;
    var card = el('<div class="sl-card" id="sl-access-sec">' +
      '<div class="sl-card-title">Доступ — матрица прав <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Роли: <b>администратор</b> — всё; <b>оператор</b> — просмотр всех разделов + управление залом, бан в CrowdSec, запуск теста, проверка DNS; <b>наблюдатель</b> — только просмотр; <b>настраиваемый</b> — выбранные права. «Домены» ограничивают пользователя только этими сайтами (пусто — все). Пользователи без настройки получают полный доступ.</div>' +
      '<div class="sl-row"><b>Создать пользователя панели</b>' +
      '<input class="sl-input" id="sl-acc-new-name" placeholder="логин (3-64)">' +
      '<input class="sl-input" id="sl-acc-new-pass" type="password" placeholder="пароль (мин. 8)">' +
      '<button class="sl-btn sl-btn-pri" id="sl-acc-add">Создать</button></div>' +
      '<div class="sl-warn" style="margin:6px 0"><b>Важно:</b> SafeLine CE не умеет ограничивать доступ к самой панели (это Pro-функция), поэтому созданный пользователь получит полный доступ к интерфейсу SafeLine. Создавайте учётки только доверенным людям, а ограничения (разделы SLExt и домены) выдавайте в матрице ниже.</div>' +
      '<div id="sl-access-list"><div class="sl-hint">Загрузка…</div></div></div>');
    host.appendChild(card);
    card.addEventListener('change', function (e) {
      var sel = e.target.closest('[data-acc-role]');
      if (sel) {
        var row = sel.closest('[data-acc-row]');
        var box = row && row.querySelector('[data-acc-perms]');
        if (box) box.style.display = sel.value === 'custom' ? '' : 'none';
      }
    });
    card.addEventListener('click', function (e) {
      if (e.target.id === 'sl-acc-add') {
        var nm = (document.getElementById('sl-acc-new-name').value || '').trim();
        var pw = document.getElementById('sl-acc-new-pass').value || '';
        api('/api/access/user', { method: 'POST', body: { username: nm, password: pw } }).then(function (r) {
          toast(r.ok ? ('Пользователь «' + nm + '» создан') : ('Ошибка: ' + (r.error || '')), !r.ok);
          if (r.ok) { removeSection('sl-access-sec'); renderAccessSettings(); }
        });
        return;
      }
      var pwBtn = e.target.closest('[data-acc-pw]');
      if (pwBtn) {
        var u2 = pwBtn.getAttribute('data-acc-pw');
        var np = window.prompt('Новый пароль для «' + u2 + '» (минимум 8 символов):');
        if (!np) return;
        api('/api/access/user/password', { method: 'POST', body: { username: u2, password: np } }).then(function (r) {
          toast(r.ok ? 'Пароль изменён' : ('Ошибка: ' + (r.error || '')), !r.ok);
        });
        return;
      }
      var delBtn = e.target.closest('[data-acc-del]');
      if (delBtn) {
        var u3 = delBtn.getAttribute('data-acc-del');
        if (!window.confirm('Удалить пользователя «' + u3 + '»?')) return;
        api('/api/access/user/delete', { method: 'POST', body: { username: u3 } }).then(function (r) {
          toast(r.ok ? 'Пользователь удалён' : ('Ошибка: ' + (r.error || '')), !r.ok);
          if (r.ok) { removeSection('sl-access-sec'); renderAccessSettings(); }
        });
        return;
      }
      var sv = e.target.closest('[data-acc-save]');
      if (!sv) return;
      var u = sv.getAttribute('data-acc-save');
      var row = card.querySelector('[data-acc-row="' + u.replace(/"/g, '') + '"]');
      if (!row) return;
      var role = row.querySelector('[data-acc-role]').value;
      var domains = (row.querySelector('[data-acc-domains]').value || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      var perms = [];
      row.querySelectorAll('[data-acc-perm]').forEach(function (c) { if (c.checked) perms.push(c.getAttribute('data-acc-perm')); });
      api('/api/access/save', { method: 'POST', body: { username: u, role: role, perms: perms, domains: domains } })
        .then(function (r) {
          toast(r.ok ? ('Доступ «' + u + '» сохранён') : ('Ошибка: ' + (r.error || '')), !r.ok);
          if (r.ok) { removeSection('sl-access-sec'); renderAccessSettings(); }
        });
    });
    api('/api/access').then(function (d) {
      var node = document.getElementById('sl-access-list');
      if (!node) return;
      if (!d || !d.ok) { node.innerHTML = '<div class="sl-err">' + esc((d && d.error) || 'недоступно') + '</div>'; return; }
      var permDefs = (d.perms || []).filter(function (p) { return p.key !== 'access.manage'; });
      var hosts = d.hosts || [];
      var rows = (d.users || []).map(function (u) {
        var roleSel = ['admin', 'operator', 'viewer', 'custom'].map(function (r) {
          return '<option value="' + r + '"' + (u.role === r ? ' selected' : '') + '>' +
            esc((d.role_labels || {})[r] || r) + '</option>';
        }).join('');
        var permsHtml = permDefs.map(function (p) {
          var on = (u.perms || []).indexOf(p.key) >= 0;
          return '<label class="sl-perm"><input type="checkbox" data-acc-perm="' + p.key + '"' + (on ? ' checked' : '') + '> ' + esc(p.label) + '</label>';
        }).join('');
        return '<div class="sl-acc-row" data-acc-row="' + esc(u.username) + '">' +
          '<div class="sl-row"><b class="sl-acc-user">' + esc(u.username) + '</b>' +
          '<label>Роль</label><select class="sl-input" data-acc-role>' + roleSel + '</select>' +
          '<label>Домены (через запятую, пусто — все)</label>' +
          '<input class="sl-input sl-wide" data-acc-domains list="sl-acc-hosts" value="' + esc((u.domains || []).join(', ')) + '">' +
          '<button class="sl-btn sl-btn-pri" data-acc-save="' + esc(u.username) + '">Сохранить</button>' +
          '<button class="sl-btn" data-acc-pw="' + esc(u.username) + '" title="Сменить пароль">Пароль</button>' +
          (u.username === 'admin' ? '' : '<button class="sl-btn sl-btn-x" data-acc-del="' + esc(u.username) + '" title="Удалить пользователя">Удалить</button>') +
          (u.configured ? '' : '<span class="sl-badge">не настроен — полный доступ</span>') + '</div>' +
          '<div class="sl-perms" data-acc-perms style="' + (u.role === 'custom' ? '' : 'display:none') + '">' +
          '<div class="sl-hint">Права для настраиваемой роли:</div>' + permsHtml + '</div></div>';
      }).join('');
      node.innerHTML = '<datalist id="sl-acc-hosts">' +
        hosts.map(function (h) { return '<option value="' + esc(h) + '">'; }).join('') + '</datalist>' +
        (rows || '<div class="sl-hint">Пользователи панели не найдены.</div>');
    });
  }

  /* ------------------------------ crowdsec ------------------------------ */

  function renderCrowdSecCard(host) {
    if (document.getElementById('sl-cs-sec') || !host) return;
    var card = el('<div class="sl-card" id="sl-cs-sec">' +
      '<div class="sl-card-title">CrowdSec — репутация IP <span class="sl-badge">SLExt</span></div>' +
      '<div class="sl-hint">Активные баны CrowdSec (firewall-bouncer) на этом сервере.</div>' +
      '<div class="sl-row"><input class="sl-input" id="sl-cs-ip" placeholder="IP для бана">' +
      '<select class="sl-input" id="sl-cs-dur">' +
      '<option value="1h">1 час</option><option value="4h" selected>4 часа</option>' +
      '<option value="24h">24 часа</option><option value="168h">7 дней</option></select>' +
      '<button class="sl-btn" id="sl-cs-ban">Забанить</button>' +
      '<button class="sl-btn" id="sl-cs-refresh">Обновить</button></div>' +
      '<div id="sl-cs-list"><div class="sl-hint">Загрузка…</div></div></div>');
    host.appendChild(card);
    lockBtn(card, 'sl-cs-ban', 'crowdsec.ban');
    card.addEventListener('click', function (e) {
      if (e.target.id === 'sl-cs-refresh') return load();
      if (e.target.id === 'sl-cs-ban') {
        api('/api/crowdsec/ban', { method: 'POST', body: {
          ip: document.getElementById('sl-cs-ip').value.trim(),
          duration: document.getElementById('sl-cs-dur').value,
          reason: 'manual from SafeLine console'
        } }).then(function (r) {
          toast(r.ok ? 'IP забанен' : ('Ошибка: ' + r.info), !r.ok);
          load();
        });
        return;
      }
      if (e.target.hasAttribute && e.target.hasAttribute('data-sl-unban')) {
        api('/api/crowdsec/unban', { method: 'POST', body: { ip: e.target.getAttribute('data-sl-unban') } })
          .then(function (r) { toast(r.ok ? 'Бан снят' : ('Ошибка: ' + r.info), !r.ok); load(); });
      }
    });
    load();

    function load() {
      api('/api/crowdsec').then(function (d) {
        var node = document.getElementById('sl-cs-list');
        if (!node) return;
        if (!d.ok) { node.innerHTML = '<div class="sl-err">' + esc(d.error || 'недоступно') + '</div>'; return; }
        var rows = (d.decisions || []).map(function (x) {
          return '<tr><td class="sl-mono">' + esc(x.ip) + '</td><td>' + esc(x.country || '—') + '</td>' +
            '<td>' + esc(x.as_org || '—') + '</td><td>' + esc(x.scenario) + '</td>' +
            '<td>' + esc(x.duration) + '</td><td>' + esc(x.type) + '</td>' +
            '<td><button class="sl-btn sl-btn-x" data-sl-unban="' + esc(x.ip) + '" title="Снять бан"' +
            (can('crowdsec.ban') ? '' : ' disabled') + '>unban</button></td></tr>';
        }).join('');
        node.innerHTML = (rows ? '<table class="sl-table"><tr><th>IP</th><th>Страна</th><th>AS</th><th>Сценарий</th><th>Осталось</th><th>Тип</th><th></th></tr>' + rows + '</table>'
                               : '<div class="sl-hint">Активных банов нет</div>');
      });
    }
  }

  /* ------------------------------ export on logs page ------------------------------ */

  function renderLogExport(ctx) {
    if (document.getElementById('sl-log-export')) return;
    if (location.pathname.indexOf('/attact_events') !== 0) return;
    var anchor = findByText(ctx, 'auto refresh');
    if (!anchor) anchor = findByText(ctx, 'attack count');
    if (!anchor) return;
    var paper = paperOf(anchor);
    var b = el('<div class="sl-row" id="sl-log-export">' +
      '<button class="sl-btn" id="sl-log-csv">Экспорт CSV (24ч)</button>' +
      '<button class="sl-btn" id="sl-log-json">JSON</button>' +
      '<button class="sl-btn" id="sl-log-csv7">CSV за 7 дней</button></div>');
    paper.parentElement.insertBefore(b, paper.nextSibling);
    b.addEventListener('click', function (e) {
      var fmt = e.target.id === 'sl-log-json' ? 'json' : 'csv';
      var hours = e.target.id === 'sl-log-csv7' ? 168 : 24;
      toast('Готовлю экспорт...');
      apiBlob('/api/export?hours=' + hours + '&format=' + fmt).then(function (blob) {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'safeline-attacks.' + fmt;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 3000);
        toast('Экспорт готов');
      }).catch(function (err) { toast('Ошибка экспорта: ' + err.message, true); });
    });
  }

  /* ------------------------------ upstream dialog patch ------------------------------ */

  var IMG_MAP = [
    ['/assets/business_blue_logo', '/assets/business_dark_logo-Bqy_5MAA.png'],
    ['blue_diamond_pure.png', 'dark_diamond_pure.png'],
    ['blue_diamond.png', 'dark_diamond.png']
  ];

  function swapImages(dark) {
    var imgs = document.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) {
      var img = imgs[i];
      var orig = img.getAttribute('data-sl-src');
      if (orig === null) {
        orig = img.getAttribute('src') || '';
        img.setAttribute('data-sl-src', orig);
      }
      var target = orig;
      if (dark) {
        for (var j = 0; j < IMG_MAP.length; j++) {
          if (orig.indexOf(IMG_MAP[j][0]) !== -1) {
            target = IMG_MAP[j][0].charAt(0) === '/'
              ? IMG_MAP[j][1]
              : orig.replace(IMG_MAP[j][0], IMG_MAP[j][1]);
            break;
          }
        }
      }
      if ((img.getAttribute('src') || '') !== target) img.setAttribute('src', target);
    }
  }

  function fixLocked() {
    var els = document.querySelectorAll('.MuiStack-root, [class*="15gr5yc"]');
    for (var i = 0; i < els.length; i++) {
      var e = els[i];
      if (e.getAttribute('data-sl-noblur')) continue;
      var s = getComputedStyle(e);
      var bf = (s.backdropFilter || s.webkitBackdropFilter || '');
      if (bf && bf !== 'none' && bf.indexOf('blur') >= 0) {
        e.style.display = 'none';
        e.style.backdropFilter = 'none';
        e.style.webkitBackdropFilter = 'none';
        e.setAttribute('data-sl-noblur', '1');
      }
    }
  }

  function hideUpsell() {
    var i, e, t;
    var kill = function (node) {
      if (node && node.style.display !== 'none') {
        node.style.display = 'none';
        node.setAttribute('data-sl-hidden', '1');
      }
    };
    var btns = document.querySelectorAll('button,a,div,span');
    for (i = 0; i < btns.length; i++) {
      e = btns[i];
      t = (e.textContent || '').trim().replace(/\s+/g, ' ');
      if (t.length > 40 || e.children.length > 4) continue;
      if (/^(7[- ]day trial|free trial|get a trial|try for free)$/i.test(t)) kill(e);
      else if (/^upgrade( license)?$/i.test(t)) kill(e);
      else if (/^upgrade to pro$/i.test(t)) kill(e);
    }
    var divs = document.querySelectorAll('div');
    for (i = 0; i < divs.length; i++) {
      e = divs[i];
      t = (e.textContent || '').trim().replace(/\s+/g, ' ');
      if (/^upgrade license$/i.test(t) && e.children.length <= 3) { kill(e); break; }
    }
    var tags = document.querySelectorAll('span,div');
    for (i = 0; i < tags.length; i++) {
      e = tags[i];
      t = (e.textContent || '').trim();
      if ((t === 'PRO' || t === 'Pro' || t === 'Professional' || t === 'Business') && e.children.length === 0 &&
          !(e.closest && (e.closest('#sl-app') || e.closest('#sl-dash-fix') || e.closest('#sl-lb-sec') || e.closest('#sl-dlg-skip')))) {
        kill(e.closest('[class*="badge"],[class*="chip"],[class*="Chip"]') || e);
      }
    }
    var imgs = document.querySelectorAll('img');
    for (i = 0; i < imgs.length; i++) {
      e = imgs[i];
      var src = e.getAttribute('data-sl-src') || e.getAttribute('src') || '';
      if (/pro-logo|pro_board|empty-pro/i.test(src)) kill(e);
    }
    var labels = document.querySelectorAll('span,div,p');
    for (i = 0; i < labels.length; i++) {
      e = labels[i];
      if (e.children.length <= 1 && /^pro only$/i.test((e.textContent || '').trim())) kill(e);
    }
    var uses = document.querySelectorAll('use');
    for (i = 0; i < uses.length; i++) {
      e = uses[i];
      var href = e.getAttribute('xlink:href') || e.getAttribute('href') || '';
      if (/zhuanyebanlogo|prologo/i.test(href)) {
        var svg = e.closest('svg');
        if (svg) kill(svg);
      }
    }
  }

  function flashSection() {
    var sec = document.getElementById('sl-lb-sec');
    if (!sec) return;
    try { sec.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) { sec.scrollIntoView(); }
    sec.classList.add('sl-flash');
    setTimeout(function () { sec.classList.remove('sl-flash'); }, 1800);
  }

  function upstreamBtnOf(node) {
    var b = node && node.closest ? node.closest('button,[role=button],a') : null;
    if (!b) return null;
    if ((b.textContent || '').toUpperCase().indexOf('ADD UPSTREAM') === -1) return null;
    if (!b.closest('[role=dialog]')) return null;
    return b;
  }

  function swallowUpstreamClick(e) {
    var b = upstreamBtnOf(e.target);
    if (!b) return;
    e.preventDefault();
    e.stopPropagation();
    if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    var add = document.getElementById('sl-lb-add');
    if (add) add.click();
    flashSection();
  }

  function markUpstreamBtn(dlg) {
    var up = findByText(dlg, 'add upstream');
    if (!up) return;
    var b = up.closest('button') || up;
    if (b && b.classList && !b.classList.contains('sl-nopro')) b.classList.add('sl-nopro');
  }

  /* ------------------------------ routing ------------------------------ */

  function hideStockSections() {
    var bp = findByTextDeep(document, 'blocking pages', '#sl-app');
    if (bp) {
      var paper = paperOf(bp);
      if (paper && paper !== document.body && !(paper.closest && paper.closest('#sl-app')) &&
          /blocking pages/i.test(paper.textContent || '')) {
        paper.style.display = 'none';
      }
    }
    var stock = findByTextDeep(document, 'html dynamic simple', '#sl-app');
    if (stock) {
      var row = stock.closest('tr') || stock.closest('[class*="MuiStack"],[class*="MuiGrid"],[class*="MuiBox"]') || stock.parentElement;
      if (row && row !== document.body && !(row.closest && row.closest('#sl-app'))) {
        row.style.display = 'none';
        row.setAttribute('data-sl-hidden', '1');
      }
    }
  }

  function hideProRuleUpsell() {
    if (location.pathname.indexOf('/attact_events/inner_rules') !== 0) return;
    var up = findByTextDeep(document, 'upgrade to pro', '.sl-nav,#sl-app');
    if (!up) return;
    var blk = up.closest('button,a') || up;
    var box = blk.closest('[class*="MuiPaper"],[class*="MuiBox"]') || blk.parentElement;
    if (box && box !== document.body && !(box.closest && box.closest('#sl-app'))) {
      box.setAttribute('data-sl-hidden', '1');
      box.style.display = 'none';
    }
  }

  function route() {
    ensureApp();
    var onLogin = location.pathname.indexOf('/login') === 0;
    var app = document.getElementById('sl-app');
    var nav = document.getElementById('sl-nav-item');
    if (app) app.style.display = onLogin ? 'none' : '';
    if (nav) nav.style.display = onLogin ? 'none' : '';
    if (onLogin) return;
    if (app && app.classList.contains('open')) slAppTop();
    themeBtn();
    hideUpsell();
    swapImages(themeEnabled());
    var path = location.pathname;
    if (path.indexOf('/statistics') === 0) fixLocked();
    hideStockSections();
    hideProRuleUpsell();
    var dlg = visibleDialog();
    if (dlg && findByText(dlg, 'add upstream')) {
      markUpstreamBtn(dlg);
      if (!sectionAlive('sl-lb-sec', dlg)) { renderLbCard(dlg); }
    } else {
      removeSection('sl-lb-sec');
    }
    if (dlg && findByTextDeep(dlg, 'skip decryption page', '#sl-dlg-skip')) {
      renderBotDialog(dlg);
    } else {
      removeSection('sl-dlg-skip');
    }
    if (path.indexOf('/system') === 0) {
      var ups = document.querySelectorAll('button,span,a');
      for (var ui = 0; ui < ups.length; ui++) {
        var ue = ups[ui];
        if (ue.children.length === 0 && /^upgrade$/i.test((ue.textContent || '').trim())) ue.style.display = 'none';
      }
    }
    var isTraffic = path === '/statistics' || path === '/statistics/' || path.indexOf('/statistics/traffic') === 0;
    if (isTraffic) renderProBoards(document);
    if (path.indexOf('/statistics/security') === 0) renderSecurityBoards(document);
    if (path.indexOf('/attact_events') === 0) renderLogExport(document);
    else removeSection('sl-log-export');
    fixDashError(document);
    renderAccessSettings();
    if (slWorkOpen()) {
      renderWorkspaceTab();
      if (SL_TAB === 'lt') ltPoll();
    }
  }

  function versionCheck() {
    api('/api/health').then(function (d) {
      if (d && d.extver && String(d.extver) !== EXTVER) location.reload();
    });
  }

  function startObserver() {
    try {
      var pend = null;
      var mo = new MutationObserver(function () {
        if (pend) return;
        pend = setTimeout(function () { pend = null; try { hideUpsell(); } catch (e) {} }, 250);
      });
      mo.observe(document.body, { childList: true, subtree: true });
    } catch (e) {}
  }

  initTheme();
  setTimeout(versionCheck, 20000);
  setInterval(versionCheck, 120000);
  document.addEventListener('mousedown', swallowUpstreamClick, true);
  document.addEventListener('click', swallowUpstreamClick, true);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setInterval(route, 1500); route(); startObserver(); });
  } else {
    setInterval(route, 1500);
    route();
    startObserver();
  }
})();
