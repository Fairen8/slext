#!/usr/bin/env python3
"""Чистые функции SLExt: политика авто-режима зала ожидания и API-маршруты.

Используется slext-api.py, patch_site_page.py и тестами.
Никаких обращений к сети/файлам/БД.
"""
import ipaddress
import re

API_PATH_RE = re.compile(r'^/[A-Za-z0-9_\-./%]*$')


def clamp_int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def api_norm_paths(raw, limit=20):
    """Нормализовать список URL-префиксов для whitelist/rate-limit."""
    out = []
    for p in (raw or [])[:limit]:
        p = str(p or '').strip()[:120]
        if not p.startswith('/') or '..' in p or not API_PATH_RE.match(p):
            continue
        if p not in out:
            out.append(p)
    return out


def api_zone_name(host):
    """nginx-совместимое имя зоны rate-limit для домена."""
    safe = re.sub(r'[^A-Za-z0-9]', '_', str(host or ''))[:40].strip('_')
    return 'slext_api_' + (safe or 'site')


def api_rl_key_var(host):
    return 'slext_api_rlk_' + api_zone_name(host)[len('slext_api_'):]


def api_rl_paths_re(paths):
    """Regex для map: совпадает с любым из указанных префиксов (с якорем)."""
    inner = '|'.join(re.escape(str(p)) for p in (paths or []) if str(p).startswith('/'))
    return '~^(%s)' % inner if inner else '^$'


# --- CrowdSec: доверенные IP/CIDR (whitelist) ---

def trusted_entry_norm(v):
    """IP или CIDR → каноническая строка; None если некорректно."""
    s = str(v or '').strip()
    if not s:
        return None
    try:
        if '/' in s:
            return str(ipaddress.ip_network(s, strict=False))
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def trusted_parse(text):
    """Разобрать список из нашего whitelist-файла (строки '- "значение"')."""
    out = []
    for line in str(text or '').splitlines():
        m = re.match(r'^\s*-\s*"?([^"#\n]+?)"?\s*$', line)
        if not m:
            continue
        e = trusted_entry_norm(m.group(1))
        if e and e not in out:
            out.append(e)
    return out


def trusted_render(entries):
    """Собрать YAML-файл whitelist CrowdSec (parsers/s02-enrich)."""
    ips = [e for e in (entries or []) if '/' not in e]
    cidrs = [e for e in (entries or []) if '/' in e]
    lines = ['name: slext/trusted',
             'description: "Trusted IPs/CIDRs managed by SLExt - never ban"',
             'whitelist:',
             '  reason: "SLExt trusted list"']
    lines.append('  ip:' if ips else '  ip: []')
    lines += ['    - "%s"' % e for e in ips]
    lines.append('  cidr:' if cidrs else '  cidr: []')
    lines += ['    - "%s"' % e for e in cidrs]
    return '\n'.join(lines) + '\n'


def wr_auto_decision(au, st, actual, rate, now):
    """Решение авто-режима.

    au   — настройки авто-режима (threshold/off_threshold/window/hold/hold_off/cooldown/min_off)
    st   — предыдущее состояние: above, below, manual_at, changed_at, source
    actual — текущее фактическое состояние зала
    rate — реальный трафик, запросов/мин
    now  — текущее время (unix)

    Возвращает (desired|None, action, reason, counters):
    desired — что сделать (True/False) или None, если менять не нужно;
    action  — 'on' | 'off' | 'wait';
    reason  — человекочитаемая причина;
    counters — новое состояние счётчиков (above/below/rate/last_eval/...).
    """
    thr = clamp_int(au.get('threshold'), 1, 10 ** 6, 60)
    off = clamp_int(au.get('off_threshold'), 0, thr, min(20, thr))
    hold = clamp_int(au.get('hold'), 1, 20, 3)
    hold_off = clamp_int(au.get('hold_off'), 1, 60, 4)
    cool = clamp_int(au.get('cooldown'), 30, 86400, 600)
    min_off = clamp_int(au.get('min_off'), 0, 86400, 600)
    above = int(st.get('above') or 0)
    below = int(st.get('below') or 0)
    above = above + 1 if rate >= thr else 0
    below = below + 1 if rate <= off else 0
    desired, action = None, 'wait'
    reason = 'трафик %s зап/мин, порог вкл %s — %s/%s проверок подряд' % (rate, thr, above, hold)
    if not actual:
        if above >= hold and now - int(st.get('manual_at') or 0) >= min_off:
            desired, action = True, 'on'
            reason = 'трафик %s зап/мин ≥ %s — %s проверок подряд' % (rate, thr, above)
    elif st.get('source') == 'auto':
        if below >= hold_off and now - int(st.get('changed_at') or 0) >= cool:
            desired, action = False, 'off'
            reason = 'трафик %s зап/мин ≤ %s — %s проверок подряд' % (rate, off, below)
    if action != 'wait':
        above = below = 0
    counters = {'above': above, 'below': below, 'rate': rate, 'last_eval': int(now),
                'window': clamp_int(au.get('window'), 30, 3600, 60), 'threshold': thr,
                'off_threshold': off}
    return desired, action, reason, counters
