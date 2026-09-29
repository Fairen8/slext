#!/usr/bin/env python3
import base64
import csv
import datetime
import glob
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from string import Template

import psycopg2

from wr_policy import clamp_int, wr_auto_decision  # noqa: E402

VERSION = '3.0'
BASE = '/opt/slext'
STATE_FILE = os.path.join(BASE, 'conf', 'state.json')
LB_CONF = os.path.join(BASE, 'conf', 'lb-upstreams.conf')
ENV_FILE = os.path.join(BASE, 'conf', 'slext.env')
GEO_DIR = os.path.join(BASE, 'conf', 'geo')
NGINX_ROOT = '/data/safeline/resources/nginx'
GEO_NGINX_DIR = os.path.join(NGINX_ROOT, 'slext-geo')
PAGES_DIR = os.path.join(NGINX_ROOT, 'slext-pages')
APPLY_SH = os.path.join(BASE, 'bin', 'apply-injection.sh')
PAGE_PATCH = os.path.join(BASE, 'bin', 'patch_site_page.py')
COUNTRIES_FILE = os.path.join(BASE, 'conf', 'countries.json')
IPDENY_URL = 'https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone'
CC_PATTERN = re.compile(r'^https?://[^/]+:9443$')
ADDR_PATTERN = re.compile(r'^[A-Za-z0-9_.\-]+:\d{1,5}$')
IP_PATTERN = re.compile(r'^[0-9a-fA-F:.]{3,45}$')
CIDR_PATTERN = re.compile(r'^[0-9a-fA-F:.]{3,45}/\d{1,3}$')

ATTACK_TYPES = {
    -4: 'Large Data', -3: 'Deny Rule', -2: 'Allow List', -1: 'Non Attack',
    0: 'SQL Inj', 1: 'XSS', 2: 'CSRF', 3: 'SSRF', 4: 'Dos', 5: 'Backdoor',
    6: 'Unserialize', 7: 'Code Execution', 8: 'Code Inj', 9: 'Cmd Inj',
    10: 'File Uploading', 11: 'File Include', 12: 'Redirect',
    13: 'Improper Permission', 14: 'Leaking', 15: 'Unauthorized Request',
    16: 'Insecure Config', 17: 'XXE', 18: 'XPath Inj', 19: 'LDAP Inj',
    20: 'Path Traversal', 21: 'Scanner', 22: 'Horizontal Bypass',
    23: 'Vertical Bypass', 24: 'File Modify', 25: 'File Read',
    26: 'File Delete', 27: 'Wrong Logic', 28: 'CRLF Inj', 29: 'Template Inj',
    30: 'Click Hijack', 31: 'Buffer Overflow', 32: 'Integer Overflow',
    33: 'Format String', 34: 'Competitive Condition',
    35: 'HTTP Protocol Violation', 36: 'HTTP Request Smuggling',
    61: 'Timeout', 62: 'Unknown', 63: 'Threat Intelligence',
    64: 'Cookie Falsify', 99999999: 'All',
}
ACTION_NAMES = {1: 'Blocked', 2: 'Inspected', 3: 'Audited'}

PAGE_DEFS = {
    '403': {'file': 'forbidden.html', 'loc': '/.safeline/forbidden_page',
            'title': 'Запрос заблокирован', 'message': 'Запрос заблокирован системой защиты сайта.',
            'icon': 'shield', 'color': '#FF6666'},
    '404': {'file': 'not_found.html', 'loc': '/.safeline/not_found_page',
            'title': 'Страница не найдена', 'message': 'Такой страницы здесь нет.',
            'icon': 'search', 'color': '#0067B8'},
    '429': {'file': 'acl.html', 'loc': '/.safeline/acl_page',
            'title': 'Слишком много запросов', 'message': 'Превышен лимит запросов. Попробуйте чуть позже.',
            'icon': 'gauge', 'color': '#FF6666'},
    '465': {'file': 'waiting_room.html', 'loc': '/.safeline/waiting_room_page',
            'title': 'Вы в очереди', 'message': 'Сейчас большой наплыв посетителей. Страница откроется автоматически.',
            'icon': 'hourglass', 'color': '#0067B8'},
    '466': {'file': 'offline.html', 'loc': '/.safeline/offline_page',
            'title': 'Сайт на обслуживании', 'message': 'Идут технические работы. Скоро вернёмся.',
            'icon': 'wrench', 'color': '#0067B8'},
    '502': {'file': 'bad_gateway.html', 'loc': '/.safeline/bad_gateway_page',
            'title': 'Сервис недоступен', 'message': 'Сервер не отвечает. Попробуйте обновить страницу.',
            'icon': 'plug', 'color': '#FF6666'},
    '504': {'file': 'gateway_timeout.html', 'loc': '/.safeline/gateway_timeout_page',
            'title': 'Превышено время ожидания', 'message': 'Сервер слишком долго отвечает. Попробуйте ещё раз.',
            'icon': 'clock', 'color': '#FF6666'},
}

PAGE_ICONS = {
    'shield': '<path d="M12 3l7 3v6c0 4.5-2.9 7.6-7 9-4.1-1.4-7-4.5-7-9V6l7-3z"/><path d="M9.4 12l1.9 1.9L15 10.2"/>',
    'search': '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-3.8-3.8"/>',
    'gauge': '<path d="M4 14a8 8 0 0 1 16 0"/><path d="M12 14l3.6-3.6"/><circle cx="12" cy="14" r="1.4"/>',
    'hourglass': '<path d="M7 3h10"/><path d="M7 21h10"/><path d="M8 3c0 3.6 7.5 4.9 7.5 9S8 17.4 8 21"/><path d="M16 3c0 3.6-7.5 4.9-7.5 9S16 17.4 16 21"/>',
    'wrench': '<path d="M15.5 5.5a3.5 3.5 0 0 0 4.4 4.4L11.6 18.2a2 2 0 0 1-2.8-2.8L17.1 7.1"/><path d="M15.5 5.5L14 4a3.1 3.1 0 1 1 3.1 3.1L15.5 5.5z"/>',
    'plug': '<path d="M9 3v5"/><path d="M15 3v5"/><path d="M7 8h10v3a5 5 0 0 1-5 5 5 5 0 0 1-5-5V8z"/><path d="M12 16v5"/>',
    'clock': '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
}

PAGE_TEMPLATE = Template('''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
$refresh
<title>$title</title>
<!-- slext-error-page -->
<style>
:root{--primary-color:$accent;--light-primary-color:#9AC3E3;--font-color:#FFFFFF;--light-font-color:#B3D1E9;--warning-color:#FF6666;--warning-font-color:#FFFFFF;--warning-light-font-color:#FFD1D1}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font-family:PingFang SC,Helvetica Neue,Helvetica,Arial,sans-serif;background-color:var(--primary-color)}
#slg-bg{background-color:var(--primary-color);position:fixed;inset:0;z-index:100}
#slg-box{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:90%;max-width:40rem;text-align:center;z-index:300}
#slg-warning{display:block;margin:0 auto 18px}
#slg-text{font-size:1.5rem;line-height:2.2rem;color:var(--font-color)}
#slg-desc{color:var(--light-font-color);font-size:.8rem;line-height:2rem}
.btn{display:inline-block;margin-top:12px;padding:10px 22px;border-radius:999px;background:var(--font-color);color:var(--primary-color);font-size:14px;text-decoration:none}
#slg-copyright{position:fixed;left:0;right:0;bottom:0;padding:0 0 1.5rem;text-align:center;color:var(--light-font-color);font-size:.8rem;line-height:2rem;z-index:300}
#slg-logo svg{display:block;margin:0 auto}
#slg-name{color:var(--font-color)}
</style>
</head>
<body>
<div id="slg-bg"></div>
<div id="slg-box">
  <svg id="slg-warning" width="68" height="59"><g fill="var(--font-color)"><g><path d="M29.455 2.852c2.062-3.527 6.151-4.07 8.48 0 1.538 2.527 7.818 13.159 14.15 23.904l.827 1.401.412.7.823 1.396A32540 32540 0 0 1 67.03 52.144l.02.038c.26.507 2.626 5.356-1.267 6.818H3.356s-6.846-1.44-.983-9.723c2.345-3.963 8.37-14.306 14.423-24.7l1.008-1.73c4.476-7.689 8.855-15.211 11.651-19.995m4.526 40.47c-2.157 0-3.905 1.74-3.905 3.885s1.748 3.884 3.905 3.884 3.905-1.739 3.905-3.884-1.748-3.884-3.905-3.884m.042-23.955c-2.18 0-3.947 1.758-3.947 3.926V35.69c0 2.168 1.767 3.926 3.947 3.926s3.947-1.757 3.947-3.926V23.293c0-2.168-1.767-3.926-3.947-3.926"/></g></g></svg>
  <div id="slg-text">$title</div>
  <div id="slg-desc">$message</div>
  $button
</div>
<div id="slg-copyright">
  <div id="slg-logo"><svg width="32" height="35"><g fill="var(--font-color)"><path d="M15.006.33c.602-.44 1.4-.44 2.002 0 1.985 1.444 6.911 4.473 12.901 4.631.78.035 1.418.599 1.577 1.356.922 4.754 2.605 20.848-15.452 28.35C-2.077 27.183-.43 11.07.528 6.317c.142-.757.815-1.32 1.577-1.356 5.99-.158 10.863-3.187 12.9-4.63m1.037 4.54c-.28 1.647-2.15 1.938-2.15 1.938-1.9.309-2.819-1.12-2.819-1.12.82 2.255 2.198 2.391 2.446 2.397h2.423c-.7 1.802-3.48 2.133-3.48 2.133-3.159.39-4.689-1.423-4.689-1.423q.17.357.358.66l-.008-.005a11 11 0 0 0-3.106 7.671c0 6.09 4.937 11.026 11.026 11.026 6.09 0 11.027-4.936 11.027-11.026a11 11 0 0 0-3.11-7.674q.185-.3.353-.652s-1.53 1.816-4.69 1.423c0 0-2.776-.33-3.478-2.132h2.42c.245-.006 1.627-.14 2.448-2.397 0 0-.92 1.428-2.82 1.12-.142-.025-1.882-.356-2.15-1.94"/><polygon points="15.98353 17.9879553 9.8818726 21.4510476 15.3313444 24.6578974 17.2903808 23.6211992 13.5799337 21.4510476 15.98353 20.0985396 20.3159976 22.5564681 20.3159976 23.3648458 22.2042418 24.5010295 22.2042418 21.4510476" transform="rotate(-180 16.043 21.323)"/><polygon points="15.9835296 10.9942305 9.8818722 14.4573228 15.331344 17.6641726 17.2903804 16.6274743 13.5799333 14.4573228 15.9835296 13.1048148 20.3159972 15.5627433 20.3159972 16.371121 22.2042414 17.5073047 22.2042414 14.4573228"/></g></svg></div>
  <div id="slg-copyright-text"><span id="slg-prefix">Security Detection Powered By</span> <span id="slg-name">$brand</span></div>
</div>
</body>
</html>
''')


def load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    env[k] = v
    except OSError:
        pass
    return env


ENV = load_env()
PG = dict(host=ENV.get('PGHOST', '127.0.0.1'),
          port=int(ENV.get('PGPORT', '5432')),
          user=ENV.get('PGUSER', 'safeline-ce'),
          password=ENV.get('PGPASSWORD', ''),
          dbname=ENV.get('PGDATABASE', 'safeline-ce'),
          sslmode='disable')

LOCK = threading.RLock()
NODES = {}
TOKEN_CACHE = {}
GEO_CACHE = {}
CS_CACHE = {'at': 0, 'data': None}
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def db():
    return psycopg2.connect(**PG)


def default_state():
    return {
        'lb': {'algorithm': 'round_robin', 'backends': [],
               'health': {'enabled': True, 'interval': 15, 'timeout': 3,
                          'path': '/', 'failures': 3, 'notify': True},
               'options': {'keepalive': 32, 'connect_timeout': 5, 'read_timeout': 300,
                           'send_timeout': 60, 'tries': 3, 'retry_5xx': True,
                           'passive_max_fails': 3, 'passive_fail_timeout': 10}},
        'notify': {
            'telegram': {'enabled': False, 'bot_token': '', 'chat_id': '',
                         'min_risk': 0, 'last_id': 0, 'last_send': 0, 'last_error': ''},
            'discord': {'enabled': False, 'webhook': '', 'min_risk': 0,
                        'last_send': 0, 'last_error': ''},
        },
        'geo': {'enabled': False, 'mode': 'block', 'countries': [],
                'updated_at': 0, 'last_error': ''},
        'page': {'enabled': False, 'brand': 'SafeLine WAF', 'color': '', 'updated_at': 0,
                 'pages': {c: {'enabled': True, 'title': PAGE_DEFS[c]['title'],
                               'message': PAGE_DEFS[c]['message']} for c in PAGE_DEFS}},
        'alarm': {'enabled': False, 'rules': [
            {'id': 'attacks', 'name': 'Attack spike', 'metric': 'attacks',
             'threshold': 20, 'window': 5, 'cooldown': 30, 'enabled': True, 'last_fired': 0},
        ]},
        'syslog': {'enabled': False, 'host': '', 'port': 514, 'proto': 'udp', 'last_error': ''},
        'backup': {'enabled': True, 'hour': 4, 'keep_days': 7,
                   'dir': '/var/backups/slext', 'last_run': 0, 'last_error': ''},
        'waiting': {'sites': {}, 'panel_base': '', 'last_session_id': 0},
        'skip': {'enabled': True},
    }


def migrate_state(st):
    if 'telegram' in st and 'notify' not in st:
        st['notify'] = default_state()['notify']
        st['notify']['telegram'].update(st.pop('telegram') or {})
    p = st.get('page')
    if isinstance(p, dict) and 'pages' not in p:
        pages = {c: {'enabled': True, 'title': PAGE_DEFS[c]['title'],
                     'message': PAGE_DEFS[c]['message']} for c in PAGE_DEFS}
        pages['403'] = {'enabled': True,
                        'title': p.get('title') or PAGE_DEFS['403']['title'],
                        'message': p.get('message') or PAGE_DEFS['403']['message']}
        st['page'] = {'enabled': bool(p.get('enabled')), 'brand': p.get('brand') or 'SafeLine WAF',
                      'color': p.get('color') or '', 'updated_at': p.get('updated_at', 0),
                      'pages': pages}
        p = st['page']
    if isinstance(p, dict):
        if str(p.get('color') or '') == '#0fc6c2':
            p['color'] = ''
        if not p.get('brand'):
            p['brand'] = 'SafeLine WAF'
    return st


def load_state():
    try:
        with open(STATE_FILE) as f:
            st = json.load(f)
        st = migrate_state(st or {})
        base = default_state()
        for k in ('notify', 'geo', 'alarm', 'syslog', 'backup', 'waiting'):
            if k in st and isinstance(st[k], dict):
                base[k] = {**base[k], **st[k]}
        if isinstance(st.get('page'), dict):
            pg = st['page']
            base['page']['enabled'] = bool(pg.get('enabled', base['page']['enabled']))
            if pg.get('brand'):
                base['page']['brand'] = str(pg['brand'])[:60]
            if pg.get('color'):
                base['page']['color'] = str(pg['color'])[:20]
            base['page']['updated_at'] = int(pg.get('updated_at', 0) or 0)
            src_pages = pg.get('pages') if isinstance(pg.get('pages'), dict) else {}
            for c in PAGE_DEFS:
                cur = src_pages.get(c)
                if isinstance(cur, dict):
                    if 'enabled' in cur:
                        base['page']['pages'][c]['enabled'] = bool(cur['enabled'])
                    for fld in ('title', 'message'):
                        if cur.get(fld) is not None:
                            base['page']['pages'][c][fld] = str(cur[fld])[:600]
        if 'notify' in st and isinstance(st.get('notify'), dict):
            for ch in ('telegram', 'discord'):
                if isinstance(st['notify'].get(ch), dict):
                    base['notify'][ch] = {**default_state()['notify'][ch], **st['notify'][ch]}
        if 'lb' in st:
            base['lb'] = {**default_state()['lb'], **st['lb']}
            base['lb']['health'] = {**default_state()['lb']['health'], **st['lb'].get('health', {})}
            base['lb']['options'] = {**default_state()['lb']['options'], **st['lb'].get('options', {})}
        if isinstance(st.get('loadtest'), dict):
            base['loadtest'] = st['loadtest']
        if isinstance(st.get('dns'), dict):
            base['dns'] = st['dns']
        if isinstance(st.get('access'), dict):
            base['access'] = st['access']
        return base
    except (OSError, ValueError):
        return default_state()


def save_state(st):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


STATE = load_state()


def verify_token(tok):
    if not tok or len(tok) > 4096:
        return False
    now = time.time()
    hit = TOKEN_CACHE.get(tok)
    if hit and hit > now:
        return True
    try:
        req = urllib.request.Request('https://127.0.0.1:9443/api/business/account',
                                     headers={'Authorization': 'Bearer ' + tok})
        with urllib.request.urlopen(req, timeout=5, context=SSL_CTX) as r:
            ok = r.status == 200
    except urllib.error.HTTPError as e:
        ok = e.code == 200
    except Exception:
        ok = False
    if ok:
        TOKEN_CACHE[tok] = now + 60
        if len(TOKEN_CACHE) > 200:
            for k in list(TOKEN_CACHE)[:100]:
                TOKEN_CACHE.pop(k, None)
    return ok


def ts_scale():
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT COALESCE(MAX(created_at), 0) FROM mgt_detect_log_basic')
            v = c.fetchone()[0]
        return 1000 if v > 10 ** 12 else 1
    except Exception:
        return 1


def health():
    pg_ok = False
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT 1')
            c.fetchone()
        pg_ok = True
    except Exception:
        pass
    extver = ''
    try:
        with open(os.path.join(BASE, 'conf', 'extver')) as f:
            extver = f.read().strip()
    except OSError:
        pass
    return {'ok': True, 'pg': pg_ok, 'time': int(time.time()), 'version': VERSION,
            'extver': extver}


def attack_filters(hours, site, action, atype, risk, sites=None):
    sc = ts_scale()
    since = int(time.time() * sc) - hours * 3600 * sc
    where = ['created_at >= %s']
    args = [since]
    if site:
        where.append('host = %s')
        args.append(site)
    elif sites:
        where.append('host = ANY(%s)')
        args.append(list(sites))
    if action is not None:
        where.append('action = %s')
        args.append(action)
    if atype is not None:
        where.append('attack_type = %s')
        args.append(atype)
    else:
        where.append('attack_type >= 0')
    if risk is not None:
        where.append('risk_level >= %s')
        args.append(risk)
    return sc, since, ' AND '.join(where), args


ATTACKS_CACHE = {'at': 0, 'key': '', 'data': None}


def attacks(hours, site='', action=None, atype=None, risk=None, sites=None):
    key = '%s|%s|%s|%s|%s|%s' % (hours, site, action, atype, risk, ','.join(sites or []))
    now = time.time()
    if ATTACKS_CACHE['data'] is not None and ATTACKS_CACHE['key'] == key and now - ATTACKS_CACHE['at'] < 60:
        return ATTACKS_CACHE['data']
    sc, since, where, args = attack_filters(hours, site, action, atype, risk, sites=sites)
    prev = since - hours * 3600 * sc
    out = {'hours': hours, 'total': 0, 'prev_total': 0, 'uniq_ips': 0, 'actions': {},
           'by_type': [], 'timeline': [], 'top_ips': [], 'top_hosts': [],
           'top_paths': [], 'by_country': [], 'by_risk': [], 'geo': [],
           'sites': [], 'scale': sc}
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT COUNT(*) FROM mgt_detect_log_basic WHERE ' + where, args)
            out['total'] = c.fetchone()[0]
            prev_extra = '' if not site else ' AND host = %s'
            prev_args = [prev, since] + ([site] if site else [])
            if not site and sites:
                prev_extra = ' AND host = ANY(%s)'
                prev_args = [prev, since, list(sites)]
            c.execute('SELECT COUNT(*) FROM mgt_detect_log_basic '
                      'WHERE created_at >= %s AND created_at < %s' + prev_extra +
                      ' AND attack_type >= 0', prev_args)
            out['prev_total'] = c.fetchone()[0]
            c.execute('SELECT COUNT(DISTINCT src_ip) FROM mgt_detect_log_basic WHERE ' + where, args)
            out['uniq_ips'] = c.fetchone()[0]
            c.execute('SELECT action, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY action ORDER BY 2 DESC', args)
            out['actions'] = {str(k): v for k, v in c.fetchall()}
            c.execute('SELECT attack_type, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY attack_type ORDER BY 2 DESC LIMIT 15', args)
            out['by_type'] = [{'type': k, 'name': ATTACK_TYPES.get(k, str(k)), 'count': v}
                              for k, v in c.fetchall()]
            bucket = 3600 * sc if hours <= 96 else 86400 * sc
            c.execute('SELECT (created_at / %s) * %s AS b, COUNT(*) FROM mgt_detect_log_basic '
                      'WHERE ' + where + ' GROUP BY b ORDER BY b', [bucket, bucket] + args)
            out['timeline'] = [{'ts': int(k), 'count': v, 'scale': sc} for k, v in c.fetchall()]
            c.execute('SELECT src_ip, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY src_ip ORDER BY 2 DESC LIMIT 10', args)
            out['top_ips'] = [{'ip': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT host, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY host ORDER BY 2 DESC LIMIT 10', args)
            out['top_hosts'] = [{'host': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT url_path, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY url_path ORDER BY 2 DESC LIMIT 10', args)
            out['top_paths'] = [{'path': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT country, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      " AND country <> '' GROUP BY country ORDER BY 2 DESC LIMIT 15", args)
            out['by_country'] = [{'country': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT risk_level, COUNT(*) FROM mgt_detect_log_basic WHERE ' + where +
                      ' GROUP BY risk_level ORDER BY 1', args)
            out['by_risk'] = [{'risk': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT host, COUNT(*) FROM mgt_detect_log_basic '
                      "WHERE created_at >= %s AND host <> '' AND attack_type >= 0 GROUP BY host ORDER BY 2 DESC",
                      [since])
            out['sites'] = [{'host': k, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT lat, lng, country, city, COUNT(*) FROM mgt_detect_log_basic '
                      "WHERE created_at >= %s AND lat <> '' AND lng <> '' AND attack_type >= 0 "
                      'GROUP BY lat, lng, country, city ORDER BY 5 DESC LIMIT 400', [since])
            out['geo'] = [{'lat': k[0], 'lng': k[1], 'country': k[2], 'city': k[3], 'count': k[4]}
                          for k in c.fetchall()]
    except Exception as e:
        out['error'] = str(e)
    ATTACKS_CACHE.update({'at': now, 'key': key, 'data': out})
    return out


def export_rows(hours, site='', action=None, atype=None, risk=None, limit=50000, sites=None):
    sc, since, where, args = attack_filters(hours, site, action, atype, risk, sites=sites)
    with db() as conn, conn.cursor() as c:
        c.execute('SELECT id, created_at, src_ip, country, province, city, host, url_path, '
                  'attack_type, risk_level, action, rule_id, event_id '
                  'FROM mgt_detect_log_basic WHERE ' + where + ' ORDER BY id DESC LIMIT %s',
                  args + [limit])
        return sc, c.fetchall()


CSV_HEADER = ['id', 'time', 'src_ip', 'country', 'province', 'city', 'host', 'url_path',
              'attack_type', 'attack_type_name', 'risk_level', 'action', 'action_name',
              'rule_id', 'event_id']


def export_csv(rows, sc):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEADER)
    for r in rows:
        ts = r[1] / sc if r[1] else 0
        w.writerow([r[0], time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)), r[2], r[3],
                    r[4], r[5], r[6], r[7], r[8], ATTACK_TYPES.get(r[8], ''),
                    r[9], r[10], ACTION_NAMES.get(r[10], ''), r[11], r[12]])
    return buf.getvalue()


def export_json(rows, sc):
    out = []
    for r in rows:
        ts = r[1] / sc if r[1] else 0
        out.append({'id': r[0], 'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)),
                    'src_ip': r[2], 'country': r[3], 'province': r[4], 'city': r[5],
                    'host': r[6], 'url_path': r[7], 'attack_type': r[8],
                    'attack_type_name': ATTACK_TYPES.get(r[8], ''), 'risk_level': r[9],
                    'action': r[10], 'action_name': ACTION_NAMES.get(r[10], ''),
                    'rule_id': r[11], 'event_id': r[12]})
    return json.dumps(out, ensure_ascii=False, indent=1)


LOG_DIR = '/data/safeline/logs/nginx'
SITE_LOG_DIR = os.path.join(LOG_DIR, 'safeline')
TRAFFIC_CACHE = {'at': 0, 'hours': 0, 'data': None}
SEC_CACHE = {'at': 0, 'hours': 0, 'data': None}

UA_BROWSERS = [('Edg/', 'Edge'), ('OPR/', 'Opera'), ('YaBrowser', 'Yandex'),
               ('Firefox/', 'Firefox'), ('Chrome/', 'Chrome'), ('Safari/', 'Safari'),
               ('MSIE', 'IE'), ('Trident', 'IE')]
UA_OS = [('Windows', 'Windows'), ('Android', 'Android'),
         ('iPhone', 'iOS'), ('iPad', 'iOS'), ('Mac OS X', 'macOS'), ('Linux', 'Linux')]
BOT_RX = re.compile(r'bot|spider|crawl|slurp|curl|wget|python|go-http|scanner|nmap|zgrab|'
                    r'java/|okhttp|httpclient|libwww|postman|insomnia', re.I)
PIPE_RE = re.compile(r'^(?P<ip>\S+) \| (?P<user>[^|]*) \| (?P<ts>[^|]+) \| "(?P<host>[^"]*)" \| '
                     r'"(?P<req>[^"]*)" \| (?P<status>\d{3}) \| (?P<bytes>\S+) \| '
                     r'"(?P<ref>[^"]*)" \| "(?P<ua>[^"]*)"')
MAIN_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) '
                     r'(?P<bytes>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')


def ua_parse(ua):
    if not ua or ua == '-':
        return '—', '—', '—'
    if BOT_RX.search(ua):
        device = 'Bot/Tool'
    elif re.search(r'ipad|tablet', ua, re.I):
        device = 'Tablet'
    elif re.search(r'mobile|iphone|android', ua, re.I):
        device = 'Mobile'
    else:
        device = 'Desktop'
    browser = 'Other'
    for rx, name in UA_BROWSERS:
        if rx in ua:
            browser = name
            break
    osname = 'Other'
    for rx, name in UA_OS:
        if rx in ua:
            osname = name
            break
    return browser, osname, device


def parse_ts(s):
    try:
        return int(datetime.datetime.strptime(s.strip(), '%d/%b/%Y:%H:%M:%S %z').timestamp())
    except (ValueError, TypeError):
        return 0


def traffic(hours):
    now = time.time()
    if TRAFFIC_CACHE['data'] and TRAFFIC_CACHE['hours'] == hours and now - TRAFFIC_CACHE['at'] < 60:
        return TRAFFIC_CACHE['data']
    since = int(now - hours * 3600)
    out = {'ok': True, 'hours': hours, 'total': 0, 'lines': 0, 'last_hour': 0,
           'status': {}, 'status_classes': {}, 'browsers': [], 'os': [], 'devices': [],
           'referers': [], 'hosts': [], 'paths': [], 'top_ips': [], 'timeline': [],
           'ua_raw': []}
    status = {}
    cls = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, 'other': 0}
    browsers = {}
    oses = {}
    devices = {}
    refs = {}
    hosts = {}
    paths = {}
    ips = {}
    timeline = {}
    ua_raw = {}
    lines = 0
    files = []
    files += sorted(glob.glob(os.path.join(SITE_LOG_DIR, 'accesslog_*')))
    files += sorted(glob.glob(os.path.join(LOG_DIR, 'access.log*')))
    for path in files:
        try:
            if path.endswith('.gz'):
                fh = gzip.open(path, 'rt', errors='replace')
            else:
                fh = open(path, errors='replace')
            with fh:
                for line in fh:
                    m = PIPE_RE.match(line)
                    is_pipe = True
                    if not m:
                        m = MAIN_RE.match(line)
                        is_pipe = False
                    if not m:
                        continue
                    ts = parse_ts(m.group('ts'))
                    if not ts or ts < since:
                        continue
                    lines += 1
                    st = m.group('status')
                    status[st] = status.get(st, 0) + 1
                    c = st[0] + 'xx'
                    if c in cls:
                        cls[c] += 1
                    else:
                        cls['other'] += 1
                    req = m.group('req') or ''
                    parts = req.split(' ')
                    pth = parts[1] if len(parts) > 1 else req
                    pth = pth.split('?')[0][:200]
                    host = m.group('host') if is_pipe else ''
                    ref = m.group('ref') or '-'
                    b, o, dv = ua_parse(m.group('ua'))
                    browsers[b] = browsers.get(b, 0) + 1
                    oses[o] = oses.get(o, 0) + 1
                    devices[dv] = devices.get(dv, 0) + 1
                    ips[m.group('ip')] = ips.get(m.group('ip'), 0) + 1
                    if ref and ref != '-':
                        try:
                            rp = urllib.parse.urlparse(ref if '//' in ref else '//' + ref)
                            rh = rp.netloc or ref[:80]
                            rpath = rp.path or '/'
                            key = (rh, rpath[:80])
                        except ValueError:
                            key = (ref[:80], '')
                        refs[key] = refs.get(key, 0) + 1
                    if host:
                        hosts[host] = hosts.get(host, 0) + 1
                    pk = ((parts[0] if parts else 'GET')[:8], pth)
                    paths[pk] = paths.get(pk, 0) + 1
                    bkt = ts - (ts % 3600)
                    timeline[bkt] = timeline.get(bkt, 0) + 1
                    if dv == 'Bot/Tool' and len(ua_raw) < 40:
                        ua_raw[m.group('ua')[:120]] = ua_raw.get(m.group('ua')[:120], 0) + 1
        except OSError:
            continue
    out['lines'] = lines
    out['total'] = lines
    out['status'] = dict(sorted(status.items(), key=lambda x: -x[1])[:12])
    out['status_classes'] = cls
    out['browsers'] = [{'name': k, 'count': v} for k, v in sorted(browsers.items(), key=lambda x: -x[1])[:8]]
    out['os'] = [{'name': k, 'count': v} for k, v in sorted(oses.items(), key=lambda x: -x[1])[:8]]
    out['devices'] = [{'name': k, 'count': v} for k, v in sorted(devices.items(), key=lambda x: -x[1])]
    out['referers'] = [{'host': k[0], 'path': k[1], 'count': v}
                       for k, v in sorted(refs.items(), key=lambda x: -x[1])[:10]]
    out['hosts'] = [{'host': k, 'count': v} for k, v in sorted(hosts.items(), key=lambda x: -x[1])[:10]]
    out['paths'] = [{'method': k[0], 'path': k[1], 'count': v}
                    for k, v in sorted(paths.items(), key=lambda x: -x[1])[:10]]
    out['top_ips'] = [{'ip': k, 'count': v} for k, v in sorted(ips.items(), key=lambda x: -x[1])[:10]]
    out['timeline'] = [{'ts': k, 'count': v} for k, v in sorted(timeline.items())]
    out['ua_raw'] = [{'ua': k, 'count': v} for k, v in sorted(ua_raw.items(), key=lambda x: -x[1])[:6]]
    out['simple'] = {'status_by_name': [{'code': k, 'count': v} for k, v in status.items()]}
    out['ua_breakdown'] = {'browsers': out['browsers'], 'devices': out['devices'], 'os': out['os']}
    TRAFFIC_CACHE['at'] = now
    TRAFFIC_CACHE['hours'] = hours
    TRAFFIC_CACHE['data'] = out
    return out


def iter_access(hours):
    since = int(time.time() - hours * 3600)
    files = sorted(glob.glob(os.path.join(SITE_LOG_DIR, 'accesslog_*')))
    files += sorted(glob.glob(os.path.join(LOG_DIR, 'access.log*')))
    for path in files:
        try:
            if path.endswith('.gz'):
                fh = gzip.open(path, 'rt', errors='replace')
            else:
                fh = open(path, errors='replace')
            with fh:
                for line in fh:
                    m = PIPE_RE.match(line) or MAIN_RE.match(line)
                    if not m:
                        continue
                    ts = parse_ts(m.group('ts'))
                    if not ts or ts < since:
                        continue
                    yield ts, m
        except OSError:
            continue


def _cat(ips, timeline):
    return {'total': sum(ips.values()),
            'top_ips': [{'ip': i, 'count': n} for i, n in sorted(ips.items(), key=lambda x: -x[1])[:8]],
            'timeline': [{'ts': t, 'count': n} for t, n in sorted(timeline.items())]}


def security_stats(hours):
    if SEC_CACHE['data'] and SEC_CACHE['hours'] == hours and time.time() - SEC_CACHE['at'] < 60:
        return SEC_CACHE['data']
    cats = {k: ({}, {}) for k in ('rate_limit', 'waiting_room', 'anti_bot', 'auth')}
    for ts, m in iter_access(hours):
        st = m.group('status')
        ip = m.group('ip')
        key = None
        if st == '429':
            key = 'rate_limit'
        elif st == '465':
            key = 'waiting_room'
        elif st == '468':
            key = 'anti_bot'
        elif st in ('401', '403'):
            req = m.group('req') or ''
            pth = req.split(' ')[1] if ' ' in req else req
            if pth.startswith('/.safeline/'):
                key = 'auth'
        if not key:
            continue
        ips, timeline = cats[key]
        ips[ip] = ips.get(ip, 0) + 1
        b = ts - (ts % 3600)
        timeline[b] = timeline.get(b, 0) + 1
    out = {'ok': True, 'hours': hours}
    for k, (ips, timeline) in cats.items():
        out[k] = _cat(ips, timeline)
    sc = ts_scale()
    since = int(time.time() * sc) - hours * 3600 * sc
    bucket = 3600 * sc
    acl_total, rules, acl_tl, pages, apps, att_tl = 0, [], [], [], [], []
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT COUNT(*) FROM mgt_detect_log_basic WHERE created_at >= %s '
                      'AND attack_type IN (-3, -2)', (since,))
            acl_total = c.fetchone()[0]
            c.execute('SELECT policy_name, rule_id, COUNT(*) FROM mgt_detect_log_basic '
                      'WHERE created_at >= %s AND attack_type IN (-3, -2) '
                      'GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 8', (since,))
            rules = [{'rule': (r[0] or r[1] or 'rule'), 'count': r[2]} for r in c.fetchall()]
            c.execute('SELECT (created_at / %s) * %s AS b, COUNT(*) FROM mgt_detect_log_basic '
                      'WHERE created_at >= %s AND attack_type IN (-3, -2) GROUP BY b ORDER BY b',
                      (bucket, bucket, since))
            acl_tl = [{'ts': int(k) / sc, 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT url_path, COUNT(*) FROM mgt_detect_log_basic WHERE created_at >= %s '
                      'GROUP BY 1 ORDER BY 2 DESC LIMIT 10', (since,))
            pages = [{'path': k or '/', 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT host, COUNT(*) FROM mgt_detect_log_basic WHERE created_at >= %s '
                      'GROUP BY 1 ORDER BY 2 DESC LIMIT 10', (since,))
            apps = [{'host': k or '—', 'count': v} for k, v in c.fetchall()]
            c.execute('SELECT (created_at / %s) * %s AS b, COUNT(*) FROM mgt_detect_log_basic '
                      'WHERE created_at >= %s GROUP BY b ORDER BY b', (bucket, bucket, since))
            att_tl = [{'ts': int(k) / sc, 'count': v} for k, v in c.fetchall()]
    except Exception as e:
        out['error'] = str(e)[:300]
    out['acl_rule'] = {'total': acl_total, 'rules': rules, 'timeline': acl_tl}
    out['pages'] = pages
    out['apps'] = apps
    out['attacks_timeline'] = att_tl
    out['attacks_total'] = sum(x['count'] for x in att_tl)
    SEC_CACHE['at'] = time.time()
    SEC_CACHE['hours'] = hours
    SEC_CACHE['data'] = out
    return out


def notify_send(text, kind='all', min_risk=0):
    results = {}
    with LOCK:
        notify = json.loads(json.dumps(STATE['notify']))
    tg = notify.get('telegram', {})
    if kind in ('all', 'telegram') and tg.get('enabled') and tg.get('bot_token') and tg.get('chat_id'):
        try:
            url = 'https://api.telegram.org/bot%s/sendMessage' % tg['bot_token']
            data = json.dumps({'chat_id': tg['chat_id'], 'text': text,
                               'disable_web_page_preview': True}).encode()
            req = urllib.request.Request(url, data=data,
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as r:
                json.loads(r.read().decode())
            results['telegram'] = True
        except Exception as e:
            results['telegram'] = False
            with LOCK:
                STATE['notify']['telegram']['last_error'] = str(e)[:300]
    dc = notify.get('discord', {})
    if kind in ('all', 'discord') and dc.get('enabled') and dc.get('webhook'):
        try:
            body = json.dumps({'content': text[:1900], 'username': 'SafeLine'}).encode()
            req = urllib.request.Request(dc['webhook'], data=body,
                                         headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read()
            results['discord'] = True
        except Exception as e:
            results['discord'] = False
            with LOCK:
                STATE['notify']['discord']['last_error'] = str(e)[:300]
    if results:
        with LOCK:
            save_state(STATE)
    syslog_send({'event': 'notify', 'text': text, 'channels': results})
    return results


def syslog_send(obj):
    with LOCK:
        cfg = dict(STATE.get('syslog') or {})
    if not cfg.get('enabled') or not cfg.get('host'):
        return False
    line = (json.dumps({'ts': int(time.time()), 'host': socket.gethostname(),
                        'slext': VERSION, **obj}, ensure_ascii=False) + '\n').encode()
    try:
        if cfg.get('proto') == 'tcp':
            with socket.create_connection((cfg['host'], int(cfg.get('port', 514))), timeout=5) as s:
                s.sendall(line)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(line, (cfg['host'], int(cfg.get('port', 514))))
            s.close()
        return True
    except Exception as e:
        with LOCK:
            STATE['syslog']['last_error'] = str(e)[:300]
        return False


def run(cmd, timeout=60, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        return p.returncode, (p.stdout or '').strip(), (p.stderr or '').strip()
    except Exception as e:
        return 1, '', str(e)


def cscli(args, timeout=30):
    return run(['cscli'] + args, timeout=timeout)


def crowdsec_list():
    now = time.time()
    if CS_CACHE['data'] and now - CS_CACHE['at'] < 10:
        return CS_CACHE['data']
    rc, out, err = cscli(['decisions', 'list', '-o', 'json'])
    if rc != 0:
        return {'ok': False, 'error': (err or out)[:300]}
    try:
        alerts = json.loads(out or '[]')
    except ValueError:
        return {'ok': False, 'error': 'bad cscli json'}
    decisions = []
    for a in alerts:
        meta = {}
        ev = (a.get('events') or [{}])[0]
        for m in (ev.get('meta') or []):
            meta[m.get('key')] = m.get('value')
        for d in a.get('decisions') or []:
            decisions.append({
                'id': d.get('id'), 'ip': d.get('value'), 'type': d.get('type'),
                'scenario': d.get('scenario'), 'duration': d.get('duration'),
                'origin': d.get('origin'), 'created_at': a.get('created_at'),
                'events': len(a.get('events') or []),
                'country': meta.get('IsoCode', ''), 'asn': meta.get('ASNNumber', ''),
                'as_org': meta.get('ASNOrg', ''),
            })
    data = {'ok': True, 'decisions': decisions, 'count': len(decisions)}
    CS_CACHE['data'] = data
    CS_CACHE['at'] = now
    return data


def valid_ip(ip):
    try:
        return str(ipaddress.ip_address(str(ip or '').strip()))
    except ValueError:
        return None


def crowdsec_ban(ip, duration, reason):
    ip = valid_ip(ip)
    if not ip:
        return False, 'bad ip'
    dur = str(duration or '4h')[:16]
    if not re.match(r'^\d+[smh]$', dur):
        dur = '4h'
    args = ['decisions', 'add', '--ip', ip, '--duration', dur,
            '--reason', ('slext: ' + str(reason or 'manual ban'))[:128]]
    rc, out, err = cscli(args)
    CS_CACHE['data'] = None
    return rc == 0, (err or out)[:300]


def crowdsec_unban(ip):
    ip = valid_ip(ip)
    if not ip:
        return False, 'bad ip'
    rc, out, err = cscli(['decisions', 'delete', '--ip', ip])
    CS_CACHE['data'] = None
    return rc == 0, (err or out)[:300]


def node_up(addr):
    return NODES.get(addr, {}).get('up', True)


ALGO_LINES = {
    'least_conn': 'least_conn;',
    'ip_hash': 'ip_hash;',
    'hash_uri': 'hash $request_uri consistent;',
    'hash_cookie': 'hash $cookie_slext$remote_addr consistent;',
    'random_two': 'random two;',
}


def render_lb(lb):
    algo = lb.get('algorithm', 'round_robin')
    opts = lb.get('options') or {}
    lines = ['# slext load balancer (autogenerated)', 'upstream slext_lb {']
    if ALGO_LINES.get(algo):
        lines.append('    ' + ALGO_LINES[algo])
    keepalive = max(0, min(1024, int(opts.get('keepalive', 0) or 0)))
    if keepalive > 0:
        lines.append('    keepalive %d;' % keepalive)
    max_fails = max(0, min(100, int(opts.get('passive_max_fails', 3) or 3)))
    fail_timeout = max(1, min(3600, int(opts.get('passive_fail_timeout', 10) or 10)))
    h = lb.get('health') or {}
    servers = []
    for b in lb.get('backends', []):
        if not b.get('enabled', True):
            continue
        if h.get('enabled', True) and not node_up(b['addr']):
            continue
        servers.append(b)
    if not servers:
        lines.append('    server 127.0.0.1:9 down;')
    for b in servers:
        w = max(1, min(100, int(b.get('weight', 1))))
        parts = ['server %s weight=%d max_fails=%d fail_timeout=%ds' % (b['addr'], w, max_fails, fail_timeout)]
        mc = int(b.get('max_conns', 0) or 0)
        if mc > 0:
            parts.append('max_conns=%d' % min(100000, mc))
        if b.get('role') == 'backup':
            parts.append('backup')
        lines.append('    ' + ' '.join(parts) + ';')
    lines.append('}')
    lines.append('')
    lines.append('server {')
    lines.append('    listen 127.0.0.1:8081;')
    lines.append('    location / {')
    lines.append('        proxy_pass http://slext_lb;')
    lines.append('        proxy_http_version 1.1;')
    if keepalive > 0:
        lines.append('        proxy_set_header Connection "";')
    lines.append('        proxy_set_header Host $host;')
    lines.append('        proxy_set_header X-Real-IP $remote_addr;')
    lines.append('        proxy_connect_timeout %ds;' % max(1, min(600, int(opts.get('connect_timeout', 5) or 5))))
    lines.append('        proxy_send_timeout %ds;' % max(1, min(3600, int(opts.get('send_timeout', 60) or 60))))
    lines.append('        proxy_read_timeout %ds;' % max(1, min(3600, int(opts.get('read_timeout', 300) or 300))))
    if opts.get('retry_5xx', True):
        lines.append('        proxy_next_upstream error timeout http_502 http_503 http_504;')
    lines.append('        proxy_next_upstream_tries %d;' % max(1, min(10, int(opts.get('tries', 3) or 3))))
    lines.append('    }')
    lines.append('}')
    lines.append('')
    return '\n'.join(lines)


def lb_apply():
    with LOCK:
        text = render_lb(STATE['lb'])
    os.makedirs(os.path.dirname(LB_CONF), exist_ok=True)
    with open(LB_CONF, 'w') as f:
        f.write(text)
    p = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if p.returncode != 0:
        return False, (p.stderr or p.stdout).strip()
    p = subprocess.run(['nginx', '-s', 'reload'], capture_output=True, text=True)
    return p.returncode == 0, (p.stderr or p.stdout).strip()


def backend_status(lb):
    with LOCK:
        nodes = {k: dict(v) for k, v in NODES.items()}
    res = []
    for b in lb.get('backends', []):
        st = nodes.get(b['addr'], {'fails': 0, 'up': True})
        res.append({**b, 'up': st.get('up', True), 'fails': st.get('fails', 0)})
    return res


def check_node(addr, path, timeout):
    host, _, port = addr.rpartition(':')
    try:
        req = urllib.request.Request('http://%s:%s%s' % (host, port, path), method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 500
    except Exception:
        return False


def lb_worker():
    last = 0
    while True:
        try:
            with LOCK:
                lb = json.loads(json.dumps(STATE['lb']))
            h = lb.get('health') or {}
            now = time.time()
            if h.get('enabled', True) and now - last >= max(5, int(h.get('interval', 15))):
                last = now
                changed = False
                for b in lb.get('backends', []):
                    if not b.get('enabled', True):
                        continue
                    addr = b['addr']
                    ok = check_node(addr, h.get('path', '/'), float(h.get('timeout', 3)))
                    st = NODES.setdefault(addr, {'fails': 0, 'up': True})
                    if ok:
                        st['fails'] = 0
                        if not st['up']:
                            st['up'] = True
                            changed = True
                            notify_send('SLExt: узел %s снова доступен' % addr)
                    else:
                        st['fails'] += 1
                        if st['up'] and st['fails'] >= int(h.get('failures', 3)):
                            st['up'] = False
                            changed = True
                            notify_send('SLExt: узел %s недоступен и исключён из балансировки' % addr)
                if changed:
                    lb_apply()
        except Exception:
            pass
        time.sleep(3)


def notify_worker():
    while True:
        try:
            with LOCK:
                tg = dict(STATE['notify']['telegram'])
                dc = dict(STATE['notify']['discord'])
            tg_on = bool(tg.get('enabled') and tg.get('bot_token') and tg.get('chat_id'))
            dc_on = bool(dc.get('enabled') and dc.get('webhook'))
            if tg_on or dc_on:
                min_risk = min(int(tg.get('min_risk', 0) or 0) if tg_on else 10,
                               int(dc.get('min_risk', 0) or 0) if dc_on else 10)
                with db() as conn, conn.cursor() as c:
                    c.execute('SELECT id, src_ip, host, url_path, attack_type, action, risk_level, country '
                              'FROM mgt_detect_log_basic WHERE id > %s ORDER BY id ASC LIMIT 10',
                              (int(tg.get('last_id', 0)),))
                    rows = c.fetchall()
                for r in rows:
                    sent_tg = sent_dc = False
                    if int(r[6] or 0) >= min_risk:
                        text = ('SafeLine: атака обнаружена\n'
                                'IP: %s (%s)\nХост: %s\nПуть: %s\nТип: %s | action: %s | risk: %s\nВремя: %s' %
                                (r[1], r[7] or '-', r[2], r[3],
                                 ATTACK_TYPES.get(r[4], r[4]), ACTION_NAMES.get(r[5], r[5]), r[6],
                                 time.strftime('%Y-%m-%d %H:%M:%S')))
                        res = notify_send(text)
                        sent_tg = bool(res.get('telegram'))
                        sent_dc = bool(res.get('discord'))
                    if (tg_on and not sent_tg) or (dc_on and not sent_dc):
                        break
                    now = int(time.time())
                    with LOCK:
                        STATE['notify']['telegram']['last_id'] = r[0]
                        if sent_tg:
                            STATE['notify']['telegram']['last_send'] = now
                            STATE['notify']['telegram']['last_error'] = ''
                        if sent_dc:
                            STATE['notify']['discord']['last_send'] = now
                            STATE['notify']['discord']['last_error'] = ''
                        save_state(STATE)
                    time.sleep(0.3)
        except Exception:
            pass
        time.sleep(5)


METRICS = {
    'attacks': '1=1',
    'blocked': 'action = 1',
    'high_risk': 'risk_level >= 4',
}


def alarm_worker():
    while True:
        try:
            with LOCK:
                alarm = json.loads(json.dumps(STATE['alarm']))
            if alarm.get('enabled'):
                now = int(time.time())
                for rule in alarm.get('rules') or []:
                    if not rule.get('enabled', True):
                        continue
                    window = clamp_int(rule.get('window'), 1, 1440, 5)
                    cooldown = clamp_int(rule.get('cooldown'), 1, 1440, 30)
                    if now - int(rule.get('last_fired', 0)) < cooldown * 60:
                        continue
                    metric = METRICS.get(rule.get('metric', 'attacks'), '1=1')
                    sc = ts_scale()
                    since = int(now * sc) - window * 60 * sc
                    with db() as conn, conn.cursor() as c:
                        c.execute('SELECT COUNT(*) FROM mgt_detect_log_basic '
                                  'WHERE created_at >= %s AND ' + metric, (since,))
                        count = c.fetchone()[0]
                    if count >= clamp_int(rule.get('threshold'), 1, 10 ** 9, 20):
                        text = ('SafeLine alarm: %s\n%s за %d мин: %s (порог %s)' %
                                (rule.get('name', rule.get('id')), rule.get('metric', 'attacks'),
                                 window, count, rule.get('threshold')))
                        res = notify_send(text)
                        with LOCK:
                            for r in STATE['alarm']['rules']:
                                if r.get('id') == rule.get('id'):
                                    r['last_fired'] = now
                            save_state(STATE)
        except Exception:
            pass
        time.sleep(60)


def do_backup():
    with LOCK:
        cfg = dict(STATE.get('backup') or {})
    outdir = cfg.get('dir') or '/var/backups/slext'
    os.makedirs(outdir, exist_ok=True)
    try:
        os.chmod(outdir, 0o700)
    except OSError:
        pass
    name = time.strftime('slext-%Y%m%d-%H%M%S.tar.gz')
    path = os.path.join(outdir, name)
    date = time.strftime('%Y-%m-%d %H:%M:%S')
    tmpdb = '/tmp/slext-pg.sql'
    rc, o, e = run(['docker', 'exec', 'safeline-pg', 'pg_dump', '-U', 'safeline-ce',
                    'safeline-ce'], timeout=120)
    if rc != 0:
        return False, (e or o)[:300]
    with open(tmpdb, 'w') as f:
        f.write(o)
    try:
        with tarfile.open(path, 'w:gz') as tar:
            tar.add(os.path.join(BASE, 'conf'), arcname='conf')
            if os.path.isdir(GEO_NGINX_DIR):
                tar.add(GEO_NGINX_DIR, arcname='nginx/slext-geo')
            if os.path.isdir(PAGES_DIR):
                tar.add(PAGES_DIR, arcname='nginx/slext-pages')
            tar.add(LB_CONF, arcname='nginx/lb-upstreams.conf')
            tar.add(tmpdb, arcname='db/safeline-ce.sql')
    finally:
        try:
            os.remove(tmpdb)
        except OSError:
            pass
    keep = clamp_int(cfg.get('keep_days'), 1, 365, 7)
    cutoff = time.time() - keep * 86400
    for fn in os.listdir(outdir):
        fp = os.path.join(outdir, fn)
        if fn.endswith('.tar.gz') and os.path.getmtime(fp) < cutoff:
            try:
                os.remove(fp)
            except OSError:
                pass
    with LOCK:
        STATE['backup']['last_run'] = int(time.time())
        STATE['backup']['last_error'] = ''
        save_state(STATE)
    return True, path


def backup_worker():
    while True:
        try:
            with LOCK:
                cfg = dict(STATE.get('backup') or {})
            if cfg.get('enabled'):
                now = time.time()
                lt = time.localtime(now)
                hour = clamp_int(cfg.get('hour'), 0, 23, 4)
                if lt.tm_hour >= hour and now - int(cfg.get('last_run', 0)) > 20 * 3600:
                    ok, info = do_backup()
                    if not ok:
                        with LOCK:
                            STATE['backup']['last_error'] = info
                            save_state(STATE)
        except Exception:
            pass
        time.sleep(600)


def load_countries():
    try:
        with open(COUNTRIES_FILE, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and data:
            return data
    except (OSError, ValueError):
        pass
    return {}


def geo_cached(cc):
    fn = os.path.join(GEO_DIR, cc.lower() + '.zone')
    try:
        with open(fn) as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def geo_fetch(cc):
    cc = (cc or '').upper()
    if not re.match(r'^[A-Z]{2}$', cc):
        return False, 'bad country code'
    os.makedirs(GEO_DIR, exist_ok=True)
    url = IPDENY_URL % cc.lower()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'slext/3.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read().decode()
    except Exception as e:
        return False, 'download failed: %s' % str(e)[:200]
    lines = [ln.strip() for ln in data.splitlines() if CIDR_PATTERN.match(ln.strip())]
    if not lines:
        return False, 'empty zone'
    tmp = os.path.join(GEO_DIR, cc.lower() + '.zone.tmp')
    with open(tmp, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(tmp, os.path.join(GEO_DIR, cc.lower() + '.zone'))
    return True, len(lines)


def geo_apply():
    with LOCK:
        geo = json.loads(json.dumps(STATE['geo']))
    cc = [c.upper() for c in (geo.get('countries') or []) if re.match(r'^[A-Za-z]{2}$', str(c))]
    os.makedirs(GEO_NGINX_DIR, exist_ok=True)
    os.makedirs(os.path.join(NGINX_ROOT, 'conf.d'), exist_ok=True)
    disabled = (not geo.get('enabled')) or (not cc)
    default = 0
    val = 1
    if geo.get('mode') == 'allow':
        default = 1
        val = 0
    lines = []
    missing = []
    for c in cc:
        fn = os.path.join(GEO_DIR, c.lower() + '.zone')
        try:
            with open(fn) as f:
                for ln in f:
                    ln = ln.strip()
                    if CIDR_PATTERN.match(ln):
                        lines.append('%s %d;' % (ln, val))
        except OSError:
            missing.append(c)
    with open(os.path.join(GEO_NGINX_DIR, 'deny.list'), 'w') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))
    with open(os.path.join(NGINX_ROOT, 'conf.d', 'zz_slext_geo.conf'), 'w') as f:
        f.write('# slext geo (autogenerated)\n')
        if not disabled:
            f.write('geo $slext_geo_deny {\n    default %d;\n' % default)
            f.write('    include /etc/nginx/slext-geo/deny.list;\n}\n')
        else:
            f.write('geo $slext_geo_deny {\n    default 0;\n}\n')
    with open(os.path.join(GEO_NGINX_DIR, 'check.conf'), 'w') as f:
        f.write('# slext geo check (autogenerated)\n')
        if not disabled:
            f.write('if ($slext_geo_deny = 1) { return 403; }\n')
    rc, out, err = run(['/opt/slext/bin/apply-injection.sh'], timeout=120)
    ok = rc == 0
    rc2, out2, err2 = run(['docker', 'exec', 'safeline-tengine', 'nginx', '-t'], timeout=60)
    if rc2 == 0:
        run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reload'], timeout=60)
    else:
        ok = False
    with LOCK:
        STATE['geo']['updated_at'] = int(time.time())
        STATE['geo']['last_error'] = ''
        if missing:
            STATE['geo']['last_error'] = 'no zone data: ' + ','.join(missing)
        if not ok:
            STATE['geo']['last_error'] = ('apply failed: ' + (err or out))[:300]
        save_state(STATE)
    return ok, {'missing': missing, 'cidrs': len(lines), 'error': STATE['geo']['last_error']}


def page_html(code, cfg, page):
    import html as _html
    d = PAGE_DEFS.get(code, PAGE_DEFS['403'])
    title = str(cfg.get('title') or d['title'])[:120]
    message = str(cfg.get('message') or d['message'])[:600]
    brand = str(page.get('brand') or 'SafeLine WAF')[:60]
    color = str(page.get('color') or '')
    if not color or color == '#0fc6c2':
        color = str(d.get('color') or '')
    if not re.match(r'^#[0-9a-fA-F]{3,8}$', color):
        color = '#0067B8'
    button = ''
    refresh = ''
    if code in ('429', '465', '466', '502', '504'):
        button = '<a class="btn" href="javascript:location.reload()">Обновить страницу</a>'
    if code in ('465', '466', '502', '504'):
        refresh = '<meta http-equiv="refresh" content="60">'
    elif code == '404':
        button = '<a class="btn" href="/">На главную</a>'
    return PAGE_TEMPLATE.safe_substitute(
        title=_html.escape(title), message=_html.escape(message),
        brand=_html.escape(brand), accent=color, button=button, refresh=refresh)


def page_apply():
    with LOCK:
        page = json.loads(json.dumps(STATE['page']))
    os.makedirs(PAGES_DIR, exist_ok=True)
    try:
        queue_write_page()
    except Exception:
        pass
    for code, d in PAGE_DEFS.items():
        target = os.path.join(PAGES_DIR, d['file'])
        cfg = (page.get('pages') or {}).get(code) or {}
        if page.get('enabled') and cfg.get('enabled', True):
            if code == '465':
                sites = site_list()
                host = (sites[0]['hosts'] or [''])[0] if sites else ''
                with LOCK:
                    panel_base = str((STATE.get('waiting') or {}).get('panel_base') or '')
                content = waiting_page_html(host, waiting_cfg(host), panel_base)
            else:
                content = page_html(code, cfg, page)
            with open(target, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            try:
                os.remove(target)
            except OSError:
                pass
    cmd = ['python3', PAGE_PATCH]
    for fn in sorted(os.listdir(os.path.join(NGINX_ROOT, 'sites-enabled'))):
        if fn.startswith('IF_'):
            cmd.append(os.path.join(NGINX_ROOT, 'sites-enabled', fn))
    rc, out, err = run(cmd, timeout=60)
    if rc != 0:
        return False, (err or out)[:300]
    rc, out, err = run(['docker', 'exec', 'safeline-tengine', 'nginx', '-t'], timeout=60)
    if rc != 0:
        return False, (err or out)[:300]
    run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reload'], timeout=60)
    with LOCK:
        STATE['page']['updated_at'] = int(time.time())
        save_state(STATE)
    return True, 'ok'


MGT_BASE = 'https://127.0.0.1:9443'
_SITE_CACHE = {'at': 0, 'sites': []}


def _jwt_payload(tok):
    try:
        payload = str(tok).split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()).decode('utf-8', 'replace'))
    except Exception:
        return {}


def _jwt_username(tok):
    return str(_jwt_payload(tok).get('Username') or '')


_MGT_TOKEN_CACHE = {'tok': '', 'at': 0}


def mgt_token():
    """Токен панели, который реально принимает mgt (кеш 5 минут).

    Часть токенов mgt отклоняет (несогласованное 2FA-состояние и т.п.),
    поэтому кандидат проверяется живым запросом; приоритет — admin.
    """
    now = time.time()
    cached = _MGT_TOKEN_CACHE['tok']
    if cached and now - _MGT_TOKEN_CACHE['at'] < 300:
        return cached
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT token FROM mgt_auth_token WHERE (expire IS NULL OR expire = 0 OR expire > %s) '
                      'ORDER BY id DESC LIMIT 30', (int(time.time()),))
            rows = [r[0] for r in c.fetchall()]
    except Exception:
        return ''
    if not rows:
        return ''
    ordered = sorted(rows, key=lambda t: 0 if _jwt_username(t) == 'admin' else 1)
    for tok in ordered[:10]:
        code, _ = mgt_request('GET', '/api/business/account', token=tok)
        if code == 200:
            _MGT_TOKEN_CACHE.update({'tok': tok, 'at': now})
            return tok
    return ordered[0]


def mgt_request(method, path, body=None, token=None):
    tok = token or mgt_token()
    data = json.dumps(body).encode() if body is not None else None
    headers = {'Content-Type': 'application/json'}
    if tok:
        headers['Authorization'] = 'Bearer ' + tok
    req = urllib.request.Request(MGT_BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15, context=SSL_CTX) as r:
            return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or '{}')
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {'error': str(e)[:200]}


def site_list():
    now = time.time()
    if _SITE_CACHE['sites'] and now - _SITE_CACHE['at'] < 60:
        return _SITE_CACHE['sites']
    sites = []
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT id, comment, server_names FROM mgt_website ORDER BY id')
            for sid, comment, names in c.fetchall():
                if isinstance(names, str):
                    try:
                        hosts = json.loads(names or '[]')
                    except ValueError:
                        hosts = []
                else:
                    hosts = list(names or [])
                sites.append({'id': sid, 'comment': comment or '', 'hosts': hosts})
    except Exception:
        pass
    _SITE_CACHE['sites'] = sites
    _SITE_CACHE['at'] = now
    return sites


def site_by_host(host):
    for s in site_list():
        if host in s['hosts']:
            return s
    return None


def waiting_conf(site_id, token=None):
    code, data = mgt_request('GET', '/api/open/site/%d/waiting' % site_id, token=token)
    if code == 200 and isinstance(data, dict) and data.get('data'):
        return data['data']
    return {}


def waiting_set_enabled(site_id, enabled, token=None):
    """POST + подтверждение факта. Возвращает (ok, conf, error)."""
    last_err = ''
    for attempt in range(3):
        code, data = mgt_request('POST', '/api/open/site/%d/waiting' % site_id,
                                 {'is_enabled': bool(enabled)}, token=token)
        if code != 200:
            msg = ''
            if isinstance(data, dict):
                msg = str(data.get('msg') or data.get('error') or '')
            last_err = msg or ('SafeLine ответил HTTP %s' % code)
        for _ in range(6):
            time.sleep(0.5)
            conf = waiting_conf(site_id, token=token)
            if bool(conf.get('is_enabled')) == bool(enabled):
                MGT_CONF_CACHE[site_id] = (time.time(), conf)
                return True, conf, ''
        if not last_err:
            last_err = 'SafeLine не подтвердил переключение'
    return False, waiting_conf(site_id, token=token), last_err


MGT_CONF_CACHE = {}
WR_OP_LOCK = threading.Lock()
WR_PATCH = {'ts': 0, 'ok': None, 'info': '', 'running': False}
WR_SESSIONS = {}


def mgt_conf_cached(site_id, ttl=5.0):
    now = time.time()
    ts, conf = MGT_CONF_CACHE.get(site_id, (0, {}))
    if conf and now - ts < ttl:
        return conf
    conf = waiting_conf(site_id)
    if conf:
        MGT_CONF_CACHE[site_id] = (now, conf)
    return conf


def mgt_conf_forget(site_id):
    MGT_CONF_CACHE.pop(site_id, None)


def _wr_cfg(host):
    with LOCK:
        return json.loads(json.dumps(((STATE.get('waiting') or {}).get('sites') or {}).get(host) or {}))


def _wr_state_patch(host, patch):
    with LOCK:
        sites = STATE.setdefault('waiting', {}).setdefault('sites', {})
        st = sites.setdefault(host, {}).setdefault('state', {})
        st.update(patch)
        save_state(STATE)


def site_patch_fast():
    """Быстрое восстановление патчей сайта после перегенерации конфига SafeLine."""
    try:
        sdir = os.path.join(NGINX_ROOT, 'sites-enabled')
        files = []
        for fn in sorted(os.listdir(sdir)):
            if not fn.startswith('IF_') or fn.endswith(('.orig', '.bak', '.slext-orig')):
                continue
            p = os.path.join(sdir, fn)
            files.append(p)
            try:
                txt = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            orig = txt
            if 'access_log /var/log/nginx/access.log safeline' not in txt:
                txt = re.sub(r'(^[ \t]*server_name .*;\n)',
                             r'\1    access_log /var/log/nginx/access.log safeline;\n',
                             txt, count=1, flags=re.M)
            if 'slext-geo/check.conf' not in txt:
                txt = re.sub(r'(^[ \t]*server_name .*;\n)',
                             r'\1    include /etc/nginx/slext-geo/check.conf;\n',
                             txt, count=1, flags=re.M)
            if txt != orig:
                try:
                    open(p, 'w', encoding='utf-8').write(txt)
                except OSError:
                    pass
        rc, out, err = run(['python3', PAGE_PATCH] + files, timeout=60)
        if rc != 0:
            return False, (err or out)[:300]
        rc, out, err = run(['docker', 'exec', 'safeline-tengine', 'nginx', '-t'], timeout=60)
        if rc != 0:
            return False, (err or out)[:300]
        run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reload'], timeout=60)
        return True, 'ok'
    except Exception as e:
        return False, str(e)[:300]


def site_patch_ensure(delay=1.2):
    """Фоновое восстановление патчей; повторные вызовы схлопываются."""
    with LOCK:
        if WR_PATCH.get('running'):
            return
        WR_PATCH['running'] = True

    def _job():
        try:
            time.sleep(delay)
            ok, info = site_patch_fast()
            with LOCK:
                WR_PATCH.update({'ts': int(time.time()), 'ok': ok, 'info': (info or '')[:300]})
                save_state(STATE)
        except Exception:
            pass
        finally:
            with LOCK:
                WR_PATCH['running'] = False

    threading.Thread(target=_job, daemon=True).start()


def site_markers_ok():
    try:
        sdir = os.path.join(NGINX_ROOT, 'sites-enabled')
        for fn in os.listdir(sdir):
            if not fn.startswith('IF_') or fn.endswith(('.orig', '.bak', '.slext-orig')):
                continue
            try:
                txt = open(os.path.join(sdir, fn), encoding='utf-8', errors='replace').read()
            except OSError:
                return False
            if 'slext-page' not in txt or 'slext-gate' not in txt:
                return False
        return True
    except OSError:
        return False


def wr_read_actual(site_id, token=None, tries=3, pause=0.4):
    """Чтение фактического состояния зала. -> (ok, actual|None, conf)"""
    for _ in range(max(1, tries)):
        conf = waiting_conf(site_id, token=token)
        if conf:
            return True, bool(conf.get('is_enabled')), conf
        time.sleep(pause)
    return False, None, {}


def wr_limits_set(host, site_id, max_concurrent=None, session_timeout=None, max_waiting=None):
    """Лимиты зала сайта: желаемые в state, строка mgt (website_id), waiting.yaml.

    Панельный API CE лимиты не меняет, а mgt в момент переключения зала
    синхронизирует модуль со строкой mgt_waiting_room сайта. Поэтому значения
    применяются перед каждым включением (см. wr_apply) и лечатся воркером.
    """
    lim = {}
    if max_concurrent is not None:
        lim['max_concurrent'] = clamp_int(max_concurrent, 1, 5000, 100)
    if session_timeout is not None:
        lim['session_timeout'] = clamp_int(session_timeout, 1, 30, 3)
    if max_waiting is not None:
        lim['max_waiting'] = clamp_int(max_waiting, 0, 100000, 200)
    if not lim:
        return False, 'нечего менять'
    if not site_id:
        return False, 'сайт не найден'
    with LOCK:
        sites = STATE.setdefault('waiting', {}).setdefault('sites', {})
        cfg = sites.setdefault(host, {})
        cur = dict(cfg.get('limits') or {})
        cur.update(lim)
        cfg['limits'] = cur
        save_state(STATE)
    ok, err = wr_limits_sql(site_id, lim)
    if ok:
        wr_limits_yaml(lim)
    return ok, err


def wr_limits_sql(site_id, lim):
    sets, vals = [], []
    for k in ('max_concurrent', 'max_waiting', 'session_timeout'):
        if k in lim:
            sets.append(k + '=%s')
            vals.append(int(lim[k]))
    if not sets:
        return True, ''
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('UPDATE mgt_waiting_room SET ' + ', '.join(sets) +
                      ', updated_at=now() WHERE website_id=%s', vals + [int(site_id)])
            if c.rowcount == 0:
                # строки ещё нет (зал не включали) — создаём с нашими лимитами
                mc = int(lim.get('max_concurrent') or 100)
                mw = int(lim.get('max_waiting') or 200)
                st = int(lim.get('session_timeout') or 3)
                c.execute('INSERT INTO mgt_waiting_room (created_at, updated_at, name, is_enabled, '
                          'max_concurrent, max_waiting, session_timeout, website_id) '
                          'VALUES (now(), now(), %s, false, %s, %s, %s, %s)',
                          ('website_waiting_room_%d' % int(site_id), mc, mw, st, int(site_id)))
            conn.commit()
        mgt_conf_forget(int(site_id))
        return True, ''
    except Exception as e:
        return False, str(e)[:200]


WR_YAML = '/data/safeline/resources/chaos/waiting.yaml'


def wr_limits_yaml(lim):
    """Пишем лимиты и в waiting.yaml (дефолты модуля). Один раз делаем бэкап."""
    try:
        txt = open(WR_YAML, encoding='utf-8', errors='replace').read()
    except OSError:
        return
    orig = txt
    if not os.path.exists(WR_YAML + '.slext-orig'):
        try:
            import shutil as _sh
            _sh.copy2(WR_YAML, WR_YAML + '.slext-orig')
        except OSError:
            pass
    mapping = {'max_concurrent': 'max_concurrent', 'max_waiting': 'max_waiting'}
    for k, y in mapping.items():
        if k in lim:
            txt = re.sub(r'^(\s*%s:)\s*\d+' % y, r'\g<1> %d' % int(lim[k]), txt, flags=re.M)
    yto = {'session_timeout': 'cp_session_timeout'}
    if 'session_timeout' in lim:
        secs = int(lim['session_timeout']) * 60 if int(lim['session_timeout']) <= 30 else int(lim['session_timeout'])
        txt = re.sub(r'^(\s*cp_session_timeout:)\s*\d+', r'\g<1> %d' % secs, txt, flags=re.M)
    if txt != orig:
        try:
            open(WR_YAML, 'w', encoding='utf-8').write(txt)
        except OSError:
            pass


def wr_limits_desired(host=None):
    with LOCK:
        sites = ((STATE.get('waiting') or {}).get('sites') or {})
        if host is not None:
            return dict((sites.get(host) or {}).get('limits') or {})
        return {h: dict((c or {}).get('limits') or {})
                for h, c in sites.items() if (c or {}).get('limits')}


def wr_limits_actual(site_id):
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT max_concurrent, max_waiting, session_timeout FROM mgt_waiting_room WHERE website_id=%s',
                      (int(site_id),))
            r = c.fetchone()
        if r:
            return {'max_concurrent': int(r[0] or 0), 'max_waiting': int(r[1] or 0),
                    'session_timeout': int(r[2] or 0)}
    except Exception:
        pass
    return {}


def wr_limits_enforce(host, site_id):
    """Если строка mgt сайта разошлась с нашими желаемыми лимитами — вернуть наши."""
    want = wr_limits_desired(host)
    if not want or not site_id:
        return
    have = wr_limits_actual(site_id)
    diff = {k: v for k, v in want.items() if int(have.get(k) or 0) != int(v)}
    if diff:
        wr_limits_sql(site_id, diff)


def wr_apply(host, site_id, desired, source, token=None, notify_change=True):
    """Единая точка переключения зала: mgt + состояние + фоновое восстановление патчей."""
    desired = bool(desired)
    if not WR_OP_LOCK.acquire(timeout=20):
        return {'ok': False, 'error': 'переключение уже выполняется, повторите через пару секунд'}
    try:
        if desired:
            # перед включением возвращаем наши лимиты: mgt на переключении
            # синхронизирует модуль именно со строкой mgt_waiting_room
            wr_limits_enforce(host, site_id)
        cfg = _wr_cfg(host)
        notify_on = bool((cfg.get('notify') or {}).get('enabled', True))
        mgt_conf_forget(site_id)
        okr, actual, conf0 = wr_read_actual(site_id, token=token)
        if not okr:
            return {'ok': False, 'error': 'SafeLine недоступен: не удалось прочитать состояние зала'}
        if actual == desired:
            _wr_state_patch(host, {'enabled': actual, 'source': source,
                                   'pending': None, 'error': '', 'error_at': 0})
            return {'ok': True, 'actual': actual, 'changed': False, 'mgt': conf0}
        ok, conf, err = waiting_set_enabled(site_id, desired, token=token)
        if not ok:
            _wr_state_patch(host, {'pending': desired, 'pending_source': source,
                                   'error': err, 'error_at': int(time.time())})
            return {'ok': False, 'error': err,
                    'actual': (bool(conf.get('is_enabled')) if conf else None)}
        ts = int(time.time())
        patch = {'enabled': desired, 'source': source, 'changed_at': ts,
                 'pending': None, 'pending_source': '', 'pending_tries': 0,
                 'error': '', 'error_at': 0}
        if source in ('manual', 'manual-retry'):
            patch['manual_at'] = ts
        _wr_state_patch(host, patch)
        site_patch_ensure(delay=0.8)
        if notify_change and notify_on:
            notify_send('SLExt: зал ожидания на %s %s (источник: %s)' %
                        (host, 'включён' if desired else 'выключен', source))
        return {'ok': True, 'actual': desired, 'changed': True, 'mgt': conf}
    finally:
        WR_OP_LOCK.release()


def waiting_stats(site_id, days=30):
    out = {'history': [], 'agg': {}, 'timeline': []}
    sc = ts_scale()
    since = int(time.time() * sc) - days * 86400 * sc
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT id, max_concurrent, session_timeout, total_waiting, top_waiting, cur_waiting, '
                      'total_waiting_time, total_serving, avg_wait_sec, bounce_rate, dur_sec, started_at, ended_at '
                      'FROM mgt_wr_stat_log WHERE site_id=%s ORDER BY id DESC LIMIT 30', (site_id,))
            for r in c.fetchall():
                out['history'].append({
                    'id': r[0], 'max_concurrent': r[1], 'session_timeout': r[2], 'total_waiting': r[3],
                    'top_waiting': r[4], 'cur_waiting': r[5], 'total_waiting_time': r[6], 'total_serving': r[7],
                    'avg_wait_sec': r[8], 'bounce_rate': float(r[9] or 0), 'dur_sec': r[10],
                    'started_at': r[11], 'ended_at': r[12]})
            c.execute('SELECT COUNT(*), COALESCE(SUM(total_waiting),0), COALESCE(MAX(top_waiting),0), '
                      'COALESCE(SUM(total_serving),0), COALESCE(SUM(total_waiting_time),0), '
                      'COALESCE(SUM(bounce_rate * total_waiting),0) '
                      'FROM mgt_wr_stat_log WHERE site_id=%s AND started_at >= %s',
                      (site_id, since))
            a = c.fetchone()
            entered = int(a[1] or 0)
            served = int(a[3] or 0)
            out['agg'] = {'sessions': a[0], 'entered': entered, 'total_queued': entered,
                          'peak': int(a[2] or 0), 'served': served,
                          'avg_wait_sec': int(round((a[4] or 0) / served)) if served else 0,
                          'bounce_rate': (float(a[5] or 0) / entered) if entered else 0.0}
            c.execute("SELECT to_char(to_timestamp(started_at), 'YYYY-MM-DD') AS d, COUNT(*), "
                      'COALESCE(SUM(total_waiting),0) FROM mgt_wr_stat_log WHERE site_id=%s AND started_at >= %s '
                      'GROUP BY d ORDER BY d', (site_id, since))
            out['timeline'] = [{'date': r[0], 'sessions': r[1], 'queued': int(r[2] or 0)} for r in c.fetchall()]
    except Exception as e:
        out['error'] = str(e)[:200]
    return out


WAITING_TEMPLATE = Template('''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>$title</title>
<!-- slext-waiting-page -->
<style>
:root{--primary-color:$accent;--light-primary-color:#9AC3E3;--font-color:#FFFFFF;--light-font-color:#B3D1E9;--success-color:#00B87C;--warning-color:#FF6666;--warning-font-color:#FFFFFF;--warning-light-font-color:#FFD1D1}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background-color:var(--primary-color);font-family:PingFang SC,Helvetica Neue,Helvetica,Arial,sans-serif}
#slg-bg{background-color:var(--primary-color);position:fixed;inset:0;z-index:100}
#slg-box{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:90%;max-width:40rem;text-align:center;z-index:300}
#sl-dots{position:relative;width:64px;height:64px;margin:0 auto 18px}
#sl-dots i{position:absolute;top:50%;left:50%;width:12px;height:12px;margin:-6px 0 0 -6px;border-radius:50%;background:var(--font-color);opacity:.15;animation:sl-pulse 1.5s linear infinite}
#sl-dots i:nth-child(1){transform:rotate(0deg) translateY(-26px)}
#sl-dots i:nth-child(2){transform:rotate(72deg) translateY(-26px);animation-delay:.15s}
#sl-dots i:nth-child(3){transform:rotate(144deg) translateY(-26px);animation-delay:.3s}
#sl-dots i:nth-child(4){transform:rotate(216deg) translateY(-26px);animation-delay:.45s}
#sl-dots i:nth-child(5){transform:rotate(288deg) translateY(-26px);animation-delay:.6s}
@keyframes sl-pulse{0%,100%{opacity:.12}50%{opacity:1}}
#slg-text{font-size:1.5rem;line-height:2.2rem;color:var(--font-color)}
#sl-msg{margin:6px 0 0;color:var(--light-font-color);font-size:.8rem;line-height:2rem}
#sl-queue{margin-top:10px;color:var(--light-font-color);font-size:1rem;line-height:2rem}
#sl-pos,#sl-total{font-size:2.2rem;font-weight:700;color:var(--font-color)}
#sl-note{margin-top:8px;color:var(--light-font-color);font-size:.8rem;line-height:2rem}
#sl-stats{display:none;grid-auto-flow:column;justify-content:center;gap:16px;margin-top:10px;color:var(--light-font-color);font-size:.75rem;line-height:1.8}
#sl-stats b{color:var(--font-color);font-weight:700}
#slg-copyright{position:fixed;left:0;right:0;bottom:0;padding:0 0 1.5rem;text-align:center;color:var(--light-font-color);font-size:.8rem;line-height:2rem;z-index:300}
#slg-logo svg{display:block;margin:0 auto}
#slg-name{color:var(--font-color)}
</style>
</head>
<body>
<div id="slg-bg"></div>
<div id="slg-box">
  <div id="sl-dots"><i></i><i></i><i></i><i></i><i></i></div>
  <div id="slg-text">$title</div>
  <div id="sl-msg">$message</div>
  <div id="sl-queue">You Are <b id="sl-pos">$firstpos</b> th / <b id="sl-total">—</b> $posttext</div>
  <div id="sl-note">$note</div>
  <div id="sl-stats">
    <span><b id="sl-st-peak">—</b> пик</span>
    <span><b id="sl-st-queued">—</b> прошло</span>
    <span><b id="sl-st-avg">—</b> среднее ожидание</span>
  </div>
</div>
<div id="slg-copyright">
  <div id="slg-logo"><svg width="32" height="35"><g fill="var(--font-color)"><path d="M15.006.33c.602-.44 1.4-.44 2.002 0 1.985 1.444 6.911 4.473 12.901 4.631.78.035 1.418.599 1.577 1.356.922 4.754 2.605 20.848-15.452 28.35C-2.077 27.183-.43 11.07.528 6.317c.142-.757.815-1.32 1.577-1.356 5.99-.158 10.863-3.187 12.9-4.63m1.037 4.54c-.28 1.647-2.15 1.938-2.15 1.938-1.9.309-2.819-1.12-2.819-1.12.82 2.255 2.198 2.391 2.446 2.397h2.423c-.7 1.802-3.48 2.133-3.48 2.133-3.159.39-4.689-1.423-4.689-1.423q.17.357.358.66l-.008-.005a11 11 0 0 0-3.106 7.671c0 6.09 4.937 11.026 11.026 11.026 6.09 0 11.027-4.936 11.027-11.026a11 11 0 0 0-3.11-7.674q.185-.3.353-.652s-1.53 1.816-4.69 1.423c0 0-2.776-.33-3.478-2.132h2.42c.245-.006 1.627-.14 2.448-2.397 0 0-.92 1.428-2.82 1.12-.142-.025-1.882-.356-2.15-1.94"/><polygon points="15.98353 17.9879553 9.8818726 21.4510476 15.3313444 24.6578974 17.2903808 23.6211992 13.5799337 21.4510476 15.98353 20.0985396 20.3159976 22.5564681 20.3159976 23.3648458 22.2042418 24.5010295 22.2042418 21.4510476" transform="rotate(-180 16.043 21.323)"/><polygon points="15.9835296 10.9942305 9.8818722 14.4573228 15.331344 17.6641726 17.2903804 16.6274743 13.5799333 14.4573228 15.9835296 13.1048148 20.3159972 15.5627433 20.3159972 16.371121 22.2042414 17.5073047 22.2042414 14.4573228"/></g></svg></div>
  <div id="slg-copyright-text"><span id="slg-prefix">Security Detection Powered By</span> <span id="slg-name">$brand</span></div>
</div>
<script>
(function(){
  var T={ready:'Готово — входим на сайт',pending:'Вы в очереди',full:'Очередь переполнена, попробуйте позже',
    conn:'Связь потеряна, восстанавливаем соединение'};
  var PREVIEW=!location.hostname||location.protocol==='about:';
  var elPos=document.getElementById('sl-pos'),elTotal=document.getElementById('sl-total');
  var elMsg=document.getElementById('sl-msg'),elDots=document.getElementById('sl-dots');
  var done=false;
  function ready(){if(done)return;done=true;elMsg.textContent=T.ready;elPos.textContent='\\u2713';elDots.style.display='none';setTimeout(function(){location.reload();},2500);}
  function render(d){if(!d||typeof d.pos!=='number'||typeof d.total!=='number')return;elPos.textContent=d.pos;elTotal.textContent=d.total;if(d.pos===0)ready();}
  function conn(){elMsg.textContent=T.conn;}
  var delay=2500, fails=0, wsOpen=false;
  function schedule(ms){setTimeout(poll,ms);}
  function poll(){
    if(done||wsOpen)return;
    if(document.hidden){schedule(10000);return;}
    fetch('/.safeline/api/waiting/query',{cache:'no-store'}).then(function(r){if(r.status!==200)throw 0;return r.json();})
      .then(function(j){fails=0;if(j&&j.data){render(j.data);if(!done)schedule(2500);}else{conn();schedule(5000);}})
      .catch(function(){fails++;conn();schedule(Math.min(15000,3000+fails*2000));});
  }
  function fullPage(){elMsg.textContent=T.full;elPos.textContent='\\u2014';elDots.style.display='none';
    setTimeout(function(){location.reload();},30000);}
  if(PREVIEW){
    /* preview mode: no live queue */
  }else if(/(?:^|;\\s*)sl-waiting-state=full/.test(document.cookie)){
    fullPage();
  }else{
    try{
      var w=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/.safeline/api/waiting/ws');
      var opened=false;
      w.addEventListener('open',function(){opened=true;wsOpen=true;});
      w.addEventListener('message',function(e){try{var d=JSON.parse(e.data);if(d&&typeof d.pos==='number'&&typeof d.total==='number'){render(d);}}catch(_){}});
      w.addEventListener('error',function(){wsOpen=false;if(!opened)poll();});
      w.addEventListener('close',function(){wsOpen=false;if(!done)poll();});
    }catch(e){poll();}
    document.addEventListener('visibilitychange',function(){if(!document.hidden&&!done&&!wsOpen)schedule(800);});
  }
  $stats
})();
</script>
</body>
</html>
''')


def waiting_defaults(host):
    return {
        'page': {'enabled': True, 'title': 'You Are Now In Line',
                 'message': 'Please wait — the page will refresh automatically.',
                 'firstpos': '…', 'posttext': 'People Totally',
                 'note': 'Do not close this page.',
                 'brand': 'SafeLine WAF', 'color': '#0067B8', 'show_stats': True},
        'schedule': {'enabled': False, 'days': [1, 2, 3, 4, 5, 6, 7], 'from': '18:00', 'to': '23:00'},
        'auto': {'enabled': False, 'threshold': 60, 'off_threshold': 20, 'window': 60,
                 'hold': 3, 'hold_off': 4, 'cooldown': 600, 'min_off': 600},
        'notify': {'enabled': True},
        'state': {'enabled': False, 'source': 'manual', 'changed_at': 0},
    }


def waiting_cfg(host):
    with LOCK:
        wt = json.loads(json.dumps(STATE.get('waiting') or {}))
    base = waiting_defaults(host)
    cfg = (wt.get('sites') or {}).get(host) or {}
    merged = {
        'page': {**base['page'], **(cfg.get('page') or {})},
        'schedule': {**base['schedule'], **(cfg.get('schedule') or {})},
        'auto': {**base['auto'], **(cfg.get('auto') or {})},
        'notify': {**base['notify'], **(cfg.get('notify') or {})},
        'state': {**base['state'], **(cfg.get('state') or {})},
        'auto_run': dict(cfg.get('auto_run') or {}),
        'auto_log': list(cfg.get('auto_log') or []),
    }
    return merged


def waiting_page_html(host, cfg, panel_base=''):
    import html as _html
    p = cfg.get('page') or {}
    title = _html.escape(str(p.get('title') or 'You Are Now In Line')[:120])
    message = _html.escape(str(p.get('message') or 'Please wait — the page will refresh automatically.')[:600])
    note = _html.escape(str(p.get('note') or '')[:300])
    firstpos = _html.escape(str(p.get('firstpos') or '—')[:8])
    posttext = _html.escape(str(p.get('posttext') or 'People Totally')[:80])
    brand = _html.escape(str(p.get('brand') or 'SafeLine WAF')[:60])
    color = str(p.get('color') or '')
    if not color or color == '#0fc6c2':
        color = '#0067B8'
    if not re.match(r'^#[0-9a-fA-F]{3,8}$', color):
        color = '#0067B8'
    stats = ''
    if p.get('show_stats', True) and panel_base:
        safe_base = re.sub(r'[^A-Za-z0-9_:/.\-]', '', str(panel_base))[:200].rstrip('/')
        if safe_base:
            stats = ("fetch('%s/api/waiting/status?site='+encodeURIComponent(location.hostname),{cache:'no-store'}).then(function(r){return r.json();})"
                     ".then(function(j){if(j&&j.ok&&j.last){var st=document.getElementById('sl-stats');"
                     "st.style.display='grid';document.getElementById('sl-st-peak').textContent=j.last.top_waiting||0;"
                     "document.getElementById('sl-st-queued').textContent=j.last.total_waiting||0;"
                     "document.getElementById('sl-st-avg').textContent=(j.last.avg_wait_sec||0)+' с';}})"
                     ".catch(function(){});" % safe_base)
    return WAITING_TEMPLATE.safe_substitute(
        title=title, message=message, note=note, firstpos=firstpos, posttext=posttext,
        brand=brand, accent=color, stats=stats)


STATIC_RX = re.compile(r'\.(js|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|map|json|txt|xml|mp4|webm)(\?|$)', re.I)

# ------------------------- собственный зал ожидания -------------------------
# Нативный зал SafeLine CE не даёт менять лимиты (mgt жёстко навязывает 5/0/3)
# и считает запросы, а не посетителей. Поэтому очередь ведём сами:
#   * cookie slext_q с токеном; пока токен не допущен — nginx показывает нашу
#     страницу очереди (гейт в конфиге сайта, включается map-файлом);
#   * страница опрашивает /.safeline/slext/status (проксируется в наш API);
#   * API считает активных (допущенные за TTL) и выдаёт место в очереди.

QUEUE_MAP_FILE = '/data/safeline/resources/nginx/conf.d/zz_slext_queue.conf'
QUEUE_COOKIE = 'slext_q'
QUEUE_ADMITTED_TTL = 600
QUEUE_WAIT_TTL = 900
QUEUE_STATE = {}


def queue_state(host):
    return QUEUE_STATE.setdefault(host, {'admitted': {}, 'waiting': [], 'started': 0,
                                  'served': 0, 'peak_waiting': 0})


QUEUE_TEMPLATE = Template('''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Очередь</title>
<!-- slext-queue-page -->
<style>
:root{--accent:#0067B8}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px;
 background:radial-gradient(1200px 620px at 12% -12%, color-mix(in srgb, var(--accent) 20%, transparent), transparent 62%),
 radial-gradient(900px 520px at 112% 112%, color-mix(in srgb, var(--accent) 13%, transparent), transparent 58%),
 linear-gradient(160deg,#070b12,#0d1420);color:#e8eef7;
 font-family:Inter,ui-sans-serif,system-ui,"Segoe UI",Roboto,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{width:100%;max-width:600px}
.card{position:relative;overflow:hidden;background:rgba(22,30,44,.78);border:1px solid rgba(255,255,255,.09);
 border-radius:24px;padding:40px 36px 26px;box-shadow:0 34px 90px -34px rgba(0,0,0,.6);
 backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}
.glow{position:absolute;top:-42%;right:-18%;width:360px;height:360px;pointer-events:none;
 background:radial-gradient(closest-side, color-mix(in srgb, var(--accent) 42%, transparent), transparent);filter:blur(26px);opacity:.55}
.badge{display:inline-flex;align-items:center;gap:10px;padding:7px 13px;border:1px solid rgba(255,255,255,.09);
 border-radius:999px;color:#93a4bd;font-size:11.5px;letter-spacing:.14em;text-transform:uppercase}
.ic{width:40px;height:40px;border-radius:13px;display:inline-flex;align-items:center;justify-content:center;
 background:color-mix(in srgb, var(--accent) 17%, transparent);border:1px solid color-mix(in srgb, var(--accent) 36%, transparent);color:var(--accent)}
.ic svg{width:22px;height:22px}
h1{font-size:24px;margin:18px 0 8px;letter-spacing:-.01em;font-weight:700}
p{color:#93a4bd;line-height:1.65;margin:0 0 16px;font-size:15px}
.queue{display:flex;align-items:baseline;gap:10px;margin:6px 0 2px;flex-wrap:wrap}
.pos{font-size:clamp(46px,11vw,74px);font-weight:800;letter-spacing:-.04em;line-height:1;
 background:linear-gradient(118deg,var(--accent), color-mix(in srgb, var(--accent) 35%, #fff));
 -webkit-background-clip:text;background-clip:text;color:transparent}
.oflabel{color:#93a4bd;font-size:14px}
.dots{display:inline-flex;gap:6px;margin-left:6px}
.dots i{width:8px;height:8px;border-radius:50%;background:var(--accent);opacity:.35;animation:bl 1.2s infinite}
.dots i:nth-child(2){animation-delay:.15s}.dots i:nth-child(3){animation-delay:.3s}.dots i:nth-child(4){animation-delay:.45s}
@keyframes bl{0%,80%,100%{opacity:.25;transform:translateY(0)}40%{opacity:1;transform:translateY(-3px)}}
.hint{margin-top:10px;font-size:12.5px;color:#93a4bd}
.foot{margin-top:24px;padding-top:15px;border-top:1px solid rgba(255,255,255,.09);display:flex;justify-content:space-between;
 align-items:center;color:#93a4bd;font-size:11.5px;letter-spacing:.1em;text-transform:uppercase}
.dot{width:8px;height:8px;border-radius:50%;background:var(--accent);display:inline-block;margin-right:8px;
 box-shadow:0 0 12px var(--accent);vertical-align:1px}
@media (max-width:480px){.card{padding:28px 22px 20px;border-radius:20px}}
</style>
</head>
<body>
<div class="wrap"><div class="card"><span class="glow"></span>
  <span class="badge"><span class="ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
   stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span> Зал ожидания</span>
  <h1 id="sl-title">Секунду, вы в очереди</h1>
  <p id="sl-msg">Сейчас очень много посетителей. Мы держим вас в очереди, чтобы сайт работал быстро.</p>
  <div class="queue"><span class="pos" id="sl-pos">…</span>
    <span class="oflabel">Ваше место в очереди из <b id="sl-total">—</b></span>
    <span class="dots" id="sl-dots"><i></i><i></i><i></i><i></i></span></div>
  <div class="hint" id="sl-note">Страница обновится автоматически, когда подойдёт ваша очередь.</div>
  <div class="foot"><span><i class="dot"></i><span id="sl-brand">NRG / INDEX</span></span><span>ЗАЩИЩЕНО NRG / INDEX</span></div>
</div></div>
<script>
(function(){
  var T={pass:'Готово — входим на сайт',wait:'Вы в очереди',full:'Очередь переполнена, попробуйте позже',
    conn:'Связь потеряна, восстанавливаем соединение'};
  var elPos=document.getElementById('sl-pos'),elTotal=document.getElementById('sl-total');
  var elMsg=document.getElementById('sl-msg'),elDots=document.getElementById('sl-dots');
  var elTitle=document.getElementById('sl-title'),elNote=document.getElementById('sl-note'),elBrand=document.getElementById('sl-brand');
  var done=false,delay=1500,fails=0;
  function ready(){if(done)return;done=true;elMsg.textContent=T.pass;elPos.textContent='\\u2713';elDots.style.display='none';
    try{document.cookie='nrgpass=1; Path=/; Max-Age=604800; SameSite=Lax';}catch(e){}
    setTimeout(function(){location.reload();},1200);}
  function render(j){
    if(!j)return;
    var p=j.page||{};
    if(p.title){elTitle.textContent=p.title;document.title=p.title;}
    if(p.message)elMsg.textContent=p.message;
    if(p.note)elNote.textContent=p.note;
    if(p.brand)elBrand.textContent=p.brand;
    if(p.color){document.documentElement.style.setProperty('--accent',p.color);}
    if(j.state==='pass'){ready();return;}
    if(j.state==='full'){elMsg.textContent=T.full;elPos.textContent='\\u2014';elDots.style.display='none';
      setTimeout(poll,30000);return;}
    elMsg.textContent=T.wait;
    elPos.textContent=(typeof j.pos==='number'&&j.pos>0)?j.pos:'…';
    elTotal.textContent=(typeof j.total==='number'&&j.total>0)?j.total:'—';
  }
  function schedule(ms){setTimeout(poll,ms);}
  function poll(){
    if(done)return;
    if(document.hidden){schedule(8000);return;}
    fetch('/.safeline/slext/status',{cache:'no-store'}).then(function(r){if(r.status!==200)throw 0;return r.json();})
      .then(function(j){fails=0;render(j);if(!done)schedule(delay);})
      .catch(function(){fails++;elMsg.textContent=T.conn;schedule(Math.min(15000,2000+fails*2000));});
  }
  poll();
  document.addEventListener('visibilitychange',function(){if(!document.hidden&&!done)schedule(400);});
})();
</script>
</body>
</html>
''')


def queue_page_html():
    return QUEUE_TEMPLATE.safe_substitute()


def queue_write_page():
    os.makedirs(PAGES_DIR, exist_ok=True)
    target = os.path.join(PAGES_DIR, 'queue.html')
    try:
        with open(target, 'w', encoding='utf-8') as f:
            f.write(queue_page_html())
        return True
    except OSError:
        return False


def queue_stats(host):
    now = time.time()
    st = queue_state(host)
    active = len([1 for ts in st['admitted'].values() if now - ts <= QUEUE_ADMITTED_TTL])
    return {'active': active, 'waiting': len(st['waiting']), 'served': st.get('served', 0),
            'peak_waiting': st.get('peak_waiting', 0), 'started_at': st.get('started', 0)}


def queue_reset_state(host):
    queue_state(host).update({'admitted': {}, 'waiting': [], 'served': 0, 'peak_waiting': 0,
                              'started': int(time.time())})


def handle_queue_status(self):
    """GET /api/queue/status — со страницы очереди через прокси сайта."""
    host = ''
    try:
        host = str(self.headers.get('X-Slext-Host') or '').strip()[:200]
        if not host:
            host = str(self.headers.get('Host') or '').split(':')[0].strip()[:200]
    except Exception:
        host = ''
    if not site_by_host(host):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        host = (qs.get('site') or [''])[0][:200].split(':')[0]
    site = site_by_host(host) if host else None
    if not site:
        return self._json(200, {'ok': False, 'error': 'site not found'})
    cfg = queue_cfg(host)
    token = ''
    try:
        for part in (self.headers.get('Cookie') or '').split(';'):
            part = part.strip()
            if part.startswith(QUEUE_COOKIE + '='):
                token = part.split('=', 1)[1][:64]
    except Exception:
        token = ''
    if not token:
        token = secrets.token_hex(16)
    new_token, state, pos, total = queue_status(host, token)
    page_cfg = waiting_cfg(host)['page'] or {}
    data = {'ok': True, 'state': state, 'pos': pos, 'total': total,
            'enabled': bool(cfg.get('enabled')),
            'page': {k: page_cfg.get(k) for k in ('title', 'message', 'note', 'posttext', 'brand', 'color')}}
    extra = []
    if not token and new_token:
        extra.append(('Set-Cookie',
                      '%s=%s; Path=/; Max-Age=%d; SameSite=Lax' % (QUEUE_COOKIE, new_token, 86400)))
    return self._json(200, data, extra=extra)


def queue_defaults():
    return {'enabled': False, 'max_concurrent': 100, 'ttl': 600, 'max_waiting': 200}


def queue_cfg(host):
    with LOCK:
        cfg = ((STATE.get('waiting') or {}).get('sites') or {}).get(host) or {}
        q = dict(queue_defaults())
        q.update(cfg.get('queue') or {})
        return q


def queue_sync_map():
    """Пересобрать map-файл гейта по всем сайтам из state."""
    with LOCK:
        sites = ((STATE.get('waiting') or {}).get('sites') or {})
        on = [h for h, c in sites.items() if (c or {}).get('queue', {}).get('enabled')]
    lines = ['# slext-queue map (managed by SLExt API)',
             'map $host $slext_queue_on {',
             '    default 0;']
    for h in sorted(on):
        if re.match(r'^[A-Za-z0-9_.\-]{3,120}$', h):
            lines.append('    %s 1;' % h)
    lines += ['}',
              'map $cookie_%s $slext_queue_np {' % QUEUE_COOKIE,
              '    default 1;',
              '    "~." 0;',
              '}',
              'map "$slext_queue_on$slext_queue_np" $slext_queue_on0 {',
              '    "11" 1;',
              '    default 0;',
              '}',
              'map "$slext_queue_on0$request_uri" $slext_queue_gate {',
              '    "~^1/(@slext-queue|\\.safeline/)" 0;',
              '    "~^1" 1;',
              '    default 0;',
              '}']
    txt = '\n'.join(lines) + '\n'
    try:
        cur = ''
        if os.path.exists(QUEUE_MAP_FILE):
            cur = open(QUEUE_MAP_FILE, encoding='utf-8', errors='replace').read()
        if cur != txt:
            open(QUEUE_MAP_FILE, 'w', encoding='utf-8').write(txt)
            run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reload'], timeout=30)
            return True
    except OSError:
        pass
    return False


def queue_status(host, token):
    """Статус посетителя: pass / wait / full. Токен регистрируется при отсутствии."""
    now = time.time()
    cfg = queue_cfg(host)
    st = queue_state(host)
    # чистим старых
    for t in [t for t, ts in st['admitted'].items() if now - ts > max(60, int(cfg['ttl']))]:
        st['admitted'].pop(t, None)
    st['waiting'] = [(t, ts) for t, ts in st['waiting'] if now - ts < QUEUE_WAIT_TTL]
    if not token:
        return None, 'wait', 0, 0
    admitted = token in st['admitted']
    if admitted:
        st['admitted'][token] = now
        return token, 'pass', 0, 0
    waiting = [t for t, _ in st['waiting']]
    if token not in waiting:
        st['waiting'].append((token, now))
        st['peak_waiting'] = max(st['peak_waiting'], len(st['waiting']))
        waiting = [t for t, _ in st['waiting']]
        if len(waiting) > max(1, int(cfg['max_waiting'])):
            st['waiting'] = [(t, ts) for t, ts in st['waiting'] if t != token]
            return token, 'full', 0, 0
    active = len(st['admitted'])
    if active < max(1, int(cfg['max_concurrent'])):
        st['waiting'] = [(t, ts) for t, ts in st['waiting'] if t != token]
        st['admitted'][token] = now
        st['served'] += 1
        return token, 'pass', 0, 0
    pos = waiting.index(token) + 1 if token in waiting else len(waiting) + 1
    return token, 'wait', pos, len(st['waiting'])


def queue_apply(host, enabled=None, max_concurrent=None, ttl=None, max_waiting=None):
    """Настройки нашего зала сайта + синхронизация nginx-гейта."""
    with LOCK:
        sites = STATE.setdefault('waiting', {}).setdefault('sites', {})
        cfg = sites.setdefault(host, {})
        q = cfg.setdefault('queue', {})
        if enabled is not None:
            was = bool(q.get('enabled'))
            q['enabled'] = bool(enabled)
            qst = queue_state(host)
            if enabled and not was:
                qst.update({'admitted': {}, 'waiting': [], 'served': 0, 'peak_waiting': 0,
                            'started': int(time.time())})
        if max_concurrent is not None:
            q['max_concurrent'] = clamp_int(max_concurrent, 1, 5000, 100)
        if ttl is not None:
            q['ttl'] = clamp_int(ttl, 30, 86400, 600)
        if max_waiting is not None:
            q['max_waiting'] = clamp_int(max_waiting, 1, 100000, 200)
        save_state(STATE)
    queue_sync_map()
    return queue_cfg(host)


def site_patch_queue_line():
    return 'if ($slext_queue_gate) { rewrite ^ /@slext-queue last; } # slext-queue-if'
RATE_CACHE = {'at': 0, 'window': 0, 'value': 0}


def _rate_count_line(line, since):
    """(в окне?, подходит?) для строки лога."""
    m = PIPE_RE.match(line) or MAIN_RE.match(line)
    if not m:
        return False, False
    ts = parse_ts(m.group('ts'))
    if not ts:
        return False, False
    if ts < since:
        return True, False
    try:
        ua = m.group('ua') or ''
        req = m.group('req') or ''
    except (IndexError, ValueError):
        return False, False
    if BOT_RX.search(ua):
        return False, False
    parts = req.split(' ')
    if len(parts) < 2 or parts[0] != 'GET':
        return False, False
    path = parts[1]
    if path.startswith('/.safeline/') or STATIC_RX.search(path):
        return False, False
    return False, True


def _rate_scan_file(path, since):
    """Скан хвоста лога: (число запросов, покрыто ли окно целиком)."""
    count = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0, False
    chunk = 2 * 1024 * 1024
    pos = size
    total_read = 0
    while pos > 0 and total_read <= 32 * 1024 * 1024:
        start = max(0, pos - chunk)
        try:
            with open(path, 'rb') as f:
                f.seek(start)
                data = f.read(pos - start)
        except OSError:
            return count, False
        total_read += pos - start
        text = data.decode('utf-8', 'replace')
        lines = text.split('\n')
        if start > 0 and lines:
            lines = lines[1:]
        for line in reversed(lines):
            old, hit = _rate_count_line(line, since)
            if old:
                return count, True
            if hit:
                count += 1
        pos = start
    return count, False


def real_rate_pm(window):
    now = time.time()
    if RATE_CACHE['window'] == window and now - RATE_CACHE['at'] < 60:
        return RATE_CACHE['value']
    since = int(now - window)
    files = sorted(glob.glob(os.path.join(SITE_LOG_DIR, 'accesslog_*')))
    files += sorted(glob.glob(os.path.join(LOG_DIR, 'access.log*')))
    count = 0
    for path in reversed(files):
        if path.endswith('.gz'):
            try:
                with gzip.open(path, 'rt', errors='replace') as fh:
                    for line in fh:
                        old, hit = _rate_count_line(line, since)
                        if old:
                            break
                        if hit:
                            count += 1
            except OSError:
                continue
            break
        n, covered = _rate_scan_file(path, since)
        count += n
        if covered:
            break
    value = int(round(count * 60.0 / max(1, window)))
    RATE_CACHE.update({'at': now, 'window': window, 'value': value})
    return value


def _wr_log_event(host, action, reason, rate):
    with LOCK:
        c2 = STATE.setdefault('waiting', {}).setdefault('sites', {}).setdefault(host, {})
        log = c2.setdefault('auto_log', [])
        log.insert(0, {'ts': int(time.time()), 'rate': rate, 'action': action, 'reason': reason})
        del log[20:]


def _wr_sync_sessions(site, host, notify_on):
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT COALESCE(MAX(id), 0) FROM mgt_wr_stat_log WHERE site_id=%s', (site['id'],))
            maxid = c.fetchone()[0]
            if maxid > int(WR_SESSIONS.get(host, maxid)):
                c.execute('SELECT id, total_waiting, top_waiting, total_serving, avg_wait_sec, '
                          'bounce_rate, dur_sec FROM mgt_wr_stat_log WHERE site_id=%s AND id > %s '
                          'ORDER BY id ASC LIMIT 5', (site['id'], int(WR_SESSIONS.get(host, maxid))))
                for r in c.fetchall():
                    if notify_on:
                        notify_send('SLExt: зал ожидания %s — сессия завершена\n'
                                    'В очереди: %s, пик: %s, обслужено: %s\nСреднее ожидание: %s с, '
                                    'отказы: %s%%, длительность: %s с' %
                                    (host, r[1], r[2], r[3], r[4], round(float(r[5] or 0) * 100, 1), r[6]))
            WR_SESSIONS[host] = maxid
    except Exception:
        pass


def _wr_tick(first=False):
    with LOCK:
        hosts = list(((STATE.get('waiting') or {}).get('sites') or {}).keys())
    if not hosts:
        return
    if not WR_PATCH.get('running') and not site_markers_ok():
        site_patch_ensure(delay=0.2)
    for host in hosts:
        site = site_by_host(host)
        if not site:
            continue
        try:
            wr_limits_enforce(host, site['id'])
        except Exception:
            pass
        cfg = waiting_cfg(host)
        st = cfg.get('state') or {}
        actual = bool((cfg.get('queue') or {}).get('enabled'))
        # подчищаем наследие нативного зала (pending/ошибки старых версий)
        if st.get('pending') is not None or st.get('error') or st.get('pending_tries'):
            _wr_state_patch(host, {'pending': None, 'pending_source': '', 'pending_tries': 0,
                                   'error': '', 'error_at': 0})
            st = dict(st)
            st['pending'] = None
            st['error'] = ''
        if bool(st.get('enabled')) != actual:
            _wr_state_patch(host, {'enabled': actual, 'error': '', 'error_at': 0})
            st = dict(st)
            st['enabled'] = actual
        desired, source = None, ''
        sch = cfg.get('schedule') or {}
        if sch.get('enabled'):
            try:
                hm = time.strftime('%H:%M')
                days = sch.get('days') or []
                dow = int(time.strftime('%u'))
                active = (dow in days) and (str(sch.get('from', '00:00')) <= hm <= str(sch.get('to', '23:59')))
                if bool(active) != actual:
                    desired, source = bool(active), 'schedule'
            except Exception:
                pass
        au = cfg.get('auto') or {}
        if desired is None and au.get('enabled') and not WR_OP_LOCK.locked():
            try:
                window = clamp_int(au.get('window'), 30, 3600, 60)
                rate = real_rate_pm(window)
                run = cfg.get('auto_run') or {}
                merged = {'above': run.get('above'), 'below': run.get('below'),
                          'manual_at': st.get('manual_at'), 'changed_at': st.get('changed_at'),
                          'source': st.get('source')}
                dec, action, reason, counters = wr_auto_decision(au, merged, actual, rate, time.time())
                with LOCK:
                    STATE.setdefault('waiting', {}).setdefault('sites', {}).setdefault(host, {})['auto_run'] = counters
                if action != 'wait':
                    _wr_log_event(host, action, reason, rate)
                if dec is not None:
                    desired, source = dec, 'auto'
            except Exception:
                pass
        if desired is not None and bool(desired) != actual:
            queue_apply(host, enabled=bool(desired))
            ts = int(time.time())
            patch = {'enabled': bool(desired), 'source': source, 'changed_at': ts}
            if source in ('manual', 'manual-retry'):
                patch['manual_at'] = ts
            _wr_state_patch(host, patch)
        _wr_sync_sessions(site, host, bool((cfg.get('notify') or {}).get('enabled', True)))
    with LOCK:
        save_state(STATE)


def wr_startup():
    try:
        page_apply()
    except Exception:
        pass
    try:
        _wr_tick(True)
    except Exception:
        pass


def waiting_worker():
    first = True
    while True:
        try:
            _wr_tick(first)
            first = False
        except Exception:
            pass
        time.sleep(20)


LT_JOBS = {}
LOADTEST_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
               '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 SLExt-LoadTest')


def lt_origin_target(host, path):
    up_host, up_port = '', 0
    try:
        txt = open('/data/safeline/resources/nginx/sites-enabled/IF_backend_1', errors='replace').read()
        m = re.search(r'upstream\s+backend_1\s*\{(.*?)\}', txt, re.S)
        if m:
            m2 = re.search(r'server\s+([A-Za-z0-9_.\-]+)(?::(\d+))?', m.group(1))
            if m2:
                up_host = m2.group(1)
                up_port = int(m2.group(2) or 443)
    except OSError:
        pass
    if not up_host:
        return 'http://127.0.0.1:8081' + path, {'Host': host}
    scheme = 'https' if up_port == 443 else 'http'
    return '%s://%s:%d%s' % (scheme, up_host, up_port, path), {'Host': host}


def lt_target(host, path, mode):
    path = '/' + str(path or '/').lstrip('/')
    if mode == 'origin':
        return lt_origin_target(host, path)
    return 'https://%s%s' % (host, path), {}


def lt_worker(url, headers, evt, out):
    import http.client as hc
    u = urllib.parse.urlparse(url)
    ssl_ctx = ssl._create_unverified_context() if u.scheme == 'https' else None
    path = (u.path or '/') + (('?' + u.query) if u.query else '')
    port = u.port or (443 if u.scheme == 'https' else 80)
    conn = None
    while not evt.is_set():
        t0 = time.time()
        status = 0
        err = ''
        try:
            if conn is None:
                if u.scheme == 'https':
                    conn = hc.HTTPSConnection(u.hostname, port, timeout=8, context=ssl_ctx)
                else:
                    conn = hc.HTTPConnection(u.hostname, port, timeout=8)
            conn.request('GET', path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            ln = resp.length
            if ln is not None and ln > 2097152:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
            else:
                resp.read()
        except Exception as e:
            err = str(e)[:80]
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            conn = None
        out.append((round((time.time() - t0) * 1000.0, 1), status, err))


def lt_stage_stats(results, seconds):
    durs = sorted(r[0] for r in results)
    n = len(durs)

    def pct(p):
        if not n:
            return 0
        i = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
        return durs[i]

    errs = sum(1 for r in results if r[2] or r[1] == 0 or r[1] >= 500)
    blocked = sum(1 for r in results if r[1] in (403, 429, 468, 444))
    return {'requests': n, 'rps': round(n / max(0.1, seconds), 1),
            'p50': pct(50), 'p95': pct(95), 'p99': pct(99),
            'err': errs, 'err_pct': round(errs * 100.0 / n, 2) if n else 0,
            'blocked': blocked}


def lt_run_stage(url, headers, conc, seconds, ev, hard_at):
    out = []
    stop = threading.Event()
    ths = []
    for _ in range(conc):
        th = threading.Thread(target=lt_worker, args=(url, headers, stop, out), daemon=True)
        th.start()
        ths.append(th)
    t_end = min(time.time() + seconds, hard_at)
    while time.time() < t_end and not ev.is_set():
        time.sleep(0.2)
    stop.set()
    for th in ths:
        th.join(timeout=3)
    return out


def lt_recommend(rep):
    base = rep.get('stable') or rep.get('peak') or {}
    rps = float(base.get('rps') or 0)
    conc = int(base.get('conc') or 0)
    thr = int(round(rps * 60 * 0.7 / 5.0) * 5) if rps else 0
    off = int(round(max(thr, 10) * 0.35 / 5.0) * 5)
    maxc = max(2, min(64, int(round(conc * 0.8)))) if conc else 4
    return {'max_concurrent': maxc, 'threshold': max(thr, 10), 'off_threshold': max(off, 5),
            'hold': 3, 'hold_off': 4, 'cooldown': 600, 'min_off': 600,
            'stable_rps': round(rps, 1), 'stable_p95': base.get('p95') or 0,
            'note': ('Зал включать при трафике ≥ %s зап/мин (70%% от устойчивых %s rps), '
                     'безопасный лимит одновременных посетителей — %s. После теста верните защиту.'
                     % (max(thr, 10), round(rps, 1), maxc))}


def lt_report_html(rep):
    import html as _h

    def e(x):
        return _h.escape(str(x if x is not None else ''))

    stages = rep.get('stages') or []
    rec = rep.get('recommend') or {}
    rows = []
    for s in stages:
        bad = (s.get('err_pct', 0) > 2 or s.get('p95', 0) > 1000 or s.get('blocked'))
        rows.append('<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' %
                    (' class="bad"' if bad else '', s.get('conc'), s.get('rps'), s.get('p50'),
                     s.get('p95'), s.get('p99'), s.get('err_pct'), s.get('blocked'),
                     s.get('requests'), s.get('dur')))
    n = max(1, len(stages) - 1)
    maxr = max([s.get('rps') or 0 for s in stages] + [1])
    pts, dots, labels = [], [], []
    for i, s in enumerate(stages):
        x = 50 + i * 640 / n
        y = 180 - (s.get('rps') or 0) / maxr * 140
        pts.append('%s,%s' % (round(x, 1), round(y, 1)))
        dots.append('<circle cx="%s" cy="%s" r="3.5" fill="#0fc6c2"/>' % (round(x, 1), round(y, 1)))
        labels.append('<text x="%s" y="196" font-size="11" fill="#888" text-anchor="middle">%s</text>' % (round(x, 1), s.get('conc')))
    chart = ('<svg viewBox="0 0 720 210" style="width:100%;max-width:760px">' +
             '<polyline fill="none" stroke="#0fc6c2" stroke-width="2.5" points="%s"/>' % ' '.join(pts) +
             ''.join(dots) + ''.join(labels) +
             '<text x="50" y="16" font-size="11" fill="#888">RPS (по стадиям, ось X — параллельные запросы)</text></svg>')
    mode = 'через WAF (боевой путь)' if rep.get('mode') != 'origin' else 'напрямую в бэкенд (защита не мешает)'
    table_rows = ''.join(rows) or '<tr><td colspan="9" style="color:#888">нет данных</td></tr>'
    notes = (rep.get('analysis') or {}).get('notes') or []
    notes_html = ''.join('<li>%s</li>' % e(x) for x in notes) or '<li>нет данных</li>'
    tot = rep.get('totals') or {}
    prot = rep.get('protection') or {}
    if prot.get('paused'):
        prot_html = ('защита автоматически приостановлена на время теста: правил SafeLine — %s, '
                     'CrowdSec-бансер — %s. После теста всё возвращено автоматически.'
                     % (e(prot.get('acl_rules')), 'остановлен' if prot.get('crowdsec_bouncer') else 'уже был выключен'))
    elif rep.get('mode') == 'origin':
        prot_html = 'тест шёл напрямую в бэкенд — защита не затрагивалась и не отключалась.'
    else:
        prot_html = 'тест шёл через WAF; отключение защиты подтверждено вручную перед запуском.'
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<title>SLExt: тест ёмкости ' + e(rep.get('host')) + '</title><style>'
            'body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#f7f8fa;color:#1a2233;margin:0;padding:28px}'
            '.card{max-width:940px;margin:0 auto 14px;background:#fff;border-radius:12px;padding:18px 20px;box-shadow:0 2px 10px rgba(16,36,70,.08)}'
            'h1{font-size:20px;margin:0 0 6px}h2{font-size:15px;margin:18px 0 8px;color:#54607a}'
            '.kpi{display:flex;gap:12px;flex-wrap:wrap}.k{padding:10px 14px;background:#f0fbfb;border-radius:10px;min-width:120px}'
            '.k b{font-size:20px;display:block}.k span{font-size:12px;color:#54607a}'
            'table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:6px 8px;border-bottom:1px solid #e8ebf0;text-align:left}'
            'tr.bad td{color:#c0392b}.note{background:#f0fbfb;border-left:4px solid #0fc6c2;padding:10px 12px;border-radius:8px;font-size:13px}'
            'ul{margin:6px 0 0 18px;padding:0;font-size:13px}li{margin:3px 0}'
            '.warn{background:#fff8e6;border-left:4px solid #f0b429;padding:10px 12px;border-radius:8px;font-size:13px;margin-top:10px}'
            '</style></head><body>'
            '<div class="card"><h1>Адаптивный тест ёмкости — ' + e(rep.get('host')) + e(rep.get('path')) + '</h1>'
            '<div style="color:#54607a;font-size:13px">Режим: ' + e(mode) + ' · Начало: ' +
            e(time.strftime('%d.%m.%Y %H:%M', time.localtime(rep.get('started_at') or 0))) +
            ' · Длительность: ' + e(rep.get('duration')) + ' с · Итог: ' + e(rep.get('verdict')) +
            '</div>' + e(rep.get('reason') or '') +
            '<div class="kpi" style="margin-top:10px">'
            '<div class="k"><b>' + e(tot.get('requests')) + '</b><span>всего запросов</span></div>'
            '<div class="k"><b>' + e(tot.get('errors')) + '</b><span>ошибок</span></div>'
            '<div class="k"><b>' + e(tot.get('blocked')) + '</b><span>блокировок защитой</span></div>'
            '<div class="k"><b>' + e(tot.get('stages')) + '</b><span>стадий</span></div></div></div>'
            '<div class="card"><h2>Анализ</h2><div class="note"><ul>' + notes_html + '</ul></div></div>'
            '<div class="card"><h2>Динамика</h2>' + chart +
            '<h2>Стадии</h2><table><tr><th>Параллельно</th><th>RPS</th><th>p50, мс</th><th>p95, мс</th><th>p99, мс</th><th>Ошибки, %</th><th>Блок</th><th>Запросов</th><th>Длит, с</th></tr>' +
            table_rows + '</table></div>'
            '<div class="card"><h2>Рекомендации для зала ожидания (' + e(rep.get('host')) + ')</h2>'
            '<div class="note">' + e(rec.get('note')) + '</div>'
            '<div class="kpi" style="margin-top:10px">'
            '<div class="k"><b>' + e(rec.get('max_concurrent')) + '</b><span>Active Users Allowed (max_concurrent)</span></div>'
            '<div class="k"><b>' + e(rec.get('threshold')) + '</b><span>порог вкл, зап/мин</span></div>'
            '<div class="k"><b>' + e(rec.get('off_threshold')) + '</b><span>порог выкл, зап/мин</span></div>'
            '<div class="k"><b>' + e(rec.get('cooldown')) + ' с</b><span>пауза до авто-выкл</span></div></div>'
            '<div class="warn">Защита: ' + prot_html + '</div>'
            '</div></body></html>')


def lt_analyze(stages, stable, peak, p95_ms, err_pct, reason):
    out = {'scaling': [], 'notes': [], 'degradation': None}
    prev = None
    for s in stages:
        if prev is not None and prev.get('rps'):
            out['scaling'].append({'from_conc': prev.get('conc'), 'to_conc': s.get('conc'),
                                   'rps_gain_pct': round((s.get('rps', 0) - prev['rps']) * 100.0 / prev['rps'], 1)})
        bad = (s.get('err_pct', 0) > err_pct) or (s.get('p95', 0) > p95_ms) or (s.get('blocked') or 0) > 3
        if bad and out['degradation'] is None:
            out['degradation'] = {'conc': s.get('conc'), 'p95': s.get('p95'),
                                  'err_pct': s.get('err_pct'), 'blocked': s.get('blocked')}
        prev = s
    base = stable or peak or {}
    if base:
        out['notes'].append('Устойчивая пропускная способность ~%s зап/с при %s параллельных (p95 %s мс, ошибок %s%%).'
                            % (base.get('rps'), base.get('conc'), base.get('p95'), base.get('err_pct')))
    if peak and (not stable or peak.get('conc') != base.get('conc')):
        out['notes'].append('Пиковый RPS за тест — %s при %s параллельных.' % (peak.get('rps'), peak.get('conc')))
    if out['degradation']:
        out['notes'].append('Первая деградация — при %s параллельных: p95 %s мс, ошибок %s%%, блокировок %s.'
                            % (out['degradation']['conc'], out['degradation']['p95'],
                               out['degradation']['err_pct'], out['degradation']['blocked']))
    if reason:
        out['notes'].append('Остановка: ' + reason + '.')
    if stable and peak and peak.get('conc') != stable.get('conc') and stable.get('rps'):
        out['notes'].append('После деградации RPS упал с %s до %s зап/с — запас ёмкости исчерпан на %s параллельных.'
                            % (peak.get('rps'), stable.get('rps'), stable.get('conc')))
    return out


def lt_pause_protection():
    snap = {'acl': [], 'cs_bouncer': False}
    try:
        with db() as conn, conn.cursor() as c:
            c.execute("SELECT id, enabled FROM mgt_acl_config_v3 WHERE built_in = true AND site_id IN (0, 1)")
            snap['acl'] = [[rid, bool(en)] for rid, en in c.fetchall()]
            if snap['acl']:
                c.execute('UPDATE mgt_acl_config_v3 SET enabled = false WHERE id = ANY(%s)',
                          ([r[0] for r in snap['acl']],))
                conn.commit()
    except Exception:
        snap['acl'] = []
    try:
        _rc, out, _err = run(['systemctl', 'is-active', 'crowdsec-firewall-bouncer'], timeout=10)
        snap['cs_bouncer'] = (out or '').strip() == 'active'
        if snap['cs_bouncer']:
            run(['systemctl', 'stop', 'crowdsec-firewall-bouncer'], timeout=30)
    except Exception:
        pass
    return snap


def lt_resume_protection(snap):
    try:
        if snap.get('acl'):
            with db() as conn, conn.cursor() as c:
                for rid, en in snap['acl']:
                    c.execute('UPDATE mgt_acl_config_v3 SET enabled = %s WHERE id = %s', (en, rid))
                conn.commit()
    except Exception:
        pass
    try:
        _rc, out, _err = run(['hostname', '-I'], timeout=10)
        for ip in (out or '').split():
            ip = ip.strip()
            if ip:
                run(['cscli', 'decisions', 'delete', '--ip', ip], timeout=15)
    except Exception:
        pass
    try:
        if snap.get('cs_bouncer'):
            run(['systemctl', 'start', 'crowdsec-firewall-bouncer'], timeout=30)
    except Exception:
        pass


def lt_clean_own_bans():
    try:
        _rc, out, _err = run(['hostname', '-I'], timeout=10)
        for ip in (out or '').split():
            ip = ip.strip()
            if ip:
                run(['cscli', 'decisions', 'delete', '--ip', ip], timeout=15)
    except Exception:
        pass


def lt_probe(url, headers):
    out = []
    ev = threading.Event()
    th = threading.Thread(target=lt_worker, args=(url, headers, ev, out), daemon=True)
    th.start()
    deadline = time.time() + 8
    while time.time() < deadline and not out:
        time.sleep(0.1)
    ev.set()
    th.join(timeout=1)
    return None if out else 'нет ответа от цели за 8 секунд (проверьте доступность/DNS)'


def loadtest_run(job_id, ev):
    paused = None
    try:
        with LOCK:
            job = (STATE.get('loadtest') or {})
            p = dict(job.get('params') or {})
        host = p.get('host') or ''
        url, extra = lt_target(host, p.get('path'), p.get('mode'))
        headers = {'User-Agent': LOADTEST_UA, 'Accept': 'text/html,application/xhtml+xml',
                   'X-SLExt-Test': '1', 'Cookie': 'nrgpass=1', 'Cache-Control': 'no-cache'}
        headers.update(extra)
        p95_ms = int(p.get('p95_ms') or 1500)
        err_pct = float(p.get('err_pct') or 3.0)
        max_conc = int(p.get('max_conc') or 48)
        stage_sec = int(p.get('stage_sec') or 6)
        max_total = int(p.get('max_total_sec') or 240)
        mode = p.get('mode') or 'origin'
        if mode == 'waf' and p.get('auto_pause'):
            paused = lt_pause_protection()
            with LOCK:
                jj = STATE.get('loadtest') or {}
                if jj.get('id') == job_id:
                    jj['protection'] = {'paused': True, 'acl_rules': len(paused.get('acl') or []),
                                        'crowdsec_bouncer': bool(paused.get('cs_bouncer'))}
                    save_state(STATE)
        lt_clean_own_bans()
        probe_err = lt_probe(url, headers)
        if probe_err:
            with LOCK:
                j = STATE.get('loadtest') or {}
                if j.get('id') == job_id:
                    j['status'] = 'error'
                    j['error'] = 'цель недоступна: ' + probe_err
                    j['finished_at'] = int(time.time())
                    save_state(STATE)
            return
        stages = []
        conc = 1
        stable = None
        peak = None
        prev_rps = 0.0
        sat = 0
        reason = ''
        started = int(time.time())
        hard_at = time.time() + max_total
        while conc <= max_conc:
            if ev.is_set():
                reason = 'остановлено вручную'
                break
            if time.time() >= hard_at:
                reason = 'достигнут лимит общего времени'
                break
            take = time.time()
            res = lt_run_stage(url, headers, conc, stage_sec, ev, hard_at)
            elapsed = max(0.5, time.time() - take)
            st = lt_stage_stats(res, elapsed)
            st['conc'] = conc
            st['dur'] = round(elapsed, 1)
            stages.append(st)
            if peak is None or st['rps'] > peak['rps']:
                peak = st
            with LOCK:
                j = STATE.get('loadtest') or {}
                if j.get('id') == job_id:
                    j['stages'] = [dict(s) for s in stages]
                    j['progress'] = {'conc': conc, 'stage': len(stages), 'stats': st,
                                     'elapsed': int(time.time() - started)}
                    j['updated_at'] = int(time.time())
                    save_state(STATE)
            if st['requests'] == 0:
                reason = 'нет ответов — проверьте доступность сайта'
                break
            if st['blocked'] > 3 and st['blocked'] * 100.0 / st['requests'] > 1:
                reason = ('защита блокирует тест (%s ответов 403/429/468) — отключите CrowdSec и лимиты SafeLine и повторите'
                          % st['blocked'])
                break
            if st['err_pct'] > err_pct:
                reason = 'деградация: ошибок %s%% > %s%%' % (st['err_pct'], err_pct)
                break
            if st['p95'] > p95_ms:
                reason = 'деградация: p95 %s мс > %s мс' % (st['p95'], p95_ms)
                break
            stable = st
            if conc >= max_conc:
                reason = 'достигнут заданный максимум параллельных (%s)' % max_conc
                break
            if conc >= 4 and st['rps'] < prev_rps * 1.03:
                sat += 1
            else:
                sat = 0
            if sat >= 2:
                reason = 'выход на плато: RPS не растёт две стадии подряд'
                break
            prev_rps = st['rps']
            conc = min(max_conc, max(conc + 1, int(conc * 1.7)))
        base = stable or peak or {}
        verdict = ('ёмкость: ~%s запросов/с при %s параллельных' % (base.get('rps'), base.get('conc'))
                   if base else 'нет данных')
        totals = {'requests': sum(s.get('requests') or 0 for s in stages),
                  'errors': sum(s.get('err') or 0 for s in stages),
                  'blocked': sum(s.get('blocked') or 0 for s in stages),
                  'stages': len(stages)}
        rep = {'host': host, 'path': p.get('path') or '/', 'mode': mode,
               'started_at': started, 'finished_at': int(time.time()),
               'duration': int(time.time()) - started, 'reason': reason,
               'verdict': verdict, 'stages': stages, 'stable': stable, 'peak': peak,
               'totals': totals, 'analysis': lt_analyze(stages, stable, peak, p95_ms, err_pct, reason),
               'protection': {'paused': bool(paused),
                              'acl_rules': len((paused or {}).get('acl') or []),
                              'crowdsec_bouncer': bool((paused or {}).get('cs_bouncer'))}}
        rep['recommend'] = lt_recommend(rep)
        html = lt_report_html(rep)
        with LOCK:
            j = STATE.get('loadtest') or {}
            if j.get('id') == job_id:
                j['status'] = 'cancelled' if ev.is_set() else 'done'
                j['report'] = rep
                j['report_html'] = html
                j['finished_at'] = int(time.time())
                j['updated_at'] = int(time.time())
                j.pop('progress', None)
                j.pop('protection', None)
                arch = j.setdefault('archive', [])
                entry = dict(rep)
                entry['id'] = job_id
                arch.insert(0, entry)
                del arch[10:]
                save_state(STATE)
    except Exception as e:
        with LOCK:
            j = STATE.get('loadtest') or {}
            if j.get('id') == job_id:
                j['status'] = 'error'
                j['error'] = str(e)[:300]
                save_state(STATE)
    finally:
        if paused:
            lt_resume_protection(paused)


PX_LOG = '/data/safeline/logs/nginx/slext_traffic.log'
PX_LOG1 = PX_LOG + '.1'
PX_LAST_ROTATE = [0]
PX_CACHE = {'at': 0, 'key': '', 'data': None}
PX_BUCKETS = [10, 25, 50, 100, 200, 400, 800, 1600, 3200]


def px_maybe_rotate():
    now = time.time()
    if now - PX_LAST_ROTATE[0] < 300:
        return
    PX_LAST_ROTATE[0] = now
    try:
        if os.path.getsize(PX_LOG) > 100 * 1024 * 1024:
            shutil.move(PX_LOG, PX_LOG1)
            run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reopen'], timeout=30)
    except OSError:
        pass


def px_pct(sorted_vals, p):
    n = len(sorted_vals)
    if not n:
        return 0
    i = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
    return sorted_vals[i]


def proxy_stats(hours, site='', sites=None):
    key = '%s|%s|%s' % (hours, site, ','.join(sites or []))
    now = time.time()
    if PX_CACHE['data'] is not None and PX_CACHE['key'] == key and now - PX_CACHE['at'] < 15:
        return PX_CACHE['data']
    px_maybe_rotate()
    since = now - hours * 3600
    rows = []
    cut = False
    for path in (PX_LOG, PX_LOG1, PX_LOG1 + '.gz'):
        try:
            fh = gzip.open(path, 'rt', errors='replace') if path.endswith('.gz') else open(path, errors='replace')
            with fh:
                for line in fh:
                    if cut:
                        break
                    if len(rows) > 400000:
                        cut = True
                        break
                    parts = line.rstrip('\n').split('|')
                    if len(parts) < 11:
                        continue
                    try:
                        ts = datetime.datetime.fromisoformat(parts[1]).timestamp()
                    except (ValueError, TypeError):
                        continue
                    if ts < since:
                        continue
                    host = parts[2]
                    if site and host != site:
                        continue
                    if sites and host not in sites:
                        continue
                    req = parts[3] or ''
                    rp = req.split(' ')
                    method = rp[0] if rp else ''
                    pathq = rp[1] if len(rp) > 1 else '/'
                    try:
                        status = int(parts[4] or 0)
                    except ValueError:
                        status = 0
                    try:
                        b_out = int(parts[5] or 0)
                    except ValueError:
                        b_out = 0
                    try:
                        b_in = int(parts[6] or 0)
                    except ValueError:
                        b_in = 0
                    try:
                        rt = float(parts[7] or 0) * 1000.0
                    except ValueError:
                        rt = 0.0
                    urt = None
                    try:
                        if parts[8] and parts[8] != '-':
                            urt = float(parts[8].split(',')[0]) * 1000.0
                    except ValueError:
                        urt = None
                    ua = parts[10] if len(parts) > 10 else ''
                    ref = parts[11] if len(parts) > 11 else ''
                    if 'SLExt-LoadTest' in ua:
                        kind = 'test'
                    elif BOT_RX.search(ua):
                        kind = 'bot'
                    else:
                        kind = 'human'
                    rows.append((ts, status, b_out, b_in, rt, urt, method, pathq.split('?')[0][:200],
                                 kind, ua[:200], ref[:200], host, parts[0][:64]))
        except OSError:
            continue
    live = [r for r in rows if r[8] != 'test']
    n = len(live)
    out = {'ok': True, 'hours': hours, 'site': site, 'total': n,
           'test_total': len(rows) - n, 'apdex_t': 250, 'cut': cut,
           'rps': 0.0, 'apdex': 1.0, 'p50': 0, 'p75': 0, 'p90': 0, 'p95': 0, 'p99': 0,
           'uniq': 0, 'referers': [],
           'err5_pct': 0.0, 'err4_pct': 0.0, 'bw_out': 0, 'bw_in': 0, 'bots': 0, 'humans': 0,
           'up_avg': None, 'up_p95': None, 'tot_avg': None, 'tot_p95': None,
           'over_avg': None, 'over_p95': None, 'up_cov': 0,
           'timeline': [], 'hist': [], 'statuses': [], 'paths': [], 'slow': [], 'methods': []}
    if not n:
        PX_CACHE.update({'at': now, 'key': key, 'data': out})
        return out
    T = 250.0
    ok_durs = sorted(r[4] for r in live if 200 <= r[1] < 400)
    if not ok_durs:
        ok_durs = sorted(r[4] for r in live)
    err_durs = sorted(r[4] for r in live if r[1] >= 500)
    st = {}
    err5 = err4 = 0
    bw_out = bw_in = 0
    bots = humans = 0
    over = []
    up_vals = []
    sat = tol = 0
    for r in live:
        st[r[1]] = st.get(r[1], 0) + 1
        if r[1] >= 500:
            err5 += 1
        elif r[1] >= 400:
            err4 += 1
        bw_out += r[2]
        bw_in += r[3]
        if r[8] == 'bot':
            bots += 1
        else:
            humans += 1
        if r[5] is not None:
            up_vals.append(r[5])
            over.append(max(0.0, r[4] - r[5]))
        if r[4] <= T:
            sat += 1
        elif r[4] <= 4 * T:
            tol += 1
    out.update({
        'rps': round(n / max(1.0, hours * 3600.0), 3),
        'apdex': round((sat + tol / 2.0) / n, 3),
        'p50': round(px_pct(ok_durs, 50), 1),
        'p75': round(px_pct(ok_durs, 75), 1),
        'p90': round(px_pct(ok_durs, 90), 1),
        'p95': round(px_pct(ok_durs, 95), 1),
        'p99': round(px_pct(ok_durs, 99), 1),
        'p95_err': round(px_pct(err_durs, 95), 1) if err_durs else None,
        'err5_pct': round(err5 * 100.0 / n, 2),
        'err4_pct': round(err4 * 100.0 / n, 2),
        'bw_out': bw_out, 'bw_in': bw_in, 'bots': bots, 'humans': humans,
        'uniq': len(set(r[12] for r in live)),
        'up_cov': round(len(up_vals) * 100.0 / n, 1),
    })
    refs = {}
    for r in live:
        ref = (r[10] or '').strip()
        if not ref or ref == '-':
            continue
        try:
            rh = urllib.parse.urlparse(ref).hostname or ref.split('/')[0]
        except ValueError:
            rh = ref[:60]
        refs[rh] = refs.get(rh, 0) + 1
    out['referers'] = [{'host': k, 'count': v}
                       for k, v in sorted(refs.items(), key=lambda x: -x[1])[:10]]
    tot_vals = sorted(r[4] for r in live)
    if up_vals:
        up_vals.sort()
        over.sort()
        out.update({
            'up_avg': round(sum(up_vals) / len(up_vals), 1),
            'up_p95': round(px_pct(up_vals, 95), 1),
            'over_avg': round(sum(over) / len(over), 1),
            'over_p95': round(px_pct(over, 95), 1),
        })
    out['tot_avg'] = round(sum(tot_vals) / len(tot_vals), 1)
    out['tot_p95'] = round(px_pct(tot_vals, 95), 1)
    hist = [0] * (len(PX_BUCKETS) + 1)
    for r in live:
        v = r[4]
        for i, e in enumerate(PX_BUCKETS):
            if v <= e:
                hist[i] += 1
                break
        else:
            hist[-1] += 1
    labels = []
    prev = 0
    for e in PX_BUCKETS:
        labels.append('%s–%s мс' % (prev, e))
        prev = e
    labels.append('> %s мс' % PX_BUCKETS[-1])
    out['hist'] = [{'label': labels[i], 'count': hist[i]} for i in range(len(hist))]
    bkt = 300 if hours <= 6 else (900 if hours <= 48 else (3600 if hours <= 168 else 21600))
    tl = {}
    for r in live:
        b = int(r[0] // bkt * bkt)
        t = tl.setdefault(b, {'n': 0, 'd': [], 'e4': 0, 'e5': 0, 'out': 0, 'in': 0})
        t['n'] += 1
        t['d'].append(r[4])
        t['out'] += r[2]
        t['in'] += r[3]
        if r[1] >= 500:
            t['e5'] += 1
        elif r[1] >= 400:
            t['e4'] += 1
    for b in sorted(tl):
        t = tl[b]
        t['d'].sort()
        out['timeline'].append({
            'ts': b, 'count': t['n'],
            'rps': round(t['n'] / float(bkt), 2),
            'p50': round(px_pct(t['d'], 50), 1),
            'p95': round(px_pct(t['d'], 95), 1),
            'e4': t['e4'], 'e5': t['e5'],
            'out_mb': round(t['out'] / 1048576.0, 2),
            'in_mb': round(t['in'] / 1048576.0, 2)})
    statuses = []
    for code in sorted(st, reverse=True):
        statuses.append({'code': code, 'count': st[code], 'pct': round(st[code] * 100.0 / n, 2),
                         'class': ('%dxx' % (code // 100)) if code else '—'})
    out['statuses'] = statuses[:20]
    methods = {}
    for r in live:
        methods[r[6]] = methods.get(r[6], 0) + 1
    out['methods'] = sorted([{'method': k or '—', 'count': v} for k, v in methods.items()],
                            key=lambda x: -x['count'])[:6]
    by_path = {}
    for r in live:
        p = by_path.setdefault(r[7], {'n': 0, 'sum': 0.0, 'd': [], 'err': 0})
        p['n'] += 1
        p['sum'] += r[4]
        if len(p['d']) < 2000:
            p['d'].append(r[4])
        if r[1] >= 400:
            p['err'] += 1
    paths = sorted(by_path.items(), key=lambda kv: -kv[1]['n'])[:12]
    out['paths'] = [{'path': k, 'count': v['n'], 'avg': round(v['sum'] / v['n'], 1),
                     'p95': round(px_pct(sorted(v['d']), 95), 1),
                     'err_pct': round(v['err'] * 100.0 / v['n'], 1)} for k, v in paths]
    slow = sorted(live, key=lambda r: -r[4])[:12]
    out['slow'] = [{'ts': int(r[0]), 'method': r[6], 'path': r[7][:120], 'status': r[1],
                    'ms': round(r[4], 1), 'up_ms': round(r[5], 1) if r[5] is not None else None,
                    'ip': r[12]} for r in slow]
    PX_CACHE.update({'at': now, 'key': key, 'data': out})
    return out


def dns_query_domain(name, qtype, server=None, timeout=3):
    import socket as _s
    srv = server or _dns_server()
    tid = int(time.time() * 1000) & 0xFFFF
    pkt = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    try:
        for label in name.rstrip('.').split('.'):
            lb = label.encode('idna')
            pkt += bytes([len(lb)]) + lb
        pkt += b'\x00'
    except UnicodeError:
        return {'ok': False, 'error': 'bad name', 'ms': 0, 'records': []}
    pkt += struct.pack('!HH', qtype, 1)
    t0 = time.time()
    try:
        with _s.socket(_s.AF_INET, _s.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (srv, 53))
            data, _ = s.recvfrom(4096)
        ms = round((time.time() - t0) * 1000, 1)
    except OSError as e:
        return {'ok': False, 'error': str(e)[:80], 'ms': round((time.time() - t0) * 1000, 1), 'records': []}
    if len(data) < 12 or struct.unpack('!H', data[0:2])[0] != tid:
        return {'ok': False, 'error': 'bad response', 'ms': ms, 'records': []}
    rcode = data[3] & 0x0F
    qd, an = struct.unpack('!HH', data[4:8])
    off = 12
    for _ in range(qd):
        _nm, off = _dns_name(data, off)
        off += 4
    records = []
    for _ in range(an):
        nm, off = _dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack('!HHIH', data[off:off + 10])
        off += 10
        val = ''
        try:
            if rtype == 1 and rdlen == 4:
                val = '.'.join(str(b) for b in data[off:off + 4])
            elif rtype == 28 and rdlen == 16:
                val = ':'.join('%x' % x for x in struct.unpack('!8H', data[off:off + 16]))
            elif rtype in (2, 5, 12):
                val, _ = _dns_name(data, off)
            elif rtype == 15:
                pref = struct.unpack('!H', data[off:off + 2])[0]
                mx, _ = _dns_name(data, off + 2)
                val = '%s %s' % (pref, mx)
            elif rtype == 16:
                p = off
                end = off + rdlen
                parts = []
                while p < end:
                    ln = data[p]
                    parts.append(data[p + 1:p + 1 + ln].decode('utf-8', 'replace'))
                    p += 1 + ln
                val = ' '.join(parts)
        except (struct.error, IndexError):
            val = ''
        records.append({'type': rtype, 'ttl': ttl, 'value': val})
        off += rdlen
    return {'ok': rcode == 0, 'rcode': rcode, 'ms': ms, 'records': records}


def _dns_server():
    srv = '1.1.1.1'
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    p = line.split()
                    if len(p) > 1:
                        return p[1]
    except OSError:
        pass
    return srv


def _dns_name(data, off):
    labels = []
    end = off
    jumped = False
    guard = 0
    while off < len(data) and guard < 128:
        guard += 1
        ln = data[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack('!H', data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + ln].decode('utf-8', 'replace'))
        off += 1 + ln
        if not jumped:
            end = off
    return '.'.join(labels), end


def dns_tls_info(host):
    out = {'ms': None, 'subject': '', 'issuer': '', 'not_after': '', 'days_left': None, 'error': ''}
    t0 = time.time()
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out['ms'] = round((time.time() - t0) * 1000, 1)
    except Exception as e:
        out['error'] = str(e)[:100]
        return out
    try:
        pem = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-enddate'],
                             input=ssl.get_server_certificate((host, 443)),
                             capture_output=True, text=True, timeout=10).stdout
        for line in pem.splitlines():
            if line.startswith('subject='):
                out['subject'] = line.split('=', 1)[1].strip()[:200]
            elif line.startswith('issuer='):
                out['issuer'] = line.split('=', 1)[1].strip()[:200]
            elif line.startswith('notAfter='):
                out['not_after'] = line.split('=', 1)[1].strip()
                try:
                    exp = datetime.datetime.strptime(out['not_after'], '%b %d %H:%M:%S %Y %Z')
                    out['days_left'] = (exp - datetime.datetime.utcnow()).days
                except ValueError:
                    pass
    except Exception as e:
        out['error'] = str(e)[:100]
    return out


def dns_check_host(host, full=False):
    a = dns_query_domain(host, 1)
    aaaa = dns_query_domain(host, 28)
    recs_a = [r for r in a.get('records', []) if r['type'] == 1]
    recs_aaaa = [r for r in aaaa.get('records', []) if r['type'] == 28]
    ok = bool(a.get('ok') or aaaa.get('ok'))
    out = {'host': host, 'at': int(time.time()), 'ok': ok,
           'ms': a.get('ms') if a.get('ok') else (aaaa.get('ms') if aaaa.get('ok') else None),
           'a': recs_a, 'aaaa': recs_aaaa,
           'error': '' if ok else (a.get('error') or aaaa.get('error') or ('DNS rc=%s' % a.get('rcode')))}
    out['tls'] = dns_tls_info(host) if ok else {}
    if full and ok:
        ns = [r['value'] for r in dns_query_domain(host, 2).get('records', []) if r['type'] == 2]
        mx = [r['value'] for r in dns_query_domain(host, 15).get('records', []) if r['type'] == 15]
        txt = [r['value'] for r in dns_query_domain(host, 16).get('records', []) if r['type'] == 16]
        cname = [r['value'] for r in dns_query_domain(host, 5).get('records', []) if r['type'] == 5]
        out['ns'] = ns[:8]
        out['mx'] = mx[:8]
        out['txt'] = txt[:10]
        out['cname'] = cname[:4]
        out['spf'] = any(t.lower().startswith('v=spf1') for t in txt)
        out['dmarc'] = bool(dns_query_domain('_dmarc.' + host, 16).get('records'))
    return out


def dns_worker():
    time.sleep(15)
    while True:
        try:
            hosts = []
            for s in site_list():
                hosts.extend(s.get('hosts') or [])
            with LOCK:
                st = STATE.setdefault('dns', {}).setdefault('hosts', {})
            for h in dict.fromkeys(hosts):
                if not h:
                    continue
                with LOCK:
                    cur = st.get(h) or {}
                    last_full = int(cur.get('last_full') or 0)
                res = dns_check_host(h, full=(time.time() - last_full > 1800))
                if res.get('ok') and (time.time() - last_full > 1800):
                    res['last_full'] = int(time.time())
                with LOCK:
                    cur = st.setdefault(h, {})
                    if res.get('last_full'):
                        cur['last_full'] = res.pop('last_full')
                    cur['last'] = res
                    if 'ns' in res:
                        cur['records_at'] = res['at']
                    samp = cur.setdefault('samples', [])
                    samp.append({'ts': res['at'], 'ms': res.get('ms'), 'ok': bool(res.get('ok'))})
                    del samp[576:]
                    save_state(STATE)
        except Exception:
            pass
        time.sleep(300)


SLEXT_PERMS = [
    ('overview.view', 'Обзор — анализ атак'),
    ('crowdsec.view', 'CrowdSec — просмотр'),
    ('crowdsec.ban', 'CrowdSec — бан и разбан'),
    ('proxy.view', 'Проксирование — аналитика'),
    ('dns.view', 'DNS и TLS — просмотр'),
    ('dns.check', 'DNS и TLS — запуск проверки'),
    ('wr.view', 'Зал ожидания — просмотр'),
    ('wr.control', 'Зал ожидания — вкл/выкл'),
    ('wr.settings', 'Зал ожидания — настройки и страница'),
    ('lt.view', 'Тест ёмкости — просмотр и архив'),
    ('lt.run', 'Тест ёмкости — запуск и остановка'),
    ('lt.apply', 'Тест ёмкости — подстановка в зал'),
    ('lt.archive_del', 'Тест ёмкости — удаление из архива'),
    ('pages.view', 'Страницы ошибок — просмотр'),
    ('pages.edit', 'Страницы ошибок — изменение'),
    ('skip.view', 'Skip decryption — просмотр'),
    ('skip.control', 'Skip decryption — переключение'),
    ('geo.view', 'Гео-блокировка — просмотр'),
    ('geo.edit', 'Гео-блокировка — изменение'),
    ('notify.view', 'Уведомления — просмотр'),
    ('notify.edit', 'Уведомления — изменение'),
    ('access.manage', 'Управление доступом'),
]
PERM_KEYS = [k for k, _ in SLEXT_PERMS]
ALL_VIEW = [k for k in PERM_KEYS if k.endswith('.view')]
SLEXT_ROLES = {
    'admin': PERM_KEYS,
    'operator': ALL_VIEW + ['crowdsec.ban', 'wr.control', 'lt.run', 'dns.check'],
    'viewer': ALL_VIEW,
    'custom': [],
}
ROLE_LABELS = {'admin': 'Администратор', 'operator': 'Оператор', 'viewer': 'Наблюдатель', 'custom': 'Настраиваемый'}

PERM_GET = {
    '/api/attacks': 'overview.view',
    '/api/geo/check': 'geo.view',
    '/api/crowdsec': 'crowdsec.view',
    '/api/proxy': 'proxy.view',
    '/api/dns': 'dns.view',
    '/api/waiting': 'wr.view',
    '/api/loadtest': 'lt.view',
    '/api/loadtest/archive/get': 'lt.view',
    '/api/loadtest/report': 'lt.view',
    '/api/page': 'pages.view',
    '/api/skip': 'skip.view',
    '/api/geo': 'geo.view',
    '/api/notify': 'notify.view',
    '/api/alarm': 'notify.view',
    '/api/syslog': 'notify.view',
    '/api/backup': 'notify.view',
    '/api/export': 'overview.view',
}
PERM_POST = {
    '/api/crowdsec/ban': 'crowdsec.ban',
    '/api/crowdsec/unban': 'crowdsec.ban',
    '/api/dns/check': 'dns.check',
    '/api/waiting/config': 'wr.control',
    '/api/waiting/queue': 'wr.control',
    '/api/waiting/extras': 'wr.settings',
    '/api/waiting/page': 'wr.settings',
    '/api/waiting/reset': 'wr.control',
    '/api/loadtest/start': 'lt.run',
    '/api/loadtest/stop': 'lt.run',
    '/api/loadtest/apply': 'lt.apply',
    '/api/loadtest/archive/delete': 'lt.archive_del',
    '/api/page': 'pages.edit',
    '/api/skip': 'skip.control',
    '/api/geo': 'geo.edit',
    '/api/geo/sync': 'geo.edit',
    '/api/notify': 'notify.edit',
    '/api/notify/test': 'notify.edit',
    '/api/alarm': 'notify.edit',
    '/api/syslog': 'notify.edit',
    '/api/syslog/test': 'notify.edit',
    '/api/backup': 'notify.edit',
    '/api/backup/run': 'notify.edit',
}


def panel_users():
    try:
        with db() as conn, conn.cursor() as c:
            c.execute('SELECT username FROM mgt_user ORDER BY id')
            return [r[0] for r in c.fetchall() if r[0]]
    except Exception:
        return []


def user_hash(password):
    """Парольный хеш SafeLine CE: PBKDF2-HMAC-SHA256, соль ascii, 1024 итерации, 32 байта."""
    salt = ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                   for _ in range(8))
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 1024, dklen=32).hex()
    return digest, salt


def site_hosts():
    return sorted({h for s in site_list() for h in (s.get('hosts') or []) if h})


def token_username(tok):
    try:
        parts = str(tok or '').split('.')
        if len(parts) < 2:
            return ''
        p = parts[1] + '=' * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(p).decode('utf-8', 'replace'))
        return str(data.get('Username') or '')[:100]
    except Exception:
        return ''


def user_access(username):
    cfg = (STATE.get('access') or {}).get('users') or {}
    ent = cfg.get(username) or {}
    role = ent.get('role') or 'admin'
    if role not in SLEXT_ROLES:
        role = 'admin'
    if role == 'admin':
        perms = list(PERM_KEYS)
    elif role == 'custom':
        perms = [p for p in (ent.get('perms') or []) if p in PERM_KEYS]
    else:
        perms = list(SLEXT_ROLES[role])
    domains = [d for d in (ent.get('domains') or []) if d]
    return {'username': username, 'role': role, 'perms': perms, 'domains': domains,
            'configured': bool(ent)}


class H(BaseHTTPRequestHandler):
    server_version = 'slext/3.0'
    timeout = 60

    def log_message(self, fmt, *args):
        print('[api] ' + (fmt % args), flush=True)

    def _cors(self):
        origin = self.headers.get('Origin', '')
        if CC_PATTERN.match(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        elif self.path.startswith('/api/waiting/status') and origin.startswith('http'):
            try:
                host = urllib.parse.urlparse(origin).hostname or ''
            except ValueError:
                host = ''
            if host and any(host in (s['hosts'] or []) for s in site_list()):
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Vary', 'Origin')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')

    def _token(self):
        auth = self.headers.get('Authorization', '')
        return auth[7:] if auth.startswith('Bearer ') else ''

    def _json(self, code, obj, extra=None):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self._cors()
        for k, v in (extra or []):
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _text(self, code, text, ctype='text/plain; charset=utf-8', filename=None):
        data = text.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        if filename:
            self.send_header('Content-Disposition', 'attachment; filename="%s"' % filename)
        self._cors()
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0 or n > 1048576:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or '{}')
        except ValueError:
            return {}

    def _auth(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return verify_token(auth[7:])
        return False

    def _user(self):
        if not hasattr(self, '_slu'):
            uname = token_username(self._token()) or 'admin'
            self._slu = user_access(uname)
        return self._slu

    def _need(self, perm):
        return perm in self._user()['perms']

    def _hosts_allowed(self):
        return self._user().get('domains') or []

    def _host_ok(self, host):
        allowed = self._hosts_allowed()
        if not allowed:
            return True
        return bool(host) and host in allowed

    def _filters(self, qs):
        def _int(name):
            v = qs.get(name, [''])[0]
            if v == '':
                return None
            try:
                return int(v)
            except ValueError:
                return None
        return (_int('action'), _int('type'), _int('risk'))

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == '/api/health':
            return self._json(200, health())
        if u.path == '/api/skip':
            with LOCK:
                sk = json.loads(json.dumps(STATE.get('skip') or {'enabled': True}))
            return self._json(200, {'ok': True, 'skip': sk})
        if u.path == '/api/queue/status':
            return handle_queue_status(self)
        if u.path == '/api/waiting/status':
            host = qs.get('site', [''])[0][:200]
            site = site_by_host(host)
            out = {'ok': True, 'enabled': False, 'last': {}, 'agg': {}}
            if site:
                conf = waiting_conf(site['id'])
                st = waiting_stats(site['id'], 30)
                out['enabled'] = bool(conf.get('is_enabled'))
                out['last'] = st['history'][0] if st.get('history') else {}
                out['agg'] = st.get('agg') or {}
            return self._json(200, out)
        if not self._auth():
            return self._json(401, {'ok': False, 'error': 'unauthorized'})
        if u.path == '/api/me':
            return self._json(200, {'ok': True, 'user': self._user()})
        if u.path == '/api/access':
            if self._user()['role'] != 'admin':
                return self._json(403, {'ok': False, 'error': 'управление доступом — только администратор'})
            cfg = (STATE.get('access') or {}).get('users') or {}
            out = []
            for uname in panel_users():
                acc = user_access(uname)
                out.append({'username': uname, 'role': acc['role'],
                            'perms': (cfg.get(uname) or {}).get('perms') or [],
                            'domains': acc['domains'], 'configured': acc['configured']})
            return self._json(200, {'ok': True, 'users': out, 'me': self._user()['username'],
                                    'roles': {k: (PERM_KEYS if k == 'admin' else SLEXT_ROLES[k]) for k in SLEXT_ROLES},
                                    'role_labels': ROLE_LABELS,
                                    'perms': [{'key': k, 'label': l} for k, l in SLEXT_PERMS],
                                    'hosts': site_hosts()})
        if u.path in PERM_GET and not self._need(PERM_GET[u.path]):
            return self._json(403, {'ok': False, 'error': 'нет доступа: ' + PERM_GET[u.path]})
        if u.path == '/api/attacks':
            try:
                hours = max(1, min(8760, int(qs.get('hours', ['24'])[0])))
            except ValueError:
                hours = 24
            action, atype, risk = self._filters(qs)
            site = qs.get('site', [''])[0][:200]
            if site and not self._host_ok(site):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + site})
            asites = [site] if site else (self._hosts_allowed() or None)
            return self._json(200, attacks(hours, site, action, atype, risk, sites=asites))
        if u.path == '/api/security':
            try:
                hours = max(1, min(168, int(qs.get('hours', ['24'])[0])))
            except ValueError:
                hours = 24
            return self._json(200, security_stats(hours))
        if u.path == '/api/waiting':
            sites = site_list()
            allowed = self._hosts_allowed()
            if allowed:
                sites = [s for s in sites if any(h in allowed for h in (s.get('hosts') or []))]
                if not sites:
                    return self._json(403, {'ok': False, 'error': 'нет доступа к доменам'})
            host = qs.get('site', [''])[0][:200]
            if host and not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            if not host and sites:
                host = (sites[0]['hosts'] or [''])[0]
            site = site_by_host(host) if host else None
            conf = mgt_conf_cached(site['id'], ttl=3) if site else {}
            stats = waiting_stats(site['id']) if site else {}
            with LOCK:
                panel_base = str((STATE.get('waiting') or {}).get('panel_base') or '')
                patch = dict(WR_PATCH)
            cfg = waiting_cfg(host)
            live = None
            try:
                au = cfg.get('auto') or {}
                if au.get('enabled'):
                    live = real_rate_pm(clamp_int(au.get('window'), 30, 3600, 60))
            except Exception:
                live = None
            return self._json(200, {'ok': True, 'sites': sites, 'host': host,
                                    'site': site, 'mgt': conf, 'mgt_ok': bool(conf), 'cfg': cfg,
                                    'live_rate': live, 'stats': stats, 'panel_base': panel_base,
                                    'busy': WR_OP_LOCK.locked(), 'patch': patch,
                                    'limits': {'desired': wr_limits_desired(host),
                                               'actual': wr_limits_actual(site['id']) if site else {}},
                                    'queue': queue_cfg(host) if host else queue_defaults(),
                                    'queue_stats': queue_stats(host) if host else
                                    {'active': 0, 'waiting': 0, 'served': 0, 'peak_waiting': 0, 'started_at': 0}})
        if u.path == '/api/loadtest':
            with LOCK:
                job = json.loads(json.dumps(STATE.get('loadtest') or {}))
            arch = job.pop('archive', []) or []
            html = job.pop('report_html', None)
            if html:
                job['has_report'] = True
            items = [{'id': a.get('id'), 'host': a.get('host'), 'mode': a.get('mode'),
                      'started_at': a.get('started_at'), 'duration': a.get('duration'),
                      'reason': a.get('reason'), 'verdict': a.get('verdict'),
                      'stable': a.get('stable'), 'totals': a.get('totals'),
                      'protection': a.get('protection')} for a in arch]
            return self._json(200, {'ok': True, 'job': job, 'archive': items, 'sites': site_list()})
        if u.path == '/api/loadtest/archive/get':
            jid = qs.get('id', [''])[0][:40]
            with LOCK:
                rep = None
                for a in ((STATE.get('loadtest') or {}).get('archive') or []):
                    if str(a.get('id')) == jid:
                        rep = a
                        break
            if not rep:
                return self._json(404, {'ok': False, 'error': 'отчёт не найден'})
            return self._json(200, {'ok': True, 'report': rep})
        if u.path == '/api/loadtest/report':
            jid = qs.get('id', [''])[0][:40]
            with LOCK:
                lt = STATE.get('loadtest') or {}
                html = ''
                if jid:
                    for a in (lt.get('archive') or []):
                        if str(a.get('id')) == jid:
                            html = lt_report_html(a)
                            break
                else:
                    html = str(lt.get('report_html') or '')
            if not html:
                return self._json(404, {'ok': False, 'error': 'отчёта нет'})
            return self._text(200, html, 'text/html; charset=utf-8', 'slext-loadtest-report.html')
        if u.path == '/api/dns':
            with LOCK:
                dns = json.loads(json.dumps(STATE.get('dns') or {}))
            hosts = []
            for h, v in (dns.get('hosts') or {}).items():
                hosts.append({'host': h, 'last': v.get('last') or {},
                              'records_at': v.get('records_at') or 0,
                              'samples': v.get('samples') or []})
            hosts.sort(key=lambda x: x['host'])
            return self._json(200, {'ok': True, 'hosts': hosts})
        if u.path == '/api/proxy':
            try:
                hours = max(1, min(720, int(qs.get('hours', ['24'])[0])))
            except ValueError:
                hours = 24
            site = qs.get('site', [''])[0][:200]
            if site and not self._host_ok(site):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + site})
            psites = [site] if site else (self._hosts_allowed() or None)
            try:
                return self._json(200, proxy_stats(hours, site, psites))
            except Exception as e:
                return self._json(500, {'ok': False, 'error': str(e)[:300]})
        if u.path == '/api/traffic':
            try:
                hours = max(1, min(168, int(qs.get('hours', ['24'])[0])))
            except ValueError:
                hours = 24
            return self._json(200, traffic(hours))
        if u.path == '/api/export':
            try:
                hours = max(1, min(8760, int(qs.get('hours', ['168'])[0])))
            except ValueError:
                hours = 168
            action, atype, risk = self._filters(qs)
            site = qs.get('site', [''])[0][:200]
            if site and not self._host_ok(site):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + site})
            esites = [site] if site else (self._hosts_allowed() or None)
            fmt = qs.get('format', ['csv'])[0]
            try:
                sc, rows = export_rows(hours, site, action, atype, risk, sites=esites)
            except Exception as e:
                return self._json(500, {'ok': False, 'error': str(e)[:300]})
            if fmt == 'json':
                return self._text(200, export_json(rows, sc), 'application/json',
                                  'safeline-attacks.json')
            return self._text(200, export_csv(rows, sc), 'text/csv',
                              'safeline-attacks.csv')
        if u.path == '/api/lb':
            with LOCK:
                lb = json.loads(json.dumps(STATE['lb']))
            return self._json(200, {'ok': True, 'lb': lb, 'status': backend_status(lb)})
        if u.path == '/api/lb/test':
            try:
                n = max(1, min(100, int(qs.get('n', ['6'])[0])))
            except ValueError:
                n = 6
            results = []
            for _ in range(n):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:8081/', timeout=3) as r:
                        results.append(r.read(200).decode('utf-8', 'replace'))
                except Exception as e:
                    results.append('ERR ' + str(e)[:80])
            return self._json(200, {'ok': True, 'results': results})
        if u.path == '/api/notify':
            with LOCK:
                return self._json(200, {'ok': True, 'notify': STATE['notify']})
        if u.path == '/api/telegram':
            with LOCK:
                return self._json(200, {'ok': True, 'telegram': STATE['notify']['telegram']})
        if u.path == '/api/geo':
            countries = load_countries()
            selected = [c.upper() for c in (STATE['geo'].get('countries') or [])]
            items = []
            for cc in selected:
                cached = geo_cached(cc)
                items.append({'code': cc, 'name': countries.get(cc, cc), 'cidrs': cached})
            return self._json(200, {'ok': True, 'geo': STATE['geo'],
                                    'selected': items, 'countries': countries})
        if u.path == '/api/page':
            with LOCK:
                page = json.loads(json.dumps(STATE['page']))
            page_color = str(page.get('color') or '')
            if not page_color or page_color == '#0fc6c2':
                for c in PAGE_DEFS:
                    page['pages'][c]['color'] = PAGE_DEFS[c]['color']
            defs = {c: {'loc': PAGE_DEFS[c]['loc'], 'title': PAGE_DEFS[c]['title'],
                        'message': PAGE_DEFS[c]['message']} for c in PAGE_DEFS}
            return self._json(200, {'ok': True, 'page': page, 'defs': defs})
        if u.path == '/api/alarm':
            with LOCK:
                return self._json(200, {'ok': True, 'alarm': STATE['alarm']})
        if u.path == '/api/syslog':
            with LOCK:
                return self._json(200, {'ok': True, 'syslog': STATE['syslog']})
        if u.path == '/api/backup':
            with LOCK:
                cfg = dict(STATE['backup'])
            files = []
            try:
                for fn in sorted(os.listdir(cfg.get('dir') or '/var/backups/slext'), reverse=True):
                    fp = os.path.join(cfg.get('dir') or '/var/backups/slext', fn)
                    if fn.endswith('.tar.gz') and os.path.isfile(fp):
                        files.append({'name': fn, 'size': os.path.getsize(fp),
                                      'mtime': int(os.path.getmtime(fp))})
            except OSError:
                pass
            return self._json(200, {'ok': True, 'backup': cfg, 'files': files[:30]})
        if u.path == '/api/crowdsec':
            return self._json(200, crowdsec_list())
        return self._json(404, {'ok': False, 'error': 'not found'})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        body = self._body()
        if u.path == '/api/session/verify':
            return self._json(401, {'ok': False, 'error': 'deprecated'})
        if not self._auth():
            return self._json(401, {'ok': False, 'error': 'unauthorized'})
        if u.path in PERM_POST and not self._need(PERM_POST[u.path]):
            return self._json(403, {'ok': False, 'error': 'нет доступа: ' + PERM_POST[u.path]})
        if u.path in ('/api/access', '/api/access/save') and self._user()['role'] != 'admin':
            return self._json(403, {'ok': False, 'error': 'управление доступом — только администратор'})
        if u.path == '/api/access/save':
            uname = str(body.get('username') or '')[:100]
            if uname not in panel_users():
                return self._json(400, {'ok': False, 'error': 'пользователь не найден'})
            role = str(body.get('role') or 'admin')
            if role not in SLEXT_ROLES:
                return self._json(400, {'ok': False, 'error': 'неизвестная роль'})
            perms = [p for p in (body.get('perms') or []) if p in PERM_KEYS and p != 'access.manage']
            hosts = site_hosts()
            domains = [d for d in (body.get('domains') or []) if d in hosts]
            with LOCK:
                cfg = STATE.setdefault('access', {}).setdefault('users', {})
                if uname == self._user()['username'] and role != 'admin':
                    others = [n for n, e in cfg.items()
                              if n != uname and (e.get('role') or 'admin') == 'admin']
                    others += [n for n in panel_users() if n != uname and n not in cfg]
                    if not others:
                        return self._json(400, {'ok': False,
                                                'error': 'нельзя снять права администратора с последнего администратора'})
                cfg[uname] = {'role': role, 'perms': perms, 'domains': domains,
                              'updated_at': int(time.time())}
                save_state(STATE)
            return self._json(200, {'ok': True})
        if u.path == '/api/access/user':
            uname = str(body.get('username') or '').strip()[:64]
            password = str(body.get('password') or '')
            if not re.match(r'^[A-Za-z0-9_.\-]{3,64}$', uname):
                return self._json(400, {'ok': False,
                                        'error': 'логин: 3-64 символа (латиница, цифры, . _ -)'})
            if len(password) < 8:
                return self._json(400, {'ok': False, 'error': 'пароль: минимум 8 символов'})
            if uname in panel_users():
                return self._json(400, {'ok': False, 'error': 'такой пользователь уже есть'})
            digest, salt = user_hash(password)
            try:
                with db() as conn, conn.cursor() as c:
                    c.execute('INSERT INTO mgt_user (role, username, password, kdf, salt, password_enabled, '
                              'tfa_enabled, tfa_binded, jwt_version, created_at, updated_at, api_token, third_id) '
                              'VALUES (1, %s, %s, %s, %s, true, false, false, 1, now(), now(), \'\', \'\')',
                              (uname, digest, 'pbkdf2', salt))
                    conn.commit()
            except Exception as e:
                return self._json(500, {'ok': False, 'error': str(e)[:200]})
            return self._json(200, {'ok': True, 'username': uname})
        if u.path == '/api/access/user/delete':
            uname = str(body.get('username') or '')[:64]
            if uname == self._user()['username']:
                return self._json(400, {'ok': False, 'error': 'нельзя удалить себя'})
            if uname == 'admin':
                return self._json(400, {'ok': False, 'error': 'учётную запись admin удалять нельзя'})
            if uname not in panel_users():
                return self._json(404, {'ok': False, 'error': 'пользователь не найден'})
            with db() as conn, conn.cursor() as c:
                c.execute('DELETE FROM mgt_user WHERE username=%s', (uname,))
                conn.commit()
            with LOCK:
                (STATE.get('access') or {}).get('users', {}).pop(uname, None)
                save_state(STATE)
            return self._json(200, {'ok': True})
        if u.path == '/api/access/user/password':
            uname = str(body.get('username') or '')[:64]
            password = str(body.get('password') or '')
            if len(password) < 8:
                return self._json(400, {'ok': False, 'error': 'пароль: минимум 8 символов'})
            if uname not in panel_users():
                return self._json(404, {'ok': False, 'error': 'пользователь не найден'})
            digest, salt = user_hash(password)
            with db() as conn, conn.cursor() as c:
                c.execute("UPDATE mgt_user SET password=%s, kdf='pbkdf2', salt=%s, pwd_updated_at=now(), "
                          'jwt_version = jwt_version + 1 WHERE username=%s', (digest, salt, uname))
                conn.commit()
            return self._json(200, {'ok': True})
        if u.path == '/api/lb':
            lb = body.get('lb') or {}
            algo = lb.get('algorithm', 'round_robin')
            if algo not in ('round_robin', 'least_conn', 'ip_hash', 'hash_uri', 'hash_cookie', 'random_two'):
                return self._json(400, {'ok': False, 'error': 'bad algorithm'})
            backends = []
            for b in (lb.get('backends') or [])[:50]:
                addr = str(b.get('addr', ''))
                if not ADDR_PATTERN.match(addr):
                    return self._json(400, {'ok': False, 'error': 'bad addr: ' + addr})
                backends.append({
                    'addr': addr,
                    'weight': max(1, min(100, int(b.get('weight', 1) or 1))),
                    'enabled': bool(b.get('enabled', True)),
                    'role': 'backup' if b.get('role') == 'backup' else 'primary',
                    'max_conns': max(0, min(100000, int(b.get('max_conns', 0) or 0))),
                })
            h = lb.get('health') or {}
            new_health = {
                'enabled': bool(h.get('enabled', True)),
                'interval': max(5, min(300, int(h.get('interval', 15) or 15))),
                'timeout': max(1, min(30, int(h.get('timeout', 3) or 3))),
                'path': str(h.get('path', '/') or '/')[:200],
                'failures': max(1, min(20, int(h.get('failures', 3) or 3))),
                'notify': bool(h.get('notify', True)),
            }
            o = lb.get('options') or {}
            new_options = {
                'keepalive': max(0, min(1024, int(o.get('keepalive', 32) or 0))),
                'connect_timeout': max(1, min(600, int(o.get('connect_timeout', 5) or 5))),
                'read_timeout': max(1, min(3600, int(o.get('read_timeout', 300) or 300))),
                'send_timeout': max(1, min(3600, int(o.get('send_timeout', 60) or 60))),
                'tries': max(1, min(10, int(o.get('tries', 3) or 3))),
                'retry_5xx': bool(o.get('retry_5xx', True)),
                'passive_max_fails': max(0, min(100, int(o.get('passive_max_fails', 3) or 3))),
                'passive_fail_timeout': max(1, min(3600, int(o.get('passive_fail_timeout', 10) or 10))),
            }
            with LOCK:
                old_lb = STATE['lb']
                STATE['lb'] = {'algorithm': algo, 'backends': backends,
                               'health': new_health, 'options': new_options}
                ok, out = lb_apply()
                if not ok:
                    STATE['lb'] = old_lb
                    lb_apply()
                    return self._json(400, {'ok': False, 'error': out})
                save_state(STATE)
            return self._json(200, {'ok': True, 'nginx': out})
        if u.path == '/api/notify':
            src = body.get('notify') or {}
            with LOCK:
                for ch in ('telegram', 'discord'):
                    if isinstance(src.get(ch), dict):
                        cur = STATE['notify'][ch]
                        for k in ('enabled', 'bot_token', 'chat_id', 'webhook', 'min_risk'):
                            if k in src[ch]:
                                cur[k] = src[ch][k]
                        cur['enabled'] = bool(cur.get('enabled'))
                        cur['min_risk'] = max(0, min(10, int(cur.get('min_risk', 0) or 0)))
                        if ch == 'telegram' and (not cur.get('bot_token') or not cur.get('chat_id')):
                            cur['enabled'] = False
                        if ch == 'discord' and not cur.get('webhook'):
                            cur['enabled'] = False
                        if (ch == 'telegram' and int(cur.get('last_id', 0)) == 0):
                            try:
                                with db() as conn, conn.cursor() as c:
                                    c.execute('SELECT COALESCE(MAX(id), 0) FROM mgt_detect_log_basic')
                                    cur['last_id'] = c.fetchone()[0]
                            except Exception:
                                pass
                save_state(STATE)
            return self._json(200, {'ok': True, 'notify': STATE['notify']})
        if u.path == '/api/telegram':
            tg = body.get('telegram') or {}
            return self.do_POST_notify_legacy(tg)
        if u.path == '/api/notify/test':
            ch = str(body.get('channel') or 'all')
            res = notify_send('SLExt: тестовое уведомление SafeLine работает.', kind=ch)
            ok = any(res.values()) if res else False
            return self._json(200 if ok else 400, {'ok': ok, 'results': res})
        if u.path == '/api/telegram/test':
            res = notify_send('SLExt: тестовое уведомление SafeLine работает.', kind='telegram')
            ok = bool(res.get('telegram'))
            return self._json(200 if ok else 400, {'ok': ok, 'results': res})
        if u.path == '/api/geo':
            geo = body.get('geo') or {}
            mode = geo.get('mode', 'block')
            if mode not in ('block', 'allow'):
                mode = 'block'
            cc = []
            for c in (geo.get('countries') or [])[:250]:
                c = str(c).upper()
                if re.match(r'^[A-Z]{2}$', c) and c not in cc:
                    cc.append(c)
            with LOCK:
                STATE['geo'] = {**STATE['geo'], 'enabled': bool(geo.get('enabled')),
                                'mode': mode, 'countries': cc, 'last_error': ''}
                save_state(STATE)
            ok, info = geo_apply()
            return self._json(200 if ok else 400, {'ok': ok, 'geo': STATE['geo'], 'apply': info})
        if u.path == '/api/geo/sync':
            cc = body.get('countries')
            with LOCK:
                if not cc:
                    cc = STATE['geo'].get('countries') or []
            fetched, failed = {}, {}
            for c in cc[:250]:
                ok, info = geo_fetch(c)
                if ok:
                    fetched[str(c).upper()] = info
                else:
                    failed[str(c).upper()] = info
            ok, info = geo_apply()
            return self._json(200 if ok else 400,
                              {'ok': ok, 'fetched': fetched, 'failed': failed, 'apply': info})
        if u.path == '/api/page':
            page = body.get('page') or {}
            if body.get('preview'):
                with LOCK:
                    merged = json.loads(json.dumps(STATE['page']))
                if 'brand' in page:
                    merged['brand'] = str(page['brand'])[:60]
                if 'color' in page:
                    merged['color'] = str(page['color'])[:20]
                src_pages = page.get('pages') if isinstance(page.get('pages'), dict) else {}
                for c in PAGE_DEFS:
                    s = src_pages.get(c)
                    if not isinstance(s, dict):
                        continue
                    if 'title' in s:
                        merged['pages'][c]['title'] = str(s['title'])[:600]
                    if 'message' in s:
                        merged['pages'][c]['message'] = str(s['message'])[:600]
                    if 'enabled' in s:
                        merged['pages'][c]['enabled'] = bool(s['enabled'])
                code = str(body.get('code') or '')
                if code in PAGE_DEFS:
                    return self._json(200, {'ok': True, 'html': page_html(code, merged['pages'][code], merged)})
                return self._json(200, {'ok': True, 'htmls': {
                    c: page_html(c, merged['pages'][c], merged) for c in PAGE_DEFS}})
            with LOCK:
                cur = STATE['page']
                if 'enabled' in page:
                    cur['enabled'] = bool(page['enabled'])
                if 'brand' in page:
                    cur['brand'] = str(page['brand'])[:60]
                if 'color' in page:
                    cur['color'] = str(page['color'])[:20]
                src_pages = page.get('pages') if isinstance(page.get('pages'), dict) else {}
                for c in PAGE_DEFS:
                    s = src_pages.get(c)
                    if not isinstance(s, dict):
                        continue
                    if 'enabled' in s:
                        cur['pages'][c]['enabled'] = bool(s['enabled'])
                    for fld in ('title', 'message'):
                        if fld in s:
                            cur['pages'][c][fld] = str(s[fld])[:600]
                save_state(STATE)
            ok, info = page_apply()
            return self._json(200 if ok else 400, {'ok': ok, 'info': info, 'page': STATE['page']})
        if u.path == '/api/alarm':
            alarm = body.get('alarm') or {}
            rules = []
            for r in (alarm.get('rules') or [])[:20]:
                rid = re.sub(r'[^a-z0-9_\-]', '', str(r.get('id') or 'rule'))[:40] or 'rule'
                rules.append({
                    'id': rid,
                    'name': str(r.get('name') or rid)[:80],
                    'metric': r.get('metric') if r.get('metric') in METRICS else 'attacks',
                    'threshold': clamp_int(r.get('threshold'), 1, 10 ** 9, 20),
                    'window': clamp_int(r.get('window'), 1, 1440, 5),
                    'cooldown': clamp_int(r.get('cooldown'), 1, 1440, 30),
                    'enabled': bool(r.get('enabled', True)),
                    'last_fired': int(r.get('last_fired', 0) or 0),
                })
            with LOCK:
                STATE['alarm'] = {'enabled': bool(alarm.get('enabled')), 'rules': rules}
                save_state(STATE)
            return self._json(200, {'ok': True, 'alarm': STATE['alarm']})
        if u.path == '/api/syslog':
            sl = body.get('syslog') or {}
            host = str(sl.get('host', '') or '')[:200]
            if host and not re.match(r'^[A-Za-z0-9_.\-:]+$', host):
                return self._json(400, {'ok': False, 'error': 'bad host'})
            with LOCK:
                STATE['syslog'] = {
                    'enabled': bool(sl.get('enabled')),
                    'host': host,
                    'port': clamp_int(sl.get('port'), 1, 65535, 514),
                    'proto': 'tcp' if sl.get('proto') == 'tcp' else 'udp',
                    'last_error': STATE['syslog'].get('last_error', ''),
                }
                save_state(STATE)
            return self._json(200, {'ok': True, 'syslog': STATE['syslog']})
        if u.path == '/api/syslog/test':
            ok = syslog_send({'event': 'test', 'text': 'SLExt syslog test'})
            return self._json(200 if ok else 400, {'ok': ok})
        if u.path == '/api/backup':
            cfg = body.get('backup') or {}
            with LOCK:
                cur = STATE['backup']
                if 'enabled' in cfg:
                    cur['enabled'] = bool(cfg['enabled'])
                if 'hour' in cfg:
                    cur['hour'] = clamp_int(cfg['hour'], 0, 23, 4)
                if 'keep_days' in cfg:
                    cur['keep_days'] = clamp_int(cfg['keep_days'], 1, 365, 7)
                save_state(STATE)
            return self._json(200, {'ok': True, 'backup': STATE['backup']})
        if u.path == '/api/backup/run':
            ok, info = do_backup()
            return self._json(200 if ok else 400, {'ok': ok, 'info': info})
        if u.path == '/api/skip':
            sk = body.get('skip') if isinstance(body.get('skip'), dict) else body
            enabled = bool(sk.get('enabled'))
            ok, info = skip_apply(enabled)
            if ok:
                with LOCK:
                    STATE.setdefault('skip', {})['enabled'] = enabled
                    save_state(STATE)
            return self._json(200 if ok else 400, {'ok': ok, 'info': info, 'skip': STATE.get('skip')})
        if u.path == '/api/waiting/config':
            host = str(body.get('site') or '')[:200]
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            site = site_by_host(host)
            if not site:
                return self._json(400, {'ok': False, 'error': 'site not found'})
            enabled = bool(body.get('enabled'))
            res = wr_apply(host, site['id'], enabled, 'manual', token=self._token())
            mgt = res.get('mgt') or mgt_conf_cached(site['id'], ttl=0)
            payload = {'ok': bool(res.get('ok')), 'error': res.get('error') or '',
                       'mgt': mgt, 'mgt_ok': bool(mgt), 'cfg': waiting_cfg(host),
                       'changed': bool(res.get('changed'))}
            return self._json(200 if res.get('ok') else 400, payload)
        if u.path == '/api/waiting/queue':
            host = str(body.get('site') or '')[:200]
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            site = site_by_host(host)
            if not site:
                return self._json(400, {'ok': False, 'error': 'site not found'})
            if body.get('reset'):
                queue_reset_state(host)
            q = queue_apply(host,
                            enabled=bool(body.get('enabled')) if 'enabled' in body else None,
                            max_concurrent=body.get('max_concurrent'),
                            ttl=body.get('ttl'),
                            max_waiting=body.get('max_waiting'))
            if 'enabled' in body:
                ts = int(time.time())
                _wr_state_patch(host, {'enabled': bool(body.get('enabled')), 'source': 'manual',
                                       'changed_at': ts, 'manual_at': ts, 'error': '', 'error_at': 0})
            queue_write_page()
            return self._json(200, {'ok': True, 'queue': q, 'stats': queue_stats(host)})
        if u.path == '/api/waiting/reset':
            host = str(body.get('site') or '')[:200]
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            # сброс очереди SafeLine (модуль) — редко нужен; наш зал сбрасывается через /api/waiting/queue
            run(['docker', 'restart', 'safeline-tengine'], timeout=120)
            time.sleep(7)
            mgt_conf_forget(1)
            return self._json(200, {'ok': True, 'info': 'модуль зала SafeLine перезапущен', 'mgt': waiting_conf(1)})
        if u.path == '/api/waiting/page':
            host = str(body.get('site') or '')[:200]
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            page = body.get('page') or {}
            if body.get('preview'):
                merged = {**waiting_cfg(host)['page']}
                for k in ('title', 'message', 'note', 'firstpos', 'posttext', 'brand', 'color'):
                    if k in page:
                        merged[k] = str(page[k])[:600]
                if 'show_stats' in page:
                    merged['show_stats'] = bool(page['show_stats'])
                with LOCK:
                    panel_base = str((STATE.get('waiting') or {}).get('panel_base') or '')
                return self._json(200, {'ok': True, 'html': waiting_page_html(host, {'page': merged}, panel_base)})
            with LOCK:
                sites = STATE.setdefault('waiting', {}).setdefault('sites', {})
                cfg = sites.setdefault(host, {})
                p = cfg.setdefault('page', {})
                for k in ('title', 'message', 'note', 'firstpos', 'posttext', 'brand', 'color'):
                    if k in page:
                        p[k] = str(page[k])[:600]
                if 'show_stats' in page:
                    p['show_stats'] = bool(page['show_stats'])
                save_state(STATE)
            ok, info = page_apply()
            return self._json(200 if ok else 400, {'ok': ok, 'info': info, 'cfg': waiting_cfg(host)})
        if u.path == '/api/waiting/extras':
            host = str(body.get('site') or '')[:200]
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            with LOCK:
                sites = STATE.setdefault('waiting', {}).setdefault('sites', {})
                cfg = sites.setdefault(host, {})
                sch = body.get('schedule') or {}
                if sch:
                    s = cfg.setdefault('schedule', {})
                    if 'enabled' in sch:
                        s['enabled'] = bool(sch['enabled'])
                    days = []
                    for d in (sch.get('days') or [])[:7]:
                        try:
                            d = int(d)
                            if 1 <= d <= 7 and d not in days:
                                days.append(d)
                        except (TypeError, ValueError):
                            pass
                    s['days'] = days or [1, 2, 3, 4, 5, 6, 7]
                    for k in ('from', 'to'):
                        if k in sch:
                            v = str(sch[k])[:5]
                            if not re.match(r'^\d{1,2}:\d{2}$', v):
                                v = '00:00'
                            s[k] = v
                au = body.get('auto') or {}
                if au:
                    a = cfg.setdefault('auto', {})
                    if 'enabled' in au:
                        a['enabled'] = bool(au['enabled'])
                    for k, lo, hi, df in (('threshold', 1, 10 ** 6, 60), ('off_threshold', 0, 10 ** 6, 20),
                                          ('window', 30, 3600, 60), ('hold', 1, 20, 3),
                                          ('hold_off', 1, 60, 4), ('cooldown', 30, 86400, 600),
                                          ('min_off', 0, 86400, 600)):
                        if k in au:
                            a[k] = clamp_int(au[k], lo, hi, df)
                    if int(a.get('off_threshold') or 0) > int(a.get('threshold') or 60):
                        a['off_threshold'] = int(a.get('threshold') or 60)
                nf = body.get('notify') or {}
                if nf:
                    n = cfg.setdefault('notify', {})
                    if 'enabled' in nf:
                        n['enabled'] = bool(nf['enabled'])
                if 'panel_base' in body:
                    STATE['waiting']['panel_base'] = str(body['panel_base'])[:200]
                save_state(STATE)
            lim = body.get('limits') or {}
            lim_ok, lim_err = True, ''
            if lim:
                _site = site_by_host(host)
                lim_ok, lim_err = wr_limits_set(host, _site['id'] if _site else 0,
                                                lim.get('max_concurrent'),
                                                lim.get('session_timeout'),
                                                lim.get('max_waiting'))
            page_apply()
            if not lim_ok:
                return self._json(400, {'ok': False, 'error': 'лимиты: ' + (lim_err or ''),
                                        'cfg': waiting_cfg(host)})
            return self._json(200, {'ok': True, 'cfg': waiting_cfg(host),
                                    'mgt': waiting_conf(1)})
        if u.path == '/api/dns/check':
            host = str(body.get('host') or '')[:200]
            hosts = [host] if host else []
            if not hosts:
                for s in site_list():
                    hosts.extend(s.get('hosts') or [])
            results = []
            for h in dict.fromkeys(hosts):
                if not h:
                    continue
                res = dns_check_host(h, full=True)
                with LOCK:
                    st = STATE.setdefault('dns', {}).setdefault('hosts', {})
                    cur = st.setdefault(h, {})
                    cur['last'] = res
                    cur['records_at'] = res['at']
                    samp = cur.setdefault('samples', [])
                    samp.append({'ts': res['at'], 'ms': res.get('ms'), 'ok': bool(res.get('ok'))})
                    del samp[576:]
                    save_state(STATE)
                results.append(res)
            return self._json(200, {'ok': True, 'results': results})
        if u.path == '/api/loadtest/start':
            mode = 'waf' if body.get('mode') == 'waf' else 'origin'
            auto_pause = bool(body.get('auto_pause')) and mode == 'waf'
            if mode == 'waf' and not auto_pause and not body.get('ack'):
                return self._json(400, {'ok': False,
                                        'error': 'для теста через WAF подтвердите отключение защиты или включите авто-паузу'})
            host = str(body.get('host') or '')[:200]
            site = site_by_host(host)
            if not site:
                return self._json(400, {'ok': False, 'error': 'домен не найден в SafeLine'})
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            path = str(body.get('path') or '/')[:200]
            if not path.startswith('/'):
                path = '/' + path
            if '..' in path:
                return self._json(400, {'ok': False, 'error': 'некорректный путь'})
            params = {'host': host, 'path': path, 'mode': mode, 'auto_pause': auto_pause,
                      'max_conc': clamp_int(body.get('max_conc'), 1, 128, 48),
                      'stage_sec': clamp_int(body.get('stage_sec'), 3, 30, 6),
                      'p95_ms': clamp_int(body.get('p95_ms'), 200, 10000, 1500),
                      'max_total_sec': clamp_int(body.get('max_total_sec'), 30, 600, 240)}
            try:
                params['err_pct'] = max(0.5, min(50.0, float(body.get('err_pct') or 3.0)))
            except (TypeError, ValueError):
                params['err_pct'] = 3.0
            with LOCK:
                cur = STATE.get('loadtest') or {}
                if cur.get('status') == 'running' and time.time() - int(cur.get('updated_at') or 0) < 120:
                    return self._json(409, {'ok': False, 'error': 'тест уже выполняется'})
                arch = cur.get('archive') or []
                jid = str(int(time.time()))
                STATE['loadtest'] = {'id': jid, 'status': 'running', 'params': params,
                                     'started_at': int(time.time()), 'updated_at': int(time.time()),
                                     'stages': [], 'progress': {}, 'archive': arch}
                save_state(STATE)
            ev = threading.Event()
            LT_JOBS[jid] = ev
            threading.Thread(target=loadtest_run, args=(jid, ev), daemon=True).start()
            return self._json(200, {'ok': True, 'id': jid, 'params': params})
        if u.path == '/api/loadtest/stop':
            with LOCK:
                cur = STATE.get('loadtest') or {}
            ev = LT_JOBS.get(cur.get('id'))
            if ev:
                ev.set()
            return self._json(200, {'ok': True})
        if u.path == '/api/loadtest/archive/delete':
            jid = str(body.get('id') or '')[:40]
            with LOCK:
                lt = STATE.setdefault('loadtest', {})
                arch = lt.get('archive') or []
                lt['archive'] = [a for a in arch if str(a.get('id')) != jid]
                save_state(STATE)
            return self._json(200, {'ok': True})
        if u.path == '/api/loadtest/apply':
            host = str(body.get('host') or '')[:200]
            site = site_by_host(host)
            if not site:
                return self._json(400, {'ok': False, 'error': 'домен не найден'})
            if not self._host_ok(host):
                return self._json(403, {'ok': False, 'error': 'нет доступа к домену ' + host})
            with LOCK:
                rep = ((STATE.get('loadtest') or {}).get('report') or {})
            rec = rep.get('recommend') or {}
            if not rec:
                return self._json(400, {'ok': False, 'error': 'нет отчёта — сначала выполните тест'})
            with LOCK:
                cfg = STATE.setdefault('waiting', {}).setdefault('sites', {}).setdefault(host, {})
                a = cfg.setdefault('auto', {})
                a.update({'threshold': int(rec.get('threshold') or 60),
                          'off_threshold': int(rec.get('off_threshold') or 20),
                          'window': 60, 'hold': int(rec.get('hold') or 3),
                          'hold_off': int(rec.get('hold_off') or 4),
                          'cooldown': int(rec.get('cooldown') or 600),
                          'min_off': int(rec.get('min_off') or 600)})
                lim = cfg.setdefault('limits', {})
                lim['max_concurrent'] = max(100, int(rec.get('max_concurrent') or 100))
                save_state(STATE)
            ok2, err2 = wr_limits_sql(site['id'], {'max_concurrent': lim['max_concurrent']})
            if not ok2:
                return self._json(400, {'ok': False, 'error': err2 or 'не удалось применить лимит'})
            return self._json(200, {'ok': True, 'mgt_applied': True,
                                    'cfg': waiting_cfg(host), 'mgt': waiting_conf(site['id'])})
        if u.path == '/api/crowdsec/ban':
            ok, info = crowdsec_ban(body.get('ip'), body.get('duration'), body.get('reason'))
            return self._json(200 if ok else 400, {'ok': ok, 'info': info})
        if u.path == '/api/crowdsec/unban':
            ok, info = crowdsec_unban(body.get('ip'))
            return self._json(200 if ok else 400, {'ok': ok, 'info': info})
        return self._json(404, {'ok': False, 'error': 'not found'})

    def do_POST_notify_legacy(self, tg):
        with LOCK:
            cur = STATE['notify']['telegram']
            for k in ('enabled', 'bot_token', 'chat_id', 'min_risk'):
                if k in tg:
                    cur[k] = tg[k]
            cur['enabled'] = bool(cur.get('enabled'))
            cur['min_risk'] = int(cur.get('min_risk', 0) or 0)
            if not cur.get('bot_token') or not cur.get('chat_id'):
                cur['enabled'] = False
            if int(cur.get('last_id', 0)) == 0:
                try:
                    with db() as conn, conn.cursor() as c:
                        c.execute('SELECT COALESCE(MAX(id), 0) FROM mgt_detect_log_basic')
                        cur['last_id'] = c.fetchone()[0]
                except Exception:
                    pass
            save_state(STATE)
        return self._json(200, {'ok': True, 'telegram': STATE['notify']['telegram']})


SKIP_CONF = '/data/safeline/resources/nginx/conf.d/zz_slext_skip.conf'


def skip_apply(enabled):
    body = ('# slext skip decryption (pass = safeline key cookie; managed by SLExt)\n'
            'map $http_cookie $slext_skip {\n'
            '    default 0;\n')
    if enabled:
        body += ('    "~*safeline-[0-9a-f]{32,}-key=" 1;\n'
                 '    "~*nrgpass=1" 1;\n')
    body += '}\n'
    try:
        with open(SKIP_CONF, 'w') as f:
            f.write(body)
    except Exception as e:
        return False, str(e)[:200]
    rc, out, err = run(['docker', 'exec', 'safeline-tengine', 'nginx', '-t'], timeout=30)
    if rc != 0:
        return False, (err or out)[-200:]
    run(['docker', 'exec', 'safeline-tengine', 'nginx', '-s', 'reload'], timeout=30)
    return True, 'ok'


class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def handle_error(self, request, client_address):
        import sys as _sys
        et = _sys.exc_info()[0]
        if et in (BrokenPipeError, ConnectionResetError):
            return
        super().handle_error(request, client_address)


def main():
    try:
        with LOCK:
            skip_apply(bool((STATE.get('skip') or {}).get('enabled', True)))
    except Exception:
        pass
    threading.Thread(target=notify_worker, daemon=True).start()
    threading.Thread(target=lb_worker, daemon=True).start()
    threading.Thread(target=alarm_worker, daemon=True).start()
    threading.Thread(target=backup_worker, daemon=True).start()
    threading.Thread(target=waiting_worker, daemon=True).start()
    threading.Thread(target=wr_startup, daemon=True).start()
    threading.Thread(target=dns_worker, daemon=True).start()

    # Слушаем 127.0.0.1 и приватные адреса docker-мостов, чтобы панель (контейнер)
    # могла достать API через /extapi. Публичные адреса не занимаем.
    addrs = ['127.0.0.1']
    try:
        _rc, out, _err = run(['hostname', '-I'], timeout=5)
        for a in (out or '').split():
            a = a.strip()
            if not a:
                continue
            try:
                ip = ipaddress.ip_address(a)
            except ValueError:
                continue
            if ip.version == 4 and ip.is_private and a not in addrs:
                addrs.append(a)
    except Exception:
        pass

    servers = []
    for a in addrs:
        try:
            servers.append((a, S((a, 8787), H)))
        except OSError:
            pass
    if not servers:
        servers = [('127.0.0.1', S(('127.0.0.1', 8787), H))]
    print('[slext] api %s on %s' % (VERSION, ', '.join(a for a, _ in servers)), flush=True)
    for _a, srv in servers[:-1]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[-1][1].serve_forever()


if __name__ == '__main__':
    main()
