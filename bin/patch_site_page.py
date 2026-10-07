#!/usr/bin/env python3
import json
import os
import re
import sys

from wr_policy import api_zone_name, clamp_int

PAGES_DIR = '/etc/nginx/slext-pages'
HOST_PAGES_DIR = '/data/safeline/resources/nginx/slext-pages'
PAGES = [
    ('forbidden.html', '/.safeline/forbidden_page'),
    ('acl.html', '/.safeline/acl_page'),
    ('bad_gateway.html', '/.safeline/bad_gateway_page'),
    ('gateway_timeout.html', '/.safeline/gateway_timeout_page'),
    ('not_found.html', '/.safeline/not_found_page'),
    ('waiting_room.html', '/.safeline/waiting_room_page'),
    ('offline.html', '/.safeline/offline_page'),
]
PROXY = 'proxy_pass http://unix:/app/sock/tcd_error.sock;'

NF_MARK = '# slext-nf-flow'
NF_ERR = 'error_page 404 =404 /.safeline/not_found_page;'
NF_REWRITE = 'rewrite ^ /.safeline/not_found_page last;'
NF_RETURN = 'return 404;'
NF_IF = re.compile(r'(if\s*\(\$should_rewrite\)\s*\{\s*)(rewrite \^ /\.safeline/not_found_page last;|return 404;)(\s*\})')

INT_MARK = '# slext-page-intercept'
INT_LINE = 'proxy_intercept_errors on; ' + INT_MARK
BACKEND_RE = re.compile(r'(^[ \t]*proxy_pass\s+https?://backend_\d+;\n)', re.M)

ENC_MARK = '# slext-enc-pipeline'
ENC_LINE = 'proxy_set_header Accept-Encoding ""; ' + ENC_MARK
HOST_RE = re.compile(r'(^[ \t]*proxy_set_header Host \$http_host;\n)', re.M)

NF404_MARK = '# slext-nf404'
NF404_LINE = 'error_page 404 =404 $slext_nf_page; ' + NF404_MARK
NF404_OFF = ('    location = /.safeline/not_found_off {\n'
             '        internal;\n'
             '        return 404; # slext-nf404-off\n'
             '    }\n')
ENC_RE = re.compile(r'^([ \t]*)proxy_set_header Accept-Encoding ""; # slext-enc-pipeline\n', re.M)

CH_MARK = '# slext-challenge-css'
CH_LOC = ('    location = /.safeline/challenge/v2/challenge.css {\n'
          '        alias /etc/nginx/slext-pages/challenge.css; ' + CH_MARK + '\n'
          '        default_type text/css;\n'
          '        charset utf-8;\n'
          '        add_header Cache-Control "no-cache";\n'
          '        t1k_intercept off;\n'
          '        tx_intercept off;\n'
          '    }\n')

SKIP_MARK = '# slext-skip'
SKIP_IF_TPL = 'if ($slext_skip) { rewrite ^ /@slext-plain last; } ' + SKIP_MARK + '-if'
CUSTOM_PARAMS_DIR = '/data/safeline/resources/nginx/custom_params'


def site_backend(text):
    """Свой backend сайта: (scheme, N) из канонического proxy_pass."""
    m = re.search(r'proxy_pass\s+(https?)://backend_(\d+);', text)
    if m:
        return m.group(1), int(m.group(2))
    return '', 0


def skip_loc(scheme, n):
    custom = ''
    if scheme and n and os.path.exists('%s/backend_%d' % (CUSTOM_PARAMS_DIR, n)):
        custom = '        include /etc/nginx/custom_params/backend_%d;\n' % n
    return ('    location = /@slext-plain {\n'
            '        internal;\n'
            '        tx_chaos_intercept off; ' + SKIP_MARK + '-plain\n'
            '        proxy_pass %s://backend_%d$request_uri;\n'
            '        include proxy_params;\n'
            '        proxy_set_header Host $http_host;\n'
            '        proxy_set_header Accept-Encoding ""; # slext-enc-pipeline\n'
            '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            '%s'
            '        t1k_add_user_data "%d";\n'
            '        tx_add_user_data "%d";\n'
            '        t1k_body_size 1024k;\n'
            '        tx_body_size 4k;\n'
            '        t1k_error_page 403 /.safeline/forbidden_page;\n'
            '        t1k_error_page 429 /.safeline/acl_page;\n'
            '        t1k_error_page 466 /.safeline/offline_page;\n'
            '        tx_error_page 403 /.safeline/forbidden_page;\n'
            '        t1k_error_page 465 /.safeline/waiting_room_page;\n'
            '    }\n') % (scheme or 'https', n or 1, custom, n or 1, n or 1)


PX_MARK = '# slext-px-access'
PX_FORMAT_MARK = '# slext-px-format'
PX_FORMAT = ("log_format slext_px '$remote_addr|$time_iso8601|$host|$request|$status|$bytes_sent|"
             "$request_length|$request_time|$upstream_response_time|$upstream_connect_time|"
             "$http_user_agent|$http_referer'; " + PX_FORMAT_MARK)
PX_LOG_LINE = 'access_log /var/log/nginx/slext_traffic.log slext_px; ' + PX_MARK


def patch_px_log(text):
    changed = False
    if PX_FORMAT_MARK not in text:
        m = re.search(r"log_format\s+safeline_1\s+'[^;]*;", text, re.S)
        if m:
            text = text[:m.end()] + '\n' + PX_FORMAT + text[m.end():]
            changed = True
    if PX_MARK not in text and 'access_log /var/log/nginx/access.log safeline;' in text:
        text = text.replace('access_log /var/log/nginx/access.log safeline;',
                            'access_log /var/log/nginx/access.log safeline;\n    ' + PX_LOG_LINE)
        changed = True
    return text, changed


QUEUE_GW = os.environ.get('SLEXT_GW', '192.168.0.1')
QUEUE_MARK = '# slext-queue'
QUEUE_LOC = ('    location = /@slext-queue {\n'
             '        alias /etc/nginx/slext-pages/queue.html; ' + QUEUE_MARK + '-loc\n'
             '        default_type text/html;\n'
             '        charset utf-8;\n'
             '        add_header Cache-Control "no-store";\n'
             '        t1k_intercept off;\n'
             '        tx_intercept off;\n'
             '    }\n')
QUEUE_PROXY = ('    location ^~ /.safeline/slext/ {\n'
               '        ' + QUEUE_MARK + '-proxy\n'
               '        proxy_pass http://%s:8787/api/queue/;\n'
               '        proxy_set_header Host $host;\n'
               '        proxy_set_header X-Slext-Host $host;\n'
               '        proxy_set_header X-Real-IP $remote_addr;\n'
               '        proxy_read_timeout 10;\n'
               '        t1k_intercept off;\n'
               '        tx_intercept off;\n'
               '        add_header Cache-Control "no-store";\n'
               '    }\n') % QUEUE_GW
QUEUE_GO_IF = ('if ($slext_queue_go) { return 302 /.safeline/slext/go?to=$request_uri; } '
               + QUEUE_MARK + '-go')


def queue_enabled_hosts():
    try:
        st = json.load(open('/opt/slext/conf/state.json', encoding='utf-8'))
        return set((st.get('waiting', {}).get('sites', {}) or {}).keys()) and {
            h for h, c in (st.get('waiting', {}).get('sites', {}) or {}).items()
            if (c or {}).get('queue', {}).get('enabled')}
    except Exception:
        return set()


def api_route_cfg(host):
    try:
        st = json.load(open('/opt/slext/conf/state.json', encoding='utf-8'))
        return ((st.get('api_routes', {}) or {}).get('sites', {}) or {}).get(host) or {}
    except Exception:
        return {}


WL_MARK = '# slext-api-wl'
RL_MARK = '# slext-api-rl'
WL_IF = 'if ($slext_api_wl) { rewrite ^ /@slext-plain last; } ' + WL_MARK


def patch_api_routes(text, cfg, host):
    """Whitelist путей (обход челленджа) + rate-limit на @slext-plain.

    Управляется состоянием state.json (api_routes). Идемпотентно: старые строки
    по маркерам снимаются, затем при включённой конфигурации вставляются заново.
    """
    changed = False
    orig = text
    for mark in (WL_MARK, RL_MARK):
        if mark in text:
            text = '\n'.join(ln for ln in text.split('\n') if mark not in ln)
            changed = True
    if not (cfg and cfg.get('enabled') and cfg.get('paths')):
        return text, changed and text != orig
    m = re.search(r'^([ \t]*)if \(\$slext_skip\) \{ rewrite \^ /@slext-plain last; \} # slext-skip-if$',
                  text, re.M)
    if m:
        text = text[:m.end()] + '\n' + m.group(1) + WL_IF + text[m.end():]
        changed = True
    mp = re.search(r'(location = /@slext-plain \{\n)([ \t]*)', text)
    if mp:
        burst = clamp_int(cfg.get('burst'), 0, 1000, 40)
        line = ('%slimit_req zone=%s burst=%d nodelay; %s\n' %
                (mp.group(2), api_zone_name(host), burst, RL_MARK))
        text = text[:mp.end(2)] + line + text[mp.end(2):]
        changed = True
    return text, changed and text != orig


def patch_queue(text, enabled=False):
    """Наш зал: постоянные локации + rewrite-гейт (управляется map-файлом, без правки при тумблере)."""
    changed = False
    orig = text
    if '# # slext-queue' in text:
        text = text.replace('# # slext-queue', '# slext-queue')
        changed = True
    if QUEUE_MARK + '-loc' not in text:
        for anchor in ('    location = /@slext-gate {', '    location = /@slext-plain {',
                       '    location = /.safeline/not_found_page {'):
            if anchor in text:
                text = text.replace(anchor, QUEUE_LOC + anchor, 1)
                changed = True
                break
    if QUEUE_MARK + '-proxy' not in text:
        if QUEUE_LOC in text:
            text = text.replace(QUEUE_LOC, QUEUE_LOC + QUEUE_PROXY, 1)
            changed = True
        elif '    location ^~ /.safeline/challenge/v2/ {' in text:
            anchor = '    location ^~ /.safeline/challenge/v2/ {'
            text = text.replace(anchor, QUEUE_PROXY + anchor, 1)
            changed = True
    # сносим прошлые схемы гейта: map-if и auth_request
    for rx in (r'^[ \t]*if \(\$slext_queue_gate\)[^\n]*\n',
               r'^[ \t]*location = /_slext_admit \{.*?\n    \}\n'):
        text, n = re.subn(rx, '', text, flags=re.M | re.S)
        changed = changed or bool(n)
    keep = []
    for ln in text.split('\n'):
        if (QUEUE_MARK + '-admit-on') in ln or (QUEUE_MARK + '-ck') in ln \
                or (QUEUE_MARK + '-403') in ln or (QUEUE_MARK + '-ckh') in ln \
                or (QUEUE_MARK + '-go') in ln:
            changed = True
            continue
        keep.append(ln)
    text = '\n'.join(keep)
    # постоянный rewrite-гейт: основной локал и @slext-plain (путь с nrgpass)
    for pat in (r'^([ \t]*)proxy_pass\s+https?://backend_\d+\$request_uri;\n',
                r'^([ \t]*)proxy_pass\s+https?://backend_\d+;\n'):
        m = re.search(pat, text, re.M)
        if m:
            text = text[:m.start()] + m.group(1) + QUEUE_GO_IF + '\n' + text[m.start():]
            changed = True
    return text, changed and (text != orig)


GATE_MARK = '# slext-gate'
GATE_IF = 'if ($slext_gate) { rewrite ^ /@slext-gate last; } ' + GATE_MARK + '-if'
GATE_LOC = ('    location = /@slext-gate {\n'
            '        internal;\n'
            '        alias /etc/nginx/slext-pages/gate.html; ' + GATE_MARK + '-loc\n'
            '        default_type text/html;\n'
            '        charset utf-8;\n'
            '        add_header Cache-Control "no-store";\n'
            '        t1k_intercept off;\n'
            '        tx_intercept off;\n'
            '    }\n')


def patch_gate(text):
    changed = False
    if GATE_MARK + '-loc' not in text:
        marker = '    location = /@slext-plain {\n'
        if marker in text:
            text = text.replace(marker, GATE_LOC + marker, 1)
            changed = True
    if GATE_MARK + '-if' not in text:
        m = re.search(r'^([ \t]*)if \(\$slext_skip\) \{ rewrite \^ /@slext-plain last; \}', text, re.M)
        if m:
            text = text[:m.start()] + m.group(1) + GATE_IF + '\n' + text[m.start():]
            changed = True
    return text, changed


def patch_skip(text):
    changed = False
    scheme, n = site_backend(text)
    if 'slext-skip-ck' in text:
        text = '\n'.join(ln for ln in text.split('\n') if 'slext-skip-ck' not in ln)
        changed = True
    if 'location = /@slext-plain {' not in text:
        m = re.search(r'^    location = /.safeline/not_found_page \{\n', text, re.M)
        if m and scheme:
            text = text[:m.start()] + skip_loc(scheme, n) + text[m.start():]
            changed = True
    else:
        # миграция: чиним уже вставленный блок, если он указывает на чужой backend
        mm = re.search(r'location = /@slext-plain \{.*?\n    \}\n', text, re.S)
        if mm and scheme and n:
            block = mm.group(0)
            fixed = re.sub(r'proxy_pass\s+https?://backend_\d+\$request_uri;',
                           'proxy_pass %s://backend_%d$request_uri;' % (scheme, n), block)
            fixed = re.sub(r'^[ \t]*include /etc/nginx/custom_params/backend_\d+;[ \t]*\n',
                           ('        include /etc/nginx/custom_params/backend_%d;\n' % n
                            if os.path.exists('%s/backend_%d' % (CUSTOM_PARAMS_DIR, n)) else ''),
                           fixed, flags=re.M)
            fixed = re.sub(r't1k_add_user_data "\d+";', 't1k_add_user_data "%d";' % n, fixed)
            fixed = re.sub(r'tx_add_user_data "\d+";', 'tx_add_user_data "%d";' % n, fixed)
            if fixed != block:
                text = text[:mm.start()] + fixed + text[mm.end():]
                changed = True
    if 'if ($slext_skip)' not in text:
        m = re.search(r'^([ \t]*)proxy_pass\s+https?://backend_\d+;\n', text, re.M)
        if m:
            text = text[:m.start()] + m.group(1) + SKIP_IF_TPL + '\n' + text[m.start():]
            changed = True
    if 'slext-skip-cc' not in text:
        key = SKIP_IF_TPL + '\n'
        i = text.find(key)
        if i >= 0:
            text = text[:i + len(key)] + '        add_header Cache-Control $slext_cc always; # slext-skip-cc\n' + text[i + len(key):]
            changed = True
    return text, changed


def patch_challenge_css(text):
    changed = False
    if CH_MARK not in text:
        marker = '    location ^~ /.safeline/challenge/v2/ {\n'
        if marker in text:
            text = text.replace(marker, CH_LOC + marker, 1)
            changed = True
    return text, changed


DYN_MARK = '# slext-dynamic-css'
DYN_LOC = ('    location = /.safeline/static/dynamic.css {\n'
           '        alias /etc/nginx/safeline-static/dynamic.css; ' + DYN_MARK + '\n'
           '        default_type text/css;\n'
           '        charset utf-8;\n'
           '        add_header Cache-Control "no-cache";\n'
           '        t1k_intercept off;\n'
           '        tx_intercept off;\n'
           '    }\n')


def patch_dynamic_css(text):
    changed = False
    if DYN_MARK not in text:
        marker = '    location ^~ /.safeline/static/ {\n'
        if marker in text:
            text = text.replace(marker, DYN_LOC + marker, 1)
            changed = True
    return text, changed


def patch_nf404(text):
    changed = False
    if NF404_MARK not in text:
        m = ENC_RE.search(text)
        if m:
            indent = m.group(1)
            text = text[:m.end()] + indent + NF404_LINE + '\n' + text[m.end():]
            changed = True
    if 'slext-nf404-off' not in text:
        marker = '    location = /.safeline/not_found_page {\n'
        if marker in text:
            text = text.replace(marker, NF404_OFF + marker, 1)
            changed = True
    return text, changed


def cleanup_nf_flow(text):
    changed = False
    if NF_ERR + ' ' + NF_MARK in text:
        text = text.replace('    %s %s\n' % (NF_ERR, NF_MARK), '')
        changed = True
    new_text, n = NF_IF.subn(lambda m: m.group(1) + NF_REWRITE + m.group(3), text)
    if n and new_text != text:
        text = new_text
        changed = True
    return text, changed


def patch_intercept(text, on):
    changed = False
    if on:
        if INT_MARK not in text:
            m = BACKEND_RE.search(text)
            if m:
                indent = re.match(r'[ \t]*', m.group(1)).group(0)
                text = text[:m.end()] + indent + INT_LINE + '\n' + text[m.end():]
                changed = True
    else:
        if INT_MARK in text:
            text = '\n'.join(ln for ln in text.split('\n') if INT_MARK not in ln)
            changed = True
    return text, changed


def patch_enc_pipeline(text):
    changed = False
    if ENC_MARK not in text:
        m = HOST_RE.search(text)
        if m:
            indent = re.match(r'[ \t]*', m.group(1)).group(0)
            text = text[:m.end()] + indent + ENC_LINE + '\n' + text[m.end():]
            changed = True
    return text, changed


def strip_slext(text):
    """Снять все наши патчи (для служебных сайтов без backend_N)."""
    orig = text
    # вернуть стоковые страницы ошибок
    text = re.sub(r'[ \t]*alias [^;]*; # slext-page\n'
                  r'(?:[ \t]*default_type text/html;\n)?'
                  r'(?:[ \t]*charset utf-8;\n)?',
                  '        ' + PROXY + '\n', text)
    # убрать целиком вставленные локации
    for rx in (r'[ \t]*location = /@slext-plain \{.*?\n    \}\n',
               r'[ \t]*location = /@slext-gate \{.*?\n    \}\n',
               r'[ \t]*location = /@slext-queue \{.*?\n    \}\n',
               r'[ \t]*location = /_slext_admit \{.*?\n    \}\n',
               r'[ \t]*location \^~ /\.safeline/slext/ \{.*?\n    \}\n',
               r'[ \t]*location = /.safeline/challenge/v2/challenge.css \{.*?\n    \}\n',
               r'[ \t]*location = /.safeline/static/dynamic.css \{.*?\n    \}\n',
               r'[ \t]*location = /.safeline/not_found_off \{.*?\n    \}\n'):
        text = re.sub(rx, '', text, flags=re.S)
    # строки с нашими маркерами, гео-инклюд и наш access_log
    keep = []
    for ln in text.split('\n'):
        if '# slext-' in ln:
            continue
        if 'slext-geo/check.conf' in ln:
            continue
        if 'access_log /var/log/nginx/access.log safeline' in ln:
            continue
        keep.append(ln)
    text = '\n'.join(keep)
    return text, text != orig


def _write_text(path, text):
    """Атомарная запись (tmp+rename): параллельные патчи не рвут конфиг."""
    tmp = path + '.slext-tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


def patch(path, files):
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except OSError:
        return False
    # служебные сайты без backend_N (portal/auth и т.п.) — не патчим и чистим наше
    scheme0, n0 = site_backend(text)
    if not scheme0:
        text2, changed2 = strip_slext(text)
        if changed2:
            try:
                _write_text(path, text2)
            except OSError:
                return False
        return changed2
    changed = False
    for fname, loc in PAGES:
        on = fname in files
        alias = 'alias %s/%s; # slext-page' % (PAGES_DIR, fname)
        rx = re.compile(r'(location\s+(?:=\s*|\^~\s+)?' + re.escape(loc) + r'\s*\{)(.*?)(\n[ \t]*\})', re.S)

        def repl(m, on=on, alias=alias):
            body = m.group(2)
            if on:
                if '# slext-page' in body:
                    if 'default_type text/html;' in body:
                        return m.group(0)
                    pm = re.search(r'^([ \t]*)alias [^;]*; # slext-page$', body, re.M)
                    if not pm:
                        return m.group(0)
                    indent = pm.group(1)
                    body = body.replace(pm.group(0),
                                        pm.group(0) + '\n' + indent + 'default_type text/html;\n' +
                                        indent + 'charset utf-8;')
                    repl.changed = True
                    return m.group(1) + body + m.group(3)
                pm = re.search(r'^([ \t]*)' + re.escape(PROXY) + r'$', body, re.M)
                if not pm:
                    return m.group(0)
                indent = pm.group(1)
                new = (indent + 'alias %s/%s; # slext-page\n'
                       '%sdefault_type text/html;\n'
                       '%scharset utf-8;' % (PAGES_DIR, fname, indent, indent))
                body = body.replace(pm.group(0), new)
            else:
                num = r'[ \t]*'
                rx = re.compile(num + r'alias [^;]*; # slext-page\n' +
                                r'(?:' + num + r'default_type text/html;\n)?' +
                                r'(?:' + num + r'charset utf-8;\n)?')
                mm = rx.search(body)
                if not mm:
                    return m.group(0)
                indent = re.match(r'[ \t]*', mm.group(0)).group(0) or '        '
                body = rx.sub(lambda _: indent + PROXY + '\n', body)
            repl.changed = True
            return m.group(1) + body + m.group(3)

        repl.changed = False
        text = rx.sub(repl, text)
        if repl.changed:
            changed = True
    text, ch = cleanup_nf_flow(text)
    changed = changed or ch
    intercept_on = ('bad_gateway.html' in files) or ('gateway_timeout.html' in files)
    text, ch = patch_intercept(text, intercept_on)
    changed = changed or ch
    text, ch = patch_enc_pipeline(text)
    changed = changed or ch
    text, ch = patch_nf404(text)
    changed = changed or ch
    text, ch = patch_challenge_css(text)
    changed = changed or ch
    text, ch = patch_dynamic_css(text)
    changed = changed or ch
    text, ch = patch_skip(text)
    changed = changed or ch
    text, ch = patch_gate(text)
    changed = changed or ch
    qenabled = False
    qhost = ''
    mh = re.search(r'^[ \t]*server_name\s+([^;]+);', text, re.M)
    if mh:
        qhost = mh.group(1).split()[0].strip()
        qenabled = qhost in queue_enabled_hosts()
    text, ch = patch_api_routes(text, api_route_cfg(qhost), qhost)
    changed = changed or ch
    text, ch = patch_queue(text, qenabled)
    changed = changed or ch
    text, ch = patch_px_log(text)
    changed = changed or ch
    if changed:
        _write_text(path, text)
    return changed


def main():
    files = set(os.listdir(HOST_PAGES_DIR)) if os.path.isdir(HOST_PAGES_DIR) else set()
    n = 0
    for path in sys.argv[1:]:
        if patch(path, files):
            n += 1
    print('patched files: %d' % n)
    return 0


if __name__ == '__main__':
    sys.exit(main())
