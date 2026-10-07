#!/usr/bin/env python3
"""Рендер публичных страниц SLExt: шаблоны, шрифты, экранирование. Без БД."""
import importlib.util
import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.modules.setdefault('psycopg2', types.ModuleType('psycopg2'))
sys.path.insert(0, os.path.join(ROOT, 'bin'))
_spec = importlib.util.spec_from_file_location('slext_api', os.path.join(ROOT, 'bin', 'slext-api.py'))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


for code in sorted(m.PAGE_DEFS):
    if code == '465':
        continue  # рендерится wait-шаблоном
    html = m.page_html(code, {'title': m.PAGE_DEFS[code]['title'],
                              'message': m.PAGE_DEFS[code]['message']},
                       {'brand': 'NRG / INDEX'})
    check('$' not in html, 'page %s: незаменённый $' % code)
    check('data:font/woff2;base64,' in html, 'page %s: нет вшитых шрифтов' % code)
    check('<!-- slext-error-page -->' in html, 'page %s: потерян маркер' % code)
    check('HTTP %s' % code in html, 'page %s: нет кода' % code)

check('<meta http-equiv="refresh" content="60">' in m.page_html('466', {}, {}), '466: нет refresh')
check('Обновить страницу' in m.page_html('429', {}, {}), '429: нет кнопки')
check('На главную' in m.page_html('404', {}, {}), '404: нет ссылки на главную')
check('Обновить страницу' not in m.page_html('403', {}, {}), '403: лишняя кнопка')
esc = m.page_html('403', {'title': '<b>x</b>', 'message': 'a & b'}, {'brand': 'NRG / INDEX'})
check('&lt;b&gt;x&lt;/b&gt;' in esc and 'a &amp; b' in esc, 'экранирование title/message')
check('<span class="slash">/</span>' in esc, 'бренд-марка без слэша')
check('#ff0000' not in m.page_html('403', {}, {'brand': 'X', 'color': '#ff0000'}),
      'цвет панели всё ещё влияет')

waiting = m.waiting_page_html('demo.example.com', m.waiting_cfg('demo.example.com'), '')
check('$' not in waiting, 'waiting: незаменённый $')
check('data:font/woff2;base64,' in waiting, 'waiting: нет вшитых шрифтов')
check('<!-- slext-waiting-page -->' in waiting, 'waiting: потерян маркер')
for el in ('sl-pos', 'sl-total', 'sl-msg', 'sl-dots', 'sl-note',
           'sl-stats', 'sl-st-peak', 'sl-st-queued', 'sl-st-avg'):
    check('id="%s"' % el in waiting, 'waiting: нет id=%s' % el)
for frag in ('/.safeline/api/waiting/query', '/.safeline/api/waiting/ws',
             'sl-waiting-state=full', 'PREVIEW=!location.hostname'):
    check(frag in waiting, 'waiting: нет фрагмента %s' % frag)
check('#ff0000' not in m.waiting_page_html('demo.example.com', {'page': {'color': '#ff0000'}}, ''),
      'waiting: цвет панели всё ещё влияет')

queue = m.queue_page_html()
check('$' not in queue, 'queue: незаменённый $')
check('data:font/woff2;base64,' in queue, 'queue: нет вшитых шрифтов')
check('<!-- slext-queue-page -->' in queue, 'queue: потерян маркер')
for el in ('sl-title', 'sl-msg', 'sl-arc', 'sl-pos', 'sl-posline',
           'sl-total', 'sl-spin', 'sl-note', 'sl-brand'):
    check('id="%s"' % el in queue, 'queue: нет id=%s' % el)
for frag in ('/.safeline/slext/status', 'nrgpass', 'window.__slPreview'):
    check(frag in queue, 'queue: нет фрагмента %s' % frag)
check("style.setProperty('--accent'" not in queue, 'queue: цвет всё ещё влияет')

check(m.font_css().count('data:font/woff2;base64,') == 6, 'font_css: ожидалось 6 шрифтов')

# API-маршруты: генерация nginx-конфигов (whitelist + rate-limit)
import tempfile
_tmp = tempfile.mkdtemp()
m.API_WL_FILE = os.path.join(_tmp, 'wl.conf')
m.API_RL_FILE = os.path.join(_tmp, 'rl.conf')
check(m.api_routes_files_write({'app.example.com': {'enabled': True, 'paths': ['/api/v1/'],
                                                    'rate': 120, 'burst': 40}}),
      'api routes: файлы записаны')
wl = open(m.API_WL_FILE, encoding='utf-8').read()
rl = open(m.API_RL_FILE, encoding='utf-8').read()
check('map "$host$uri" $slext_api_wl' in wl, 'api wl: карта')
check('~^app\\.example\\.com/api/v1/' in wl, 'api wl: путь')
check('limit_req_zone $slext_api_rlk_app_example_com zone=slext_api_app_example_com:10m rate=120r/m;' in rl,
      'api rl: зона и rate')
check('limit_req_status 429' in rl, 'api rl: статус 429')
check(m.api_routes_files_write({}), 'api routes: пустая запись без ошибок')

# патчер: whitelist-if и limit_req в конфиге сайта
_pspec = importlib.util.spec_from_file_location('patch_site_page',
                                                os.path.join(ROOT, 'bin', 'patch_site_page.py'))
psp = importlib.util.module_from_spec(_pspec)
_pspec.loader.exec_module(psp)
site = ('server {\n'
        '    server_name app.example.com;\n'
        '    if ($slext_skip) { rewrite ^ /@slext-plain last; } # slext-skip-if\n'
        '    location = /@slext-plain {\n'
        '        internal;\n'
        '    }\n'
        '}\n')
cfg = {'enabled': True, 'paths': ['/api/v1/'], 'rate': 120, 'burst': 40}
out, changed = psp.patch_api_routes(site, cfg, 'app.example.com')
check(changed and '# slext-api-wl' in out, 'patcher: whitelist-if добавлен')
check('limit_req zone=slext_api_app_example_com burst=40 nodelay; # slext-api-rl' in out,
      'patcher: limit_req добавлен')
out2, changed2 = psp.patch_api_routes(out, {}, 'app.example.com')
check(changed2 and 'slext-api' not in out2, 'patcher: строки снимаются при отключении')

if fails:
    for f in fails:
        print('FAIL:', f)
    sys.exit(1)
print('pages test: ok')
