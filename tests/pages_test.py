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

if fails:
    for f in fails:
        print('FAIL:', f)
    sys.exit(1)
print('pages test: ok')
