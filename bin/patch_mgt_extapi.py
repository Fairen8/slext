#!/usr/bin/env python3
# Идемпотентный и self-healing патч прокси /extapi/ в конфиге панели SafeLine.
# Всегда приводит блок к виду: proxy_pass http://<gateway>:8787/ (API SLExt).
# Печатает "changed" если файл изменён, иначе "ok".
import re
import sys

src, dst, gw = sys.argv[1], sys.argv[2], sys.argv[3]

BLOCK = (
    '    location /extapi/ {\n'
    '        proxy_pass http://%s:8787/;\n'
    '        proxy_http_version 1.1;\n'
    '        proxy_set_header Host $host;\n'
    '        proxy_read_timeout 120s;\n'
    '        proxy_send_timeout 120s;\n'
    '        # slext-extapi\n'
    '    }\n' % gw
)

with open(src, encoding='utf-8') as f:
    text = f.read()

changed = False
rx = re.compile(r'^[ \t]*location\s+/extapi/?\s*\{.*?^\s*\}\n', re.M | re.S)
m = rx.search(text)
if m:
    if ('proxy_pass http://%s:8787/' % gw) not in m.group(0):
        text = text[:m.start()] + BLOCK + text[m.end():]
        changed = True
else:
    anchor = re.search(r'^[ \t]*location /assets/ \{', text, re.M)
    if not anchor:
        sys.stderr.write('anchor not found\n')
        sys.exit(1)
    text = text[:anchor.start()] + BLOCK + text[anchor.start():]
    changed = True

with open(dst, 'w', encoding='utf-8') as f:
    f.write(text)
print('changed' if changed else 'ok')
