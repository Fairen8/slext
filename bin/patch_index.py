#!/usr/bin/env python3
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding='utf-8') as f:
    html = f.read()

# Идемпотентно и с самовосстановлением: убираем старые теги/маркер и ставим заново.
html = re.sub(r'<link[^>]*href="/ext/ext\.css[^>]*>\s*', '', html)
html = re.sub(r'<script[^>]*src="/ext/ext\.js[^>]*>\s*</script>\s*', '', html)
html = re.sub(r'<!--\s*slext-injected\s*-->', '', html)

link = '<link rel="stylesheet" href="/ext/ext.css?v=7"><!-- slext-injected -->'
script = '<script src="/ext/ext.js?v=7" defer></script>'
if '</head>' in html:
    html = html.replace('</head>', link + '</head>', 1)
if '</body>' in html:
    html = html.replace('</body>', script + '</body>', 1)
with open(dst, 'w', encoding='utf-8') as f:
    f.write(html)
print('patch_index: ok')
