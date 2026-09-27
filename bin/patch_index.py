#!/usr/bin/env python3
import sys

src, dst = sys.argv[1], sys.argv[2]
html = open(src, encoding='utf-8').read()
if 'slext-injected' not in html:
    link = '<link rel="stylesheet" href="/ext/ext.css?v=7"><!-- slext-injected -->'
    script = '<script src="/ext/ext.js?v=7" defer></script>'
    if '</head>' in html:
        html = html.replace('</head>', link + '</head>', 1)
    if '</body>' in html:
        html = html.replace('</body>', script + '</body>', 1)
open(dst, 'w', encoding='utf-8').write(html)
print('patch_index: ok')
