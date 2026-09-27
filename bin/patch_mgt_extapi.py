#!/usr/bin/env python3
import re
import sys

src, dst, gw = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, encoding='utf-8') as f:
    text = f.read()
if 'slext-extapi' not in text:
    block = ('    location /extapi/ {\n'
             '        proxy_pass https://%s:9444/;\n'
             '        proxy_ssl_verify off;\n'
             '        proxy_set_header Host $host;\n'
             '        proxy_read_timeout 60s;\n'
             '        # slext-extapi\n'
             '    }\n' % gw)
    m = re.search(r'^[ \t]*location /assets/ \{', text, re.M)
    if not m:
        sys.stderr.write('anchor not found\n')
        sys.exit(1)
    text = text[:m.start()] + block + text[m.start():]
with open(dst, 'w', encoding='utf-8') as f:
    f.write(text)
print('ok')
