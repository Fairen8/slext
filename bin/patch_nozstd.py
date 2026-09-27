#!/usr/bin/env python3
p = '/data/safeline/resources/nginx/sites-enabled/IF_backend_1'
s = open(p).read()
if 'slext-nozstd' in s:
    print('already present')
    raise SystemExit
marker = '    gzip on;\n'
if marker not in s:
    print('marker missing')
    raise SystemExit(1)
s = s.replace(marker, marker + '    zstd off; # slext-nozstd\n', 1)
open(p, 'w').write(s)
print('patched')
