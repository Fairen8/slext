#!/usr/bin/env python3
p = '/data/safeline/resources/nginx/sites-enabled/IF_backend_1'
s = open(p).read()
if 'slext-enc-pipeline' in s:
    print('already present')
    raise SystemExit
marker = '        proxy_set_header Host $http_host;\n'
if marker not in s:
    print('marker missing')
    raise SystemExit(1)
s = s.replace(marker, marker + '        proxy_set_header Accept-Encoding ""; # slext-enc-pipeline\n', 1)
open(p, 'w').write(s)
print('patched')
