#!/usr/bin/env python3
import sys

p = '/data/safeline/resources/nginx/sites-enabled/IF_backend_1'
s = open(p).read()
if 'location = /.safeline/waiting_room_page' in s:
    print('already present')
    sys.exit(0)
block = ('    location = /.safeline/waiting_room_page {\n'
         '        t1k_intercept off;\n'
         '        tx_intercept off;\n'
         '        proxy_pass http://unix:/app/sock/tcd_error.sock;\n'
         '    }\n')
needle = '    location = /.safeline/not_found_page {\n'
if needle not in s:
    print('anchor not found')
    sys.exit(1)
s = s.replace(needle, block + needle, 1)
open(p, 'w').write(s)
print('inserted (https block, non-internal)')
