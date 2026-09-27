#!/usr/bin/env python3
p = '/data/safeline/resources/nginx/sites-enabled/IF_backend_1'
s = open(p).read()
if 'slext-skipdec' in s:
    print('already present')
    raise SystemExit
marker = "        proxy_intercept_errors on; # slext-page-intercept\n"
if marker not in s:
    print('marker missing')
    raise SystemExit(1)
lines = ("        sub_filter 'Math.max(3e3-(endTime-startTime),0)' '0';\n"
         "        sub_filter 'onShowContainer();docCookies.setItem' 'docCookies.setItem';\n"
         "        sub_filter_once off;\n"
         "        sub_filter_types text/html; # slext-skipdec\n")
s = s.replace(marker, marker + lines, 1)
open(p, 'w').write(s)
print('patched')
