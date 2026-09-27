#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import time
import urllib.request

CHROME = '/opt/slext/tools/chrome-headless-shell-linux64/chrome-headless-shell'
PROFILE = '/tmp/chprof2'


def totp_code():
    sec = subprocess.check_output(
        ['docker', 'exec', 'safeline-pg', 'psql', '-U', 'safeline-ce', '-d', 'safeline-ce', '-Atc',
         'SELECT tfa_secret FROM mgt_user ORDER BY id LIMIT 1']).decode().strip()
    key = base64.b32decode(sec + '=' * ((8 - len(sec) % 8) % 8))
    counter = int(time.time() // 30)
    h = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return '%06d' % ((struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


LOGIN_JS = r"""
(async function(){
 try {
  var s=document.createElement('script');
  s.src='https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js';
  await new Promise(function(res,rej){s.onload=res;s.onerror=rej;document.head.appendChild(s);});
  var key=(await (await fetch('/api/open/system/key')).json()).data;
  var csrf=(await (await fetch('/api/open/auth/csrf')).json()).data.csrf_token;
  var ivHex=CryptoJS.enc.Hex.stringify(CryptoJS.lib.WordArray.random(8));
  var ct=CryptoJS.AES.encrypt(__P__, CryptoJS.enc.Utf8.parse(key), {iv: CryptoJS.enc.Utf8.parse(ivHex), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7});
  var latin=CryptoJS.enc.Latin1.stringify(ct.ciphertext);
  var pwd=btoa(ivHex+latin);
  var r=await fetch('/api/open/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:__U__,password:pwd,csrf_token:csrf})});
  var j=await r.json();
  if (!(j && j.data && j.data.jwt)) { return 'PW-FAIL '+r.status+' '+JSON.stringify(j).slice(0,200); }
  var jwt1=j.data.jwt;
  var csrf2=(await (await fetch('/api/open/auth/csrf',{headers:{'Authorization':'Bearer '+jwt1}})).json()).data.csrf_token;
  var r2=await fetch('/api/open/auth/tfa',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+jwt1},body:JSON.stringify({code:__C__,timestamp:Date.now(),csrf_token:csrf2})});
  var j2=await r2.json();
  if (j2 && j2.data && j2.data.jwt) { localStorage.setItem('safeline_auth', j2.data.jwt); return 'TFA 200 ok'; }
  return 'TFA-FAIL '+r2.status+' '+JSON.stringify(j2).slice(0,200);
 } catch(e) { return 'ERR '+e; }
})()
"""


async def main():
    user, pw = sys.argv[1], sys.argv[2]
    targets = sys.argv[3].split(',')
    outdir = sys.argv[4]
    post_file = sys.argv[5] if len(sys.argv) > 5 else ''
    post_js = open(post_file).read() if post_file else ''
    proc = subprocess.Popen(
        [CHROME, '--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
         '--remote-debugging-port=9222', '--user-data-dir=' + PROFILE, '--window-size=1600,1000',
         '--ignore-certificate-errors', 'about:blank'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        await asyncio.sleep(2.5)
        pages = json.load(urllib.request.urlopen('http://127.0.0.1:9222/json', timeout=5))
        page = [p for p in pages if p.get('type') == 'page'][0]
        import websockets
        async with websockets.connect(page['webSocketDebuggerUrl'], max_size=64 * 1024 * 1024) as ws:
            counter = {'i': 0}
            events = []

            async def cmd(method, params=None):
                counter['i'] += 1
                mid = counter['i']
                await ws.send(json.dumps({'id': mid, 'method': method, 'params': params or {}}))
                while True:
                    msg = json.loads(await ws.recv())
                    if msg.get('id') == mid:
                        return msg
                    if len(events) < 5000:
                        events.append(msg)

            async def ev(expr, await_promise=False):
                r = await cmd('Runtime.evaluate',
                              {'expression': expr, 'returnByValue': True, 'awaitPromise': await_promise})
                res = r.get('result', {}).get('result', {})
                if 'value' in res:
                    return res['value']
                return res.get('description')

            await cmd('Page.enable')
            await cmd('Runtime.enable')
            await cmd('Network.enable')
            await cmd('Page.navigate', {'url': 'https://127.0.0.1:9443/login'})
            await asyncio.sleep(3)
            js = LOGIN_JS.replace('__U__', json.dumps(user)).replace('__P__', json.dumps(pw))
            login_result = ''
            code = totp_code()
            for attempt in range(3):
                js = LOGIN_JS.replace('__U__', json.dumps(user)).replace('__P__', json.dumps(pw)).replace('__C__', json.dumps(code))
                login_result = await ev(js, True)
                print('login attempt', attempt + 1, ':', login_result)
                if 'TFA 200' in str(login_result):
                    break
                code = totp_code()
                await asyncio.sleep(2)
            await asyncio.sleep(2)
            print('token in ls:', await ev("!!localStorage.getItem('safeline_auth')"))
            print('path:', await ev('location.pathname'))
            print('cookie:', await ev('document.cookie'))
            print('whoami:', await ev(
                "(async function(){var t=localStorage.getItem('safeline_auth');"
                "var out=[];"
                "for (var u of ['/api/business/account','/api/business/users/1','/api/business/frontend_style']) {"
                " try { var r=await fetch(u,{headers:{'Authorization':'Bearer '+t}});"
                " out.push(u+' '+r.status+' '+(await r.text()).slice(0,90)); } catch(e){ out.push(u+' ERR '+e); }"
                "}"
                "return out.join(' || ');})()", True))
            for t in targets:
                events.clear()
                await cmd('Page.navigate', {'url': 'https://127.0.0.1:9443' + t})
                await asyncio.sleep(7)
                apis = []
                for m in events:
                    if m.get('method') == 'Network.responseReceived':
                        r = m['params']['response']
                        if '/api/' in r['url']:
                            apis.append('%s %s' % (r['status'], r['url'].split('9443')[-1]))
                    if m.get('method') == 'Network.requestWillBeSentExtraInfo':
                        hdr = m['params'].get('headers') or {}
                        if 'Authorization' in hdr:
                            req_url = ''
                            apis.append('AUTH-REQ')
                print('net:', ' ; '.join(apis[-18:]))
                if post_js:
                    print('postjs:', await ev(post_js, True))
                    await asyncio.sleep(2.5)
                html = await ev('document.documentElement.outerHTML') or ''
                name = outdir + t.strip('/').replace('/', '_')
                open(name + '.html', 'w').write(html)
                r = await cmd('Page.captureScreenshot', {'format': 'png'})
                open(name + '.png', 'wb').write(base64.b64decode(r['result']['data']))
                print('saved', t, len(html))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


asyncio.run(main())
