#!/bin/bash
# Проверка авторизации API SLExt. Запуск: sudo bash tests/auth-test.sh
API=http://127.0.0.1:8787
TOKEN=$(docker exec safeline-pg psql -U safeline-ce -d safeline-ce -Atc \
  'SELECT token FROM mgt_auth_token ORDER BY id DESC LIMIT 1')
if [ -z "$TOKEN" ]; then
  echo 'NO TOKENS IN DB (нужен вход в панель SafeLine)'
  exit 0
fi

echo -n 'health без токена (ожидается 200): '
curl -s -o /dev/null -w '%{http_code}\n' "$API/api/health"

echo -n 'me с токеном (ожидается 200): '
curl -s -o /tmp/slext-a.json -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" "$API/api/me"
head -c 200 /tmp/slext-a.json; echo

echo -n 'attacks с токеном (ожидается 200): '
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" "$API/api/attacks?hours=24"

echo -n 'lb без токена (ожидается 401): '
curl -s -o /dev/null -w '%{http_code}\n' "$API/api/lb"

echo -n 'битый токен (ожидается 401): '
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer deadbeef' "$API/api/lb"

rm -f /tmp/slext-a.json
