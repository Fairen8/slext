#!/bin/bash
# Smoke-проверка установки SLExt. Запуск: bash tests/verify-install.sh
ok=0
fail=0

check() {
  if eval "$2" >/dev/null 2>&1; then
    echo "  OK   $1"
    ok=$((ok + 1))
  else
    echo "  FAIL $1"
    fail=$((fail + 1))
  fi
}

echo "== SLExt: проверка установки =="
check "служба slext-api активна"          "systemctl is-active --quiet slext-api"
check "health отвечает ok"                "curl -fsS http://127.0.0.1:8787/api/health | grep -q '\"ok\": true'"
EXTVER="$(cat /opt/slext/conf/extver 2>/dev/null)"
check "index ссылается на ext.js?v=$EXTVER" "docker exec safeline-mgt grep -q \"ext.js?v=$EXTVER\" /app/static/index.html"
check "инъекция в index (slext-injected)"  "docker exec safeline-mgt grep -q slext-injected /app/static/index.html"
check "ассеты в контейнере панели"         "docker exec safeline-mgt test -s /app/static/ext/ext.js"
check "конфиг nginx валиден"               "docker exec safeline-tengine nginx -t"
check "вотчдог slext-apply.path активен"   "systemctl is-active --quiet slext-apply.path"
check "карты skip/gate на месте"           "test -f /data/safeline/resources/nginx/conf.d/zz_slext_skip.conf -a -f /data/safeline/resources/nginx/conf.d/zz_slext_gate.conf"
check "страницы ошибок на месте"           "test -s /data/safeline/resources/nginx/slext-pages/waiting_room.html"
check "лог прокси-аналитики существует"    "test -f /data/safeline/logs/nginx/slext_traffic.log"
check "state.json доступен"                "test -f /opt/slext/conf/state.json"
check "env для PostgreSQL на месте"        "test -f /opt/slext/conf/slext.env"

echo
echo "Итог: OK=$ok, FAIL=$fail"
[ "$fail" = "0" ]
