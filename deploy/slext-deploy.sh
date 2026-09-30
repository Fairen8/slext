#!/bin/bash
# Серверный установщик SLExt из staging — используется CI/CD (GitHub Actions).
# Устанавливается в /usr/local/bin/slext-deploy и запускается через sudo без пароля
# (настраивается скриптом deploy/install-deploy-access.sh).
set -e

# Самообновление: CI выкладывает свежий deploy-скрипт в staging — применяем его сами,
# иначе /usr/local/bin/slext-deploy остаётся старой версией.
STAGED_DEPLOY=/tmp/slext-stage/deploy/slext-deploy.sh
if [ -f "$STAGED_DEPLOY" ]; then
  sed -i 's/\r$//' "$STAGED_DEPLOY" 2>/dev/null || true
  if [ "${SLEXT_DEPLOY_REEXEC:-}" != "1" ] && ! cmp -s "$STAGED_DEPLOY" /usr/local/bin/slext-deploy; then
    install -o root -g root -m 755 "$STAGED_DEPLOY" /usr/local/bin/slext-deploy
    export SLEXT_DEPLOY_REEXEC=1
    exec /usr/local/bin/slext-deploy "$@"
  fi
fi

SRC=/tmp/slext-stage
if [ ! -d "$SRC/bin" ] || [ ! -d "$SRC/www" ]; then
  echo "ОШИБКА: нет $SRC (ожидается выгрузка репозитория)"
  exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
echo "== slext-deploy $STAMP =="

# 1. Раскладываем новую версию по управляемым каталогам.
#    Остальное в /opt/slext (например, tools/) не трогаем — деплой не должен
#    удалять локальные инструменты и заметки.
mkdir -p /opt/slext /opt/slext.old
for d in bin www conf systemd; do
  rm -rf "/opt/slext.old/$d"
  if [ -d "/opt/slext/$d" ]; then
    cp -a "/opt/slext/$d" "/opt/slext.old/$d" 2>/dev/null || true
  fi
  if [ -f /opt/slext/conf/slext.env ] && [ "$d" = "conf" ]; then
    cp -a /opt/slext/conf/slext.env /opt/slext.old/conf-slext.env 2>/dev/null || true
  fi
  if [ -f /opt/slext/conf/state.json ] && [ "$d" = "conf" ]; then
    cp -a /opt/slext/conf/state.json /opt/slext.old/conf-state.json 2>/dev/null || true
  fi
  if [ -f /opt/slext/conf/lb-upstreams.conf ] && [ "$d" = "conf" ]; then
    cp -a /opt/slext/conf/lb-upstreams.conf /opt/slext.old/conf-lb-upstreams.conf 2>/dev/null || true
  fi
  if [ -d /opt/slext/conf/geo ] && [ "$d" = "conf" ]; then
    cp -a /opt/slext/conf/geo /opt/slext.old/conf-geo 2>/dev/null || true
  fi
  rm -rf "/opt/slext/$d"
  cp -a "$SRC/$d" "/opt/slext/"
done
chmod +x /opt/slext/bin/*.sh 2>/dev/null || true
chmod +x /opt/slext/bin/*.py 2>/dev/null || true
# страховка от CRLF (staging может приехать из не-Linux окружений)
find /opt/slext/bin -maxdepth 1 -type f \( -name '*.sh' -o -name '*.py' \) \
  -exec sed -i 's/\r$//' {} + 2>/dev/null || true

# 2. Рантайм-конфигурация и состояние не должны теряться при обновлении
if [ ! -f /opt/slext/conf/slext.env ] && [ -f /opt/slext.old/conf-slext.env ]; then
  cp -a /opt/slext.old/conf-slext.env /opt/slext/conf/slext.env
fi
if [ ! -f /opt/slext/conf/state.json ] && [ -f /opt/slext.old/conf-state.json ]; then
  cp -a /opt/slext.old/conf-state.json /opt/slext/conf/state.json
fi
if [ -f /opt/slext.old/conf-lb-upstreams.conf ]; then
  cp -a /opt/slext.old/conf-lb-upstreams.conf /opt/slext/conf/lb-upstreams.conf
fi
if [ -d /opt/slext.old/conf-geo ]; then
  cp -a /opt/slext.old/conf-geo /opt/slext/conf/geo
fi
rm -rf /opt/slext.old/conf-slext.env /opt/slext.old/conf-state.json \
       /opt/slext.old/conf-lb-upstreams.conf /opt/slext.old/conf-geo

# 3. Зависимости
if ! python3 -c 'import psycopg2' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  timeout 300 apt-get install -y -qq python3-psycopg2 || true
fi

# 4. Конфигурация доступа к БД (если ещё нет)
if [ ! -f /opt/slext/conf/slext.env ]; then
  PGPASS="$(timeout 30 docker exec safeline-pg printenv POSTGRES_PASSWORD)"
  printf 'PGHOST=127.0.0.1\nPGUSER=safeline-ce\nPGPASSWORD=%s\nPGDATABASE=safeline-ce\n' "$PGPASS" > /opt/slext/conf/slext.env
  chmod 600 /opt/slext/conf/slext.env
fi

# 5. Юниты systemd (на случай обновлений)
cp -a /opt/slext/systemd/. /etc/systemd/system/ 2>/dev/null || true
sed -i 's/\r$//' /etc/systemd/system/slext-*.service /etc/systemd/system/slext-*.timer \
  /etc/systemd/system/slext-*.path 2>/dev/null || true
systemctl daemon-reload || true
systemctl enable --now slext-api.service 2>/dev/null || true
systemctl enable --now slext-apply.path slext-apply.timer 2>/dev/null || true
systemctl enable --now slext-watchdog.timer 2>/dev/null || true

# 6. Применяем патчи и перезапускаем API
bash /opt/slext/bin/apply-injection.sh
systemctl restart slext-api

# 7. Ждём готовности API (до ~60 с). Не поднялся — откат на прошлую версию.
ok=0
for _ in $(seq 1 30); do
  if curl -fsS -m 3 http://127.0.0.1:8787/api/health >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [ "$ok" != "1" ]; then
  echo "ОШИБКА: API не поднялся после рестарта"
  journalctl -u slext-api -n 50 --no-pager 2>/dev/null || true
  if [ -d /opt/slext.old/bin ] && [ -d /opt/slext.old/www ]; then
    echo "== откат на предыдущую версию =="
    rm -rf /opt/slext/bin /opt/slext/www
    cp -a /opt/slext.old/bin /opt/slext/bin
    cp -a /opt/slext.old/www /opt/slext/www
    if [ -d /opt/slext.old/systemd ]; then
      cp -a /opt/slext.old/systemd/. /etc/systemd/system/ 2>/dev/null || true
      systemctl daemon-reload || true
    fi
    systemctl restart slext-api || true
    sleep 5
    curl -fsS -m 3 http://127.0.0.1:8787/api/health || true
    echo "откат выполнен"
  fi
  exit 1
fi

# 8. Проверка
curl -fsS http://127.0.0.1:8787/api/health
echo
echo "== deploy OK $STAMP (бэкап: /opt/slext.old) =="
