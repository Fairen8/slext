#!/bin/bash
# Серверный установщик SLExt из staging — используется CI/CD (GitHub Actions).
# Устанавливается в /usr/local/bin/slext-deploy и запускается через sudo без пароля
# (настраивается скриптом deploy/install-deploy-access.sh).
set -e

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
  rm -rf "/opt/slext/$d"
  cp -a "$SRC/$d" "/opt/slext/"
done
chmod +x /opt/slext/bin/*.sh 2>/dev/null || true
chmod +x /opt/slext/bin/*.py 2>/dev/null || true

# 2. Рантайм-конфигурация и состояние не должны теряться при обновлении
if [ ! -f /opt/slext/conf/slext.env ] && [ -f /opt/slext.old/conf-slext.env ]; then
  cp -a /opt/slext.old/conf-slext.env /opt/slext/conf/slext.env
fi
if [ ! -f /opt/slext/conf/state.json ] && [ -f /opt/slext.old/conf-state.json ]; then
  cp -a /opt/slext.old/conf-state.json /opt/slext/conf/state.json
fi
rm -f /opt/slext.old/conf-slext.env /opt/slext.old/conf-state.json

# 3. Зависимости
if ! python3 -c 'import psycopg2' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq python3-psycopg2 || true
fi

# 4. Конфигурация доступа к БД (если ещё нет)
if [ ! -f /opt/slext/conf/slext.env ]; then
  PGPASS="$(docker exec safeline-pg printenv POSTGRES_PASSWORD)"
  printf 'PGHOST=127.0.0.1\nPGUSER=safeline-ce\nPGPASSWORD=%s\nPGDATABASE=safeline-ce\n' "$PGPASS" > /opt/slext/conf/slext.env
  chmod 600 /opt/slext/conf/slext.env
fi

# 5. Юниты systemd (на случай обновлений)
cp -a /opt/slext/systemd/. /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload || true
systemctl enable --now slext-api.service 2>/dev/null || true
systemctl enable --now slext-apply.path slext-apply.timer 2>/dev/null || true
systemctl enable --now slext-watchdog.timer 2>/dev/null || true

# 6. Применяем патчи и перезапускаем API
bash /opt/slext/bin/apply-injection.sh
systemctl restart slext-api
sleep 2
systemctl is-active slext-api

# 7. Проверка
curl -fsS http://127.0.0.1:8787/api/health
echo
echo "== deploy OK $STAMP (бэкап: /opt/slext.old) =="
