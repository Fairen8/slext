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

# 1. Собираем новую версию во временный каталог
rm -rf /opt/slext.new
mkdir -p /opt/slext.new
cp -a "$SRC/bin" "$SRC/www" "$SRC/conf" "$SRC/systemd" /opt/slext.new/
chmod +x /opt/slext.new/bin/*.sh 2>/dev/null || true
chmod +x /opt/slext.new/bin/*.py 2>/dev/null || true

# 2. Сохраняем рантайм-конфигурацию и состояние
if [ -f /opt/slext/conf/slext.env ]; then
  cp -a /opt/slext/conf/slext.env /opt/slext.new/conf/
fi
if [ -f /opt/slext/conf/state.json ]; then
  cp -a /opt/slext/conf/state.json /opt/slext.new/conf/
fi

# 3. Бэкап текущей версии и подмена
rm -rf /opt/slext.old
if [ -d /opt/slext ]; then
  mv /opt/slext /opt/slext.old
fi
mv /opt/slext.new /opt/slext

# 4. Зависимости
if ! python3 -c 'import psycopg2' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq python3-psycopg2 || true
fi

# 5. Конфигурация доступа к БД (если ещё нет)
if [ ! -f /opt/slext/conf/slext.env ]; then
  PGPASS="$(docker exec safeline-pg printenv POSTGRES_PASSWORD)"
  printf 'PGHOST=127.0.0.1\nPGUSER=safeline-ce\nPGPASSWORD=%s\nPGDATABASE=safeline-ce\n' "$PGPASS" > /opt/slext/conf/slext.env
  chmod 600 /opt/slext/conf/slext.env
fi

# 6. Юниты systemd (на случай обновлений)
cp -a /opt/slext/systemd/. /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload || true
systemctl enable --now slext-api.service 2>/dev/null || true
systemctl enable --now slext-apply.path slext-apply.timer 2>/dev/null || true

# 7. Применяем патчи и перезапускаем API
bash /opt/slext/bin/apply-injection.sh
systemctl restart slext-api
sleep 2
systemctl is-active slext-api

# 8. Проверка
curl -fsS http://127.0.0.1:8787/api/health
echo
echo "== deploy OK $STAMP (бэкап: /opt/slext.old) =="
