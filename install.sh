#!/bin/bash
# SLExt installer: разворачивает расширения SLExt поверх SafeLine WAF (CE).
# Запуск:
#   sudo bash install.sh                 — поверх уже установленной SafeLine
#   sudo bash install.sh --with-safeline — сначала официальная установка SafeLine CE, затем SLExt
set -e

WITH_SAFELINE=0
for arg in "$@"; do
  case "$arg" in
    --with-safeline) WITH_SAFELINE=1 ;;
    -h|--help)
      echo "Использование: sudo bash install.sh [--with-safeline]"
      echo "  --with-safeline  установить SafeLine CE официальным инсталлятором, затем SLExt"
      exit 0
      ;;
  esac
done

if [ "$(id -u)" != "0" ]; then
  echo "Запустите от root:  sudo bash install.sh"
  exit 1
fi

SRC="$(cd "$(dirname "$0")" && pwd)"
echo "== Установка SLExt из $SRC =="

safeline_ready() {
  for c in safeline-mgt safeline-tengine safeline-pg; do
    docker ps --format '{{.Names}}' | grep -qx "$c" || return 1
  done
  return 0
}

echo "[1/8] Проверяю SafeLine..."
if ! safeline_ready; then
  if [ "$WITH_SAFELINE" = "1" ]; then
    echo "SafeLine не найдена — запускаю официальный инсталлятор SafeLine CE."
    echo "Он интерактивный: ответьте на его вопросы (путь, установка Docker и т.д.)."
    echo "Документация: https://docs.waf.chaitin.com/en/GetStarted/Deploy"
    bash -c "$(curl -fsSL https://waf.chaitin.com/release/latest/setup.sh)"
    if ! safeline_ready; then
      echo "ОШИБКА: после установки контейнеры SafeLine не обнаружены."
      exit 1
    fi
    echo "SafeLine установлена."
  else
    echo "ОШИБКА: SafeLine CE не найдена (нет контейнеров safeline-mgt/-tengine/-pg)."
    echo
    echo "Вариант 1) установить SafeLine официально, затем повторить:"
    echo '  bash -c "$(curl -fsSL https://waf.chaitin.com/release/latest/setup.sh)"'
    echo '  sudo bash install.sh'
    echo
    echo "Вариант 2) одной командой (скрипт сам вызовет официальный инсталлятор):"
    echo '  sudo bash install.sh --with-safeline'
    echo
    echo "Документация SafeLine: https://docs.waf.chaitin.com/en/GetStarted/Deploy"
    exit 1
  fi
fi

echo "[2/8] Зависимости..."
if ! python3 -c 'import psycopg2' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3-psycopg2
fi
if ! command -v openssl >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq openssl
fi

echo "[3/8] Файлы в /opt/slext..."
mkdir -p /opt/slext
cp -a "$SRC/bin" "$SRC/www" "$SRC/conf" /opt/slext/
chmod +x /opt/slext/bin/*.sh 2>/dev/null || true
chmod +x /opt/slext/bin/*.py 2>/dev/null || true

echo "[4/8] Конфигурация (slext.env)..."
if [ ! -f /opt/slext/conf/slext.env ]; then
  PGPASS="$(docker exec safeline-pg printenv POSTGRES_PASSWORD 2>/dev/null || true)"
  if [ -z "$PGPASS" ]; then
    echo "ОШИБКА: не удалось получить пароль PostgreSQL из контейнера safeline-pg."
    echo "Создайте /opt/slext/conf/slext.env вручную (PGHOST/PGUSER/PGPASSWORD/PGDATABASE)."
    exit 1
  fi
  cat > /opt/slext/conf/slext.env <<EOF
PGHOST=127.0.0.1
PGUSER=safeline-ce
PGPASSWORD=$PGPASS
PGDATABASE=safeline-ce
EOF
  chmod 600 /opt/slext/conf/slext.env
fi

echo "[5/8] Службы systemd..."
cp -a "$SRC/systemd/." /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now slext-api.service
systemctl enable --now slext-apply.path slext-apply.timer

echo "[6/8] Применяю патчи к SafeLine (идемпотентно)..."
bash /opt/slext/bin/apply-injection.sh

echo "[7/8] Проверка..."
sleep 3
if curl -fsS http://127.0.0.1:8787/api/health >/dev/null 2>&1; then
  echo
  echo "SLExt установлен. Откройте панель SafeLine и обновите страницу (Ctrl+F5) —"
  echo "в левом меню появится раздел SLExt (прокси-аналитика, DNS/TLS, зал ожидания,"
  echo "тест ёмкости, страницы ошибок и т.д.)."
else
  echo "API не ответил. Проверьте:"
  echo "  systemctl status slext-api"
  echo "  journalctl -u slext-api -n 50 --no-pager"
  exit 1
fi
