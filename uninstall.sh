#!/bin/bash
# Удаление SLExt. Запуск: sudo bash uninstall.sh [--yes]
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Запустите от root:  sudo bash uninstall.sh"
  exit 1
fi

if [ "$1" != "--yes" ]; then
  echo "Будут удалены: службы slext-api/slext-apply, каталог /opt/slext, инъекция."
  read -p "Продолжить? (y/N): " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "Отменено."; exit 0; }
fi

echo "[1/5] Останавливаю службы..."
systemctl disable --now slext-apply.path slext-apply.timer 2>/dev/null || true
systemctl disable --now slext-api.service 2>/dev/null || true

echo "[2/5] Удаляю юниты..."
rm -f /etc/systemd/system/slext-api.service \
      /etc/systemd/system/slext-apply.service \
      /etc/systemd/system/slext-apply.timer \
      /etc/systemd/system/slext-apply.path
systemctl daemon-reload

echo "[3/5] Убираю инъекцию из панели..."
if docker ps --format '{{.Names}}' | grep -qx safeline-mgt; then
  docker exec safeline-mgt sed -i -E \
    's|<script src="/ext/ext\.js\?v=[0-9]+" defer></script>||;
     s|<link href="/ext/ext\.css\?v=[0-9]+" rel="stylesheet">||' \
    /app/static/index.html || true
  echo "  ссылки ext.js/ext.css удалены (Ctrl+F5 в панели)."
fi

echo "[4/5] Восстанавливаю конфиги сайтов (если есть бэкап)..."
for orig in /data/safeline/resources/nginx/sites-enabled/IF_*.slext-orig; do
  [ -f "$orig" ] || continue
  tgt="${orig%.slext-orig}"
  cp -a "$tgt" "$tgt.slext-removed" 2>/dev/null || true
  cp -a "$orig" "$tgt"
  echo "  восстановлен: $tgt"
done
if ! ls /data/safeline/resources/nginx/sites-enabled/IF_*.slext-orig >/dev/null 2>&1; then
  echo "  бэкапов нет: патчи nginx останутся, но перестанут применяться."
  echo "  Для чистого конфига сохраните сайт в панели SafeLine (конфиг перегенерируется)."
fi
docker exec safeline-tengine nginx -t >/dev/null 2>&1 && docker exec safeline-tengine nginx -s reload || true

echo "[5/5] Удаляю файлы..."
rm -rf /opt/slext
if ! grep -rq '# slext-' /data/safeline/resources/nginx/sites-enabled/ 2>/dev/null; then
  rm -f /data/safeline/resources/nginx/conf.d/zz_slext_*.conf
  docker exec safeline-tengine nginx -t >/dev/null 2>&1 && docker exec safeline-tengine nginx -s reload || true
else
  echo "  ВНИМАНИЕ: в конфигах сайтов остались ссылки на карты SLExt — файлы карт сохранены,"
  echo "  чтобы nginx оставался рабочим. Сохраните сайт в панели SafeLine для чистой генерации."
fi
echo
echo "SLExt удалён. Логи аналитики (/data/safeline/logs/nginx/slext_traffic.log) оставлены — удалите вручную при необходимости."
