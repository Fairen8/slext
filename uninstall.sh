#!/bin/bash
# Удаление SLExt. Запуск: sudo bash uninstall.sh [--yes]
set -e

if [ "$(id -u)" != "0" ]; then
  echo "Запустите от root:  sudo bash uninstall.sh"
  exit 1
fi

if [ "$1" != "--yes" ]; then
  echo "Будут удалены: службы slext-api/slext-apply/slext-watchdog/slext-teststub, каталог /opt/slext, инъекция."
  read -p "Продолжить? (y/N): " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "Отменено."; exit 0; }
fi

echo "[1/6] Останавливаю службы..."
systemctl disable --now slext-apply.path slext-apply.timer 2>/dev/null || true
systemctl disable --now slext-watchdog.timer slext-watchdog.service 2>/dev/null || true
systemctl disable --now slext-teststub.service 2>/dev/null || true
systemctl disable --now slext-api.service 2>/dev/null || true

echo "[2/6] Удаляю юниты..."
rm -f /etc/systemd/system/slext-api.service \
      /etc/systemd/system/slext-apply.service \
      /etc/systemd/system/slext-apply.timer \
      /etc/systemd/system/slext-apply.path \
      /etc/systemd/system/slext-watchdog.service \
      /etc/systemd/system/slext-watchdog.timer \
      /etc/systemd/system/slext-teststub.service
systemctl daemon-reload

echo "[3/6] Убираю инъекцию из панели..."
if docker ps --format '{{.Names}}' | grep -qx safeline-mgt; then
  docker exec safeline-mgt sed -i -E \
    's|<link[^>]*href="/ext/ext\.css[^>]*>||g;
     s|<script[^>]*src="/ext/ext\.js[^>]*></script>||g;
     s|<!--[[:space:]]*slext-injected[[:space:]]*-->||g' \
    /app/static/index.html || true
  echo "  ссылки ext.js/ext.css удалены (Ctrl+F5 в панели)."
fi

echo "[4/6] Восстанавливаю конфиги сайтов (если есть бэкап)..."
RESTORE_DIR=/opt/slext/backups/nginx
restored=0
# Основной формат бэкапов: /opt/slext/backups/nginx/<file>.slext-orig
if [ -d "$RESTORE_DIR" ]; then
  for orig in "$RESTORE_DIR"/*.slext-orig; do
    [ -f "$orig" ] || continue
    base="$(basename "$orig")"
    tgt="/data/safeline/resources/nginx/sites-enabled/${base%.slext-orig}"
    case "$base" in
      IF_*.slext-orig)
        [ -f "$tgt" ] || continue
        cp -a "$tgt" "$RESTORE_DIR/${base%.slext-orig}.slext-removed" 2>/dev/null || true
        cp -a "$orig" "$tgt"
        restored=$((restored + 1))
        echo "  восстановлен: $tgt"
        ;;
    esac
  done
fi
# Легаси-формат: бэкапы, оставшиеся рядом с конфигами.
for orig in /data/safeline/resources/nginx/sites-enabled/IF_*.slext-orig; do
  [ -f "$orig" ] || continue
  tgt="${orig%.slext-orig}"
  mkdir -p "$RESTORE_DIR"
  cp -a "$tgt" "$RESTORE_DIR/$(basename "$tgt").slext-removed" 2>/dev/null || true
  cp -a "$orig" "$tgt"
  restored=$((restored + 1))
  echo "  восстановлен: $tgt"
done
if [ "$restored" = "0" ]; then
  echo "  бэкапов нет: патчи nginx останутся, но перестанут применяться."
  echo "  Для чистого конфига сохраните сайт в панели SafeLine (конфиг перегенерируется)."
fi
docker exec safeline-tengine nginx -t >/dev/null 2>&1 && docker exec safeline-tengine nginx -s reload || true

echo "[5/6] Удаляю файлы..."
rm -rf /opt/slext
if ! grep -rq '# slext-' /data/safeline/resources/nginx/sites-enabled/ 2>/dev/null; then
  rm -f /data/safeline/resources/nginx/conf.d/zz_slext_*.conf
  docker exec safeline-tengine nginx -t >/dev/null 2>&1 && docker exec safeline-tengine nginx -s reload || true
else
  echo "  ВНИМАНИЕ: в конфигах сайтов остались ссылки на карты SLExt — файлы карт сохранены,"
  echo "  чтобы nginx оставался рабочим. Сохраните сайт в панели SafeLine для чистой генерации."
fi

echo "[6/6] Готово."
echo
echo "SLExt удалён. Логи аналитики (/data/safeline/logs/nginx/slext_traffic.log) оставлены — удалите вручную при необходимости."
