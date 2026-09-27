#!/bin/bash
# Быстрый контроль работоспособности SLExt: API, цепочка панель → /extapi → API
# и валидность конфига tengine (иначе mgt не может менять зал ожидания).
# При сбое перезапускает сервис и/или переприменяет патчи. Запускается таймером раз в минуту.
set -u

API=http://127.0.0.1:8787/api/health

# 1. Сам API
if ! curl -fsS -m 5 "$API" >/dev/null 2>&1; then
  systemctl restart slext-api
  sleep 2
fi

# 2. Цепочка панели: nginx панели (9443) → /extapi → API
code=$(curl -sk -o /dev/null -m 6 -w '%{http_code}' \
       https://127.0.0.1:9443/extapi/api/health 2>/dev/null || echo 000)
if [ "$code" != "200" ]; then
  bash /opt/slext/bin/apply-injection.sh >/dev/null 2>&1 || true
fi

# 3. Конфиг tengine: если nginx -t падает, mgt не сможет включить/выключить
#    зал ожидания и перегенерировать страницы. Переприменяем патчи (уносят бэкапы
#    из include-каталогов) и перезагружаем nginx.
if ! docker exec safeline-tengine nginx -t >/dev/null 2>&1; then
  bash /opt/slext/bin/apply-injection.sh >/dev/null 2>&1 || true
  docker exec safeline-tengine nginx -t >/dev/null 2>&1 && \
    docker exec safeline-tengine nginx -s reload >/dev/null 2>&1 || true
fi

# 4. Итоговая проверка (код возврата виден в journalctl -u slext-watchdog)
curl -fsS -m 5 "$API" >/dev/null 2>&1
