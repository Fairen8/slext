# Диагностика

## Сайт получает 468 (challenge), хотя «Human verification» выключен

SafeLine хранит проверку в **per-site политике**, а не в глобальном тумблере. Признак:
в `mgt_website.challenge_id` у сайта указан id правила из `mgt_policy` (например, `7`),
тогда как у рабочего сайта там `0`. Патч конфигов сам по себе не помогает — mgt должен
перепубликовать политику.

Проверка и лечение (на сервере, от root):

```bash
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
  "SELECT id, comment, challenge_id FROM mgt_website ORDER BY id"
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
  "SELECT id, is_enabled, action, level, site_id FROM mgt_policy WHERE id=<challenge_id>"

# отключить challenge для сайта (подставьте id сайта)
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
  "UPDATE mgt_policy SET is_enabled=false, updated_at=now() WHERE id=<policy_id>"
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
  "UPDATE mgt_website SET challenge_id=0, updated_at=now() WHERE id=<site_id>"

# перепубликовать конфиг в детектор
docker restart safeline-mgt

# проверка снаружи: 200 / 302 / 405 / 400, без /.safeline/ и sl-session
curl -s -o /dev/null -w '%{http_code}\n' https://site/api/v1/health
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' https://site/
```

Прямые правки в БД применяются только после перезапуска `safeline-mgt`. Перед
изменениями сохраните строки `mgt_website`/`mgt_policy` (JSON) — для отката.

## Быстрый чек-лист

```bash
systemctl is-active slext-api                      # active?
curl -s http://127.0.0.1:8787/api/health | jq      # ok:true, extver
journalctl -u slext-api -n 50 --no-pager | grep -i error
docker exec safeline-tengine nginx -t              # конфиг валиден?
bash tests/verify-install.sh                       # полный smoke
```

## `nginx: [emerg] ... cannot load certificate key "/opt/slext/conf/mgt.key"`

Сертификат `mgt.crt` был без парного приватного ключа. SLExt генерирует пару
автоматически; чтобы починить вручную:

```bash
# проверить пару
openssl x509 -noout -modulus -in /opt/slext/conf/mgt.crt | openssl md5
openssl rsa  -noout -modulus -in /opt/slext/conf/mgt.key | openssl md5   # должен совпасть

# пересоздать (если ключа нет или пара не совпадает)
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout /opt/slext/conf/mgt.key -out /opt/slext/conf/mgt.crt -subj '/CN=SafeLine'
chmod 600 /opt/slext/conf/mgt.key

bash /opt/slext/bin/apply-injection.sh   # применит пару и перечитает nginx хоста
nginx -t && systemctl reload nginx
```

## В панели нет раздела SLExt

1. Проверьте, что `index.html` панели содержит инъекцию:

   ```bash
   docker exec safeline-mgt grep -c 'slext-injected' /app/static/index.html
   docker exec safeline-mgt grep -o 'ext.js?v=[0-9]*' /app/static/index.html
   ```

   Ожидается `1` и ссылка на актуальную версию (`v` равен `cat /opt/slext/conf/extver`).

2. Перепримените патчи:

   ```bash
   bash /opt/slext/bin/apply-injection.sh
   ```

3. Обновите страницу жёстко: **Ctrl+F5** (файл `ext.js` кэшируется по `?v=`).
4. Если пункт есть, но данных нет — проверьте `/api/health` и токен (раздел ниже).

## `401 unauthorized` из /extapi

- Токен панели истёк/отозван. Войдите в панель заново; проверка идёт через
  mgt API `/api/business/account`.
- Для тестов получите свежий токен из БД:

  ```bash
  docker exec safeline-pg psql -U safeline-ce -d safeline-ce -tAc \
    "SELECT token FROM mgt_auth_token ORDER BY id DESC LIMIT 1"
  ```

## `403 нет доступа: <право>` или `нет доступа к домену`

Это матрица доступа, а не сбой. Проверьте себя и пользователя:

```bash
TOKEN=...
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/me | jq
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/access | jq
```

Настройте роль/права/домены в SLExt → **Доступ** (администратором).

## API не стартует

```bash
journalctl -u slext-api -n 100 --no-pager
python3 -c 'import psycopg2'          # зависимость
cat /opt/slext/conf/slext.env         # PGHOST/PGUSER/PGPASSWORD/PGDATABASE
docker exec safeline-pg pg_isready
```

Частые причины: нет `python3-psycopg2`, неверный пароль PostgreSQL (обновите `slext.env`),
контейнер `safeline-pg` не запущен.

## Сайт снова показывает страницу расшифровки

Skip/gate работают через карты nginx и cookie:

```bash
# без cookie — гейт (~1800 байт)
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' -H 'Accept: text/html' https://САЙТ/
# с cookie — обычный сайт
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' -H 'Cookie: nrgpass=1' -H 'Accept: text/html' https://САЙТ/
```

Если размеры другие — проверьте патчи и состояние skip:

```bash
docker exec safeline-tengine grep -c 'slext-skip\|slext-gate' /etc/nginx/sites-enabled/IF_*
grep -A3 'map \$http_cookie' /data/safeline/resources/nginx/conf.d/zz_slext_skip.conf
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/skip
```

Переприменить: `bash /opt/slext/bin/apply-injection.sh`.

## Патчи исчезают после действий в панели SafeLine

Так и задумано: SafeLine перегенерирует конфиги. Вотчдог `slext-apply.path` возвращает патчи
за ~1 секунду. Проверить:

```bash
systemctl status slext-apply.path
systemctl list-timers slext-apply.timer
grep -c '# slext-' /data/safeline/resources/nginx/sites-enabled/IF_*
```

## Зал ожидания (SLExt): диагностика

Зал — **наш** (cookie-гейт в nginx + API), нативный зал SafeLine не используется. Состояние
и настройки — в блоке «Зал ожидания» (мгновенно). Если что-то не так:

```bash
# 1) наш API жив и что он думает
curl -s http://127.0.0.1:8787/api/health
curl -s -H "Authorization: Bearer $(cat /tmp/panel_token.txt)" \
  "http://127.0.0.1:8787/api/waiting?site=energy.fairen8.ru" | head -c 400

# 2) map-файл гейта (какие сайты включены) и конфиг tengine
cat /data/safeline/resources/nginx/conf.d/zz_slext_queue.conf
docker exec safeline-tengine nginx -t

# 3) страница очереди на месте?
grep -c 'slext-queue-page' /data/safeline/resources/nginx/slext-pages/queue.html
# нет — перегенерировать: bash /opt/slext/bin/apply-injection.sh (и «Сохранить настройки» в UI)

# 4) посетитель: свежий запрос должен получить страницу очереди, а не сайт
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: energy.fairen8.ru' \
  -H 'Accept: text/html' -H 'User-Agent: check' http://127.0.0.1/
```

Типовые причины:
- Очередь «не включается»: посмотрите map-файл (п. 2) и перезагрузите tengine
  `docker exec safeline-tengine nginx -s reload`; кнопка в UI делает это сама.
- «Все стоят в очереди»: проверьте настройки (порог/удержание/очередь) — сохраните в UI;
  кнопка **«Сбросить очередь»** очищает состояние мгновенно.
- Настройки/лимиты нативного SafeLine-зала (`mgt_waiting_room`) больше не используются.

Юнит-тесты политики авто-режима: `python3 tests/wr_policy_test.py`.

## Страница очереди — стоковая

```bash
ls -la /data/safeline/resources/nginx/slext-pages/            # queue.html есть?
grep -c 'slext-queue-page' /data/safeline/resources/nginx/slext-pages/queue.html
bash /opt/slext/bin/apply-injection.sh                        # перезалить
```

Убедитесь, что зал включён и запрос действительно отдаёт 465/нашу страницу.

## Тест ёмкости: «цель недоступна» или 0 запросов

- Появился прогрев: если цель не ответила за 8 секунд — тест не стартует (так и задумано).
- Проверьте доступность цели вручную (подставьте хост из `upstream backend_1` своего сайта,
  см. `docker exec safeline-tengine grep -A3 'upstream backend_1' /etc/nginx/sites-enabled/IF_*`):

  ```bash
  curl -sk -o /dev/null -w '%{http_code}\n' https://<оригин-хост>/
- Режим «напрямую в бэкенд» использует upstream из конфига сайта. Если меняли схему —
  проверьте `grep -A3 'upstream backend_1' /etc/nginx/sites-enabled/IF_*` в tengine.
- Перед тестом API автоматически снимает баны CrowdSec со своих IP.

## Защита не вернулась после теста через WAF

Проверьте вручную:

```bash
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -tAc \
 "SELECT id,enabled FROM mgt_acl_config_v3 WHERE built_in=true ORDER BY id"
systemctl is-active crowdsec-firewall-bouncer
```

Автовозврат выполняется в `finally` теста. Если прервался жёстко — включите правила и бансер:

```bash
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
 "UPDATE mgt_acl_config_v3 SET enabled=true WHERE built_in=true"
systemctl start crowdsec-firewall-bouncer
```

## Аналитика пустая (нет запросов в «Проксировании»)

```bash
ls -la /data/safeline/logs/nginx/slext_traffic.log
docker exec safeline-tengine grep -n 'slext-px' /etc/nginx/sites-enabled/IF_*
```

Если файла нет — патч лога не применён: `bash /opt/slext/bin/apply-injection.sh`.
Лог появится после первых запросов к сайту; данные обновляются в панели кнопкой «Обновить».

## DNS-проверки показывают ошибку

- Проверка идёт через резолвер из `/etc/resolv.conf` (UDP/53). Если провайдер блокирует —
  замените nameserver или используйте `1.1.1.1`.
- «Проверить сейчас» в SLExt → DNS и TLS повторяет полную проверку (A/AAAA/NS/MX/TXT/TLS).

## Полезные логи

| Что | Где |
|---|---|
| API SLExt | `journalctl -u slext-api` |
| Патчи/деплой | `journalctl -u slext-apply` |
| nginx WAF | `docker logs safeline-tengine` |
| Доступ-логи сайта | `/data/safeline/logs/nginx/` |
| Состояние SLExt | `/opt/slext/conf/state.json` |
