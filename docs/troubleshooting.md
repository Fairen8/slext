# Диагностика

## Быстрый чек-лист

```bash
systemctl is-active slext-api                      # active?
curl -s http://127.0.0.1:8787/api/health | jq      # ok:true, extver
journalctl -u slext-api -n 50 --no-pager | grep -i error
docker exec safeline-tengine nginx -t              # конфиг валиден?
bash tests/verify-install.sh                       # полный smoke
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

## Страница очереди — стоковая

```bash
ls -la /data/safeline/resources/nginx/slext-pages/            # waiting_room.html есть?
grep -c 'slext-waiting-page' /data/safeline/resources/nginx/slext-pages/waiting_room.html
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
