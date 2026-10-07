# Конфигурация

## Файлы

| Путь | Назначение |
|---|---|
| `/opt/slext/conf/slext.env` | доступ к PostgreSQL (шаблон — `conf/slext.env.example`) |
| `/opt/slext/conf/state.json` | всё состояние SLExt (атомарная запись, `600`) |
| `/opt/slext/conf/extver` | версия фронтенда (`ext.js?v=N`) |
| `/opt/slext/conf/countries.json` | коды стран для гео-блокировки |
| `/opt/slext/conf/lb-upstreams.conf` | сгенерированный upstream-конфиг балансировщика |
| `/opt/slext/conf/mgt.crt` | сертификат mgt (для конфигов nginx, ссылающихся на `/opt/slext/conf/mgt.crt`) |
| `/opt/slext/conf/mgt.key` | приватный ключ к `mgt.crt`; генерируется автоматически при установке/применении, если отсутствует или не совпадает с сертификатом (`600`) |
| `/opt/slext/www/` | ассеты панели и страниц |
| `/data/safeline/logs/nginx/slext_traffic.log` | access_log прокси для аналитики |

### slext.env

```ini
PGHOST=127.0.0.1
PGUSER=safeline-ce
PGPASSWORD=<пароль из контейнера safeline-pg>
PGDATABASE=safeline-ce
```

Права `600`. Пароль можно получить командой `docker exec safeline-pg printenv POSTGRES_PASSWORD`.

## state.json

Единый JSON со всем состоянием. Верхнеуровневые ключи:

| Ключ | Содержимое |
|---|---|
| `notify` | Telegram/Discord: включение, токены, min_risk, last_id |
| `alarm` | правила алертов: метрика, порог, окно, кулдаун |
| `syslog` | syslog: адрес, порт, протокол |
| `backup` | бэкапы: включение, час, срок хранения, список файлов |
| `geo` | гео-блокировка: enabled, mode (block/allow), страны, last_error |
| `page` | страницы ошибок: enabled, brand, тексты по кодам (палитра NRG / INDEX фиксирована) |
| `lb` | балансировщик: алгоритм, узлы, health-check, таймауты |
| `skip` | `{enabled: bool}` — skip decryption |
| `waiting` | зал: sites → {page, schedule, auto, notify, state, auto_run, auto_log} |
| `loadtest` | текущий тест, отчёт, `archive` (10 последних) |
| `dns` | домены: последние проверки, записи, TLS, `samples` (576 точек) |
| `access` | матрица доступа: `users → {role, perms, domains}` |

## nginx-карты (conf.d)

Создаются в `/data/safeline/resources/nginx/conf.d/`:

| Файл | Содержимое |
|---|---|
| `zz_slext_nf.conf` | `map $http_accept $slext_nf_page` — HTML-404 через свою страницу, API — проход |
| `zz_slext_skip.conf` | `map $http_cookie $slext_skip` — bypass для cookie SafeLine или `nrgpass=1` |
| `zz_slext_cc.conf` | `map $http_accept $slext_cc` — `no-store` для HTML (не кэшировать шифрованные страницы) |
| `zz_slext_gate.conf` | `map "$slext_skip$cookie_nrgpass$http_accept" $slext_gate` — гейт первого захода |
| `zz_slext_geo.conf`, `slext-geo/check.conf` | гео-блокировка: `geo $slext_geo_deny` + включаемый список CIDR |
| `zz_slext_access_log.conf` | формат лога SafeLine для аналитики |

## Патчи в конфиге сайта

Все вставки помечены `# slext-*` и описаны в [architecture.md](architecture.md#патчи-nginx-конфига-сайта).
Бэкап исходного конфига (`IF_<id>.slext-orig`) создаётся автоматически при первой установке
на непатченном файле — используется при удалении.

## systemd

`/etc/systemd/system/`:

| Юнит | Что делает |
|---|---|
| `slext-api.service` | API SLExt (`ExecStart=/usr/bin/python3 /opt/slext/bin/slext-api.py`, `Restart=always`) |
| `slext-apply.timer` | переприменение патчей каждые 2 минуты |
| `slext-apply.path` | вотчдог каталога `sites-enabled`: применяет патчи через ~1 с после изменений |

```bash
systemctl status slext-api
journalctl -u slext-api -n 100 --no-pager
systemctl list-timers slext-apply.timer
```

## Настройки в панели

Все параметры меняются во вкладке **SLExt** (см. [features.md](features.md)) и сразу пишутся
в `state.json`; часть действий дополнительно применяет конфиги (`apply-injection.sh`,
`skip_apply`, `geo_sync`, `waiting page_apply`).

Права и домены пользователей — вкладка **Доступ** (см. [access.md](access.md)).
