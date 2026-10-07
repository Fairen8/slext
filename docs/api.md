# API

Базовый адрес: `http://127.0.0.1:8787` (внутри сервера) либо через панель: `/extapi/api/...`.
Формат — JSON. Авторизация — заголовок `Authorization: Bearer <токен панели SafeLine>`.
Без токена — `401`, при недостатке прав — `403` (`{"ok": false, "error": "нет доступа: <право>"}`).
CORS разрешён только для origin панели; `/api/waiting/status` доступен странице очереди с
ограничением по hostname.

Права в скобках — требуемое право матрицы доступа (см. [access.md](access.md)).

## Служебные

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/health` | — | состояние API: `pg`, `extver`, `version` |
| GET | `/api/me` | — | текущий пользователь: `username, role, perms, domains` |
| GET | `/api/waiting/status?site=` | — | статус очереди для страницы ожидания |

## Доступ (только администратор)

| Метод | Путь | Описание |
|---|---|---|
| GET | `/api/access` | пользователи панели, роли, права, домены, список прав и хостов |
| POST | `/api/access/save` | `{username, role, perms[], domains[]}` — сохранить настройку |

## Аналитика и мониторинг

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/attacks?hours=&site=` | `overview.view` | реальные атаки: тоталы, типы, динамика, топы, гео; учитывает доменные ограничения |
| GET | `/api/security?hours=` | `proxy.view` | сводка security posture (детекты по категориям, ACL, страницы; учитывает домены) |
| GET | `/api/traffic?hours=` | `proxy.view` | трафик из логов nginx: браузеры/ОС/устройства, статусы, referer, топы |
| GET | `/api/proxy?hours=&site=` | `proxy.view` | золотые сигналы: RPS, перцентили, Apdex, ошибки, трафик, топы, медленные (фильтр по доменам) |
| GET | `/api/dns` | `dns.view` | домены: последние проверки (A/AAAA/NS/MX/TXT/SPF/DMARC/TLS) и история `samples` |
| POST | `/api/dns/check` | `dns.check` | внеочередная полная проверка (`{host?}` — один домен или все) |
| GET | `/api/crowdsec` | `crowdsec.view` | активные решения CrowdSec |
| POST | `/api/crowdsec/ban` | `crowdsec.ban` | `{ip, duration, reason}` |
| POST | `/api/crowdsec/unban` | `crowdsec.ban` | `{ip}` |
| GET | `/api/export?hours=&format=csv\|json&site=&action=&atype=&risk=` | `overview.view` | экспорт атак (учитывает домены) |

## Зал ожидания

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/waiting?site=` | `wr.view` | сайты (с фильтром по доменам), конфиг, статистика, live-трафик |
| POST | `/api/waiting/config` | `wr.control` | `{site, enabled}` — вкл/выкл очереди |
| POST | `/api/waiting/extras` | `wr.settings` | расписание, авто-режим (`threshold, off_threshold, window, hold, hold_off, cooldown, min_off`), уведомления |
| POST | `/api/waiting/page` | `wr.settings` | `{site, page}`, `{preview:1}` — тексты/стиль страницы очереди |

## Тест ёмкости

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/loadtest` | `lt.view` | текущий тест, прогресс, отчёт, архив, список сайтов |
| POST | `/api/loadtest/start` | `lt.run` | `{host, path, mode: origin\|waf, auto_pause, max_conc, stage_sec, p95_ms, err_pct, max_total_sec}` |
| POST | `/api/loadtest/stop` | `lt.run` | остановить текущий тест |
| POST | `/api/loadtest/apply` | `lt.apply` | `{host}` — применить рекомендации в зал ожидания (пороги + max_concurrent) |
| GET | `/api/loadtest/archive/get?id=` | `lt.view` | полный отчёт из архива |
| GET | `/api/loadtest/report?id=` | `lt.view` | HTML-отчёт (последний или архивный) |
| POST | `/api/loadtest/archive/delete` | `lt.archive_del` | `{id}` — удалить из архива |

## Страницы и безопасность

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/page` | `pages.view` | настройки страниц ошибок |
| POST | `/api/page` | `pages.edit` | сохранить (`{page}`) или превью (`{preview:1, code, page}`) |
| GET | `/api/skip` | `skip.view` | состояние skip decryption |
| POST | `/api/skip` | `skip.control` | `{enabled}` — применить (перегенерирует `zz_slext_skip.conf`, `nginx -t`, reload) |
| GET | `/api/geo` | `geo.view` | гео-настройки и выбранные страны с размером CIDR |
| POST | `/api/geo` | `geo.edit` | `{geo:{enabled, mode, countries[]}}` |
| POST | `/api/geo/sync` | `geo.edit` | `{countries[]}` — скачать ipdeny и применить списки |
| GET | `/api/apiroutes?site=` | `api.view` | API-маршруты: сайты (с фильтром по доменам), конфиг whitelist/rate-limit, время применения |
| POST | `/api/apiroutes` | `api.edit` | `{site, enabled, paths[], rate, burst}` — whitelist путей (обход челленджа) + rate-limit на IP; генерирует карты/зоны, патчит сайт, `nginx -t`, reload |

## Уведомления и инфраструктура

| Метод | Путь | Право | Описание |
|---|---|---|---|
| GET | `/api/notify` | `notify.view` | каналы уведомлений |
| POST | `/api/notify` | `notify.edit` | сохранить Telegram/Discord |
| POST | `/api/notify/test` | `notify.edit` | `{channel: telegram\|discord}` — тест |
| GET | `/api/alarm` | `notify.view` | правила алертов |
| POST | `/api/alarm` | `notify.edit` | сохранить правила |
| GET | `/api/syslog` | `notify.view` | настройки syslog |
| POST | `/api/syslog` | `notify.edit` | сохранить syslog |
| POST | `/api/syslog/test` | `notify.edit` | тестовое сообщение |
| GET | `/api/backup` | `notify.view` | настройки бэкапов и список файлов |
| POST | `/api/backup` | `notify.edit` | сохранить настройки |
| POST | `/api/backup/run` | `notify.edit` | сделать бэкап сейчас |
| GET | `/api/lb` | — | балансировщик: узлы и статус |
| POST | `/api/lb` | — | сохранить конфигурацию upstream |
| GET | `/api/lb/test?n=` | — | проверить распределение (n запросов) |

## Примеры

```bash
TOKEN=$(cat /tmp/panel_token.txt)

# Проверка состояния
curl -s http://127.0.0.1:8787/api/health | jq

# Текущий пользователь и права
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/me | jq

# Прокси-аналитика за 24 часа
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8787/api/proxy?hours=24" | jq '.rps,.p95,.apdex'

# Малый тест ёмкости напрямую в бэкенд
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"host":"example.com","mode":"origin","max_conc":8,"stage_sec":5,"max_total_sec":60}' \
  http://127.0.0.1:8787/api/loadtest/start | jq
```
